"""
Cerimonia delle chiavi del progetto evoto.

Questo modulo contiene:
- il polinomio segreto di ogni garante;
- gli impegni di Feldman con le relative prove di Schnorr;
- la verifica delle share ricevute;
- la chiave pubblica congiunta dell'elezione;
- la share aggregata e la chiave di verifica di ogni garante;
- i contesti di hash Q e Q_bar;
- la simulazione completa della cerimonia.

Segue la specifica condivisa docs/spec_f1.md v0.4,
in particolare le sezioni 18, 19, 20, 23 e 35.

La chiave segreta dell'elezione non viene mai costruita:
esiste soltanto come somma dei termini noti ai singoli garanti.
"""

from dataclasses import dataclass
import secrets

from evoto.gruppo import (
    GroupParameters,
    H,
    is_subgroup_element,
    mod_pow,
)
from evoto.prove import (
    SchnorrProof,
    prove_schnorr,
    verify_schnorr,
)


@dataclass(frozen=True)
class Guardian:
    """
    Materiale privato di un garante.

    index: numero del garante, da 1 a n.
    coefficients: coefficienti a_i,0, ..., a_i,k-1 del polinomio segreto.

    Il termine noto a_i,0 è il contributo del garante alla chiave
    dell'elezione: questo oggetto non viene mai pubblicato.
    """

    index: int
    coefficients: tuple[int, ...]


@dataclass(frozen=True)
class GuardianRecord:
    """
    Parte pubblica di un garante, destinata al registro.

    commitments: impegni di Feldman K_i,0, ..., K_i,k-1.
    proofs: una prova di Schnorr per ogni impegno.
    """

    index: int
    commitments: tuple[int, ...]
    proofs: tuple[SchnorrProof, ...]


@dataclass(frozen=True)
class KeyCeremony:
    """
    Risultato della cerimonia delle chiavi simulata.

    records, joint_public_key, base_hash ed extended_base_hash
    sono informazioni pubbliche.

    secret_shares contiene invece le share aggregate s_l. In un sistema
    reale ognuna resterebbe soltanto presso il garante corrispondente e
    non comparirebbe mai in un unico oggetto: qui i garanti sono simulati
    in un solo programma, come dichiarato nella proposta di progetto.
    """

    records: tuple[GuardianRecord, ...]
    joint_public_key: int
    base_hash: int
    extended_base_hash: int
    secret_shares: dict[int, int]


def compute_base_hash(
    params: GroupParameters,
    guardian_count: int,
    quorum: int,
    election_id: int,
) -> int:
    """
    Calcola il contesto Q della cerimonia delle chiavi.

    Q = H(p, q, g, n, k, e)

    Serve prima che la chiave congiunta esista, quindi non la contiene.
    """

    if guardian_count < 1:
        raise ValueError("Il numero di garanti deve essere almeno 1.")

    if not 1 <= quorum <= guardian_count:
        raise ValueError(
            "Il quorum deve essere compreso tra 1 e il numero di garanti."
        )

    if election_id < 0:
        raise ValueError("L'identificativo dell'elezione deve essere non negativo.")

    return H(
        params.p,
        params.q,
        params.g,
        guardian_count,
        quorum,
        election_id,
        params=params,
    )


def compute_extended_base_hash(
    base_hash: int,
    joint_public_key: int,
    params: GroupParameters,
) -> int:
    """
    Calcola il contesto esteso Q_bar.

    Q_bar = H(Q, K)

    Lega tutte le prove successive alla chiave pubblica dell'elezione.
    """

    if not is_subgroup_element(joint_public_key, params):
        raise ValueError("La chiave pubblica non appartiene al sottogruppo.")

    return H(
        base_hash,
        joint_public_key,
        params=params,
    )


def create_guardian(
    index: int,
    quorum: int,
    params: GroupParameters,
    coefficients: tuple[int, ...] | None = None,
) -> Guardian:
    """
    Crea un garante con il suo polinomio segreto di grado quorum - 1.

    I coefficienti sono scelti uniformemente in Z_q.

    Come per il nonce di encrypt, nei test possono essere passati
    esplicitamente per riprodurre i vettori della specifica.
    """

    if index < 1:
        raise ValueError("L'indice del garante deve essere almeno 1.")

    if quorum < 1:
        raise ValueError("Il quorum deve essere almeno 1.")

    if coefficients is None:
        coefficients = tuple(
            secrets.randbelow(params.q)
            for _ in range(quorum)
        )

    if len(coefficients) != quorum:
        raise ValueError("Il polinomio deve avere esattamente quorum coefficienti.")

    for coefficient in coefficients:
        if not 0 <= coefficient < params.q:
            raise ValueError(
                "Ogni coefficiente deve essere compreso tra 0 e q - 1."
            )

    return Guardian(
        index=index,
        coefficients=tuple(coefficients),
    )


def evaluate_polynomial(
    coefficients: tuple[int, ...],
    point: int,
    params: GroupParameters,
) -> int:
    """
    Valuta il polinomio segreto modulo q con lo schema di Horner.

        P(x) = a_0 + a_1 x + ... + a_(k-1) x^(k-1) mod q

    Il punto 0 restituirebbe il segreto del garante, quindi nella
    cerimonia si usano soltanto i punti 1, ..., n.
    """

    if not coefficients:
        raise ValueError("Il polinomio deve avere almeno un coefficiente.")

    if point < 0:
        raise ValueError("Il punto di valutazione deve essere non negativo.")

    result = 0

    for coefficient in reversed(coefficients):
        result = (result * point + coefficient) % params.q

    return result


def compute_commitments(
    guardian: Guardian,
    params: GroupParameters,
) -> tuple[int, ...]:
    """
    Calcola gli impegni di Feldman del garante.

        K_i,j = g^(a_i,j) mod p

    Gli impegni sono pubblici e permettono di controllare le share
    senza conoscere il polinomio.
    """

    return tuple(
        mod_pow(params.g, coefficient, params.p)
        for coefficient in guardian.coefficients
    )


def create_guardian_record(
    guardian: Guardian,
    params: GroupParameters,
    base_hash: int,
    nonces: tuple[int, ...] | None = None,
) -> GuardianRecord:
    """
    Costruisce la parte pubblica del garante.

    Ogni impegno K_i,j viene accompagnato da una prova di Schnorr
    che dimostra la conoscenza del coefficiente a_i,j, con contesto:

        (Q, i, j)

    I nonce delle prove possono essere passati esplicitamente nei test.
    """

    commitments = compute_commitments(guardian, params)

    if nonces is not None and len(nonces) != len(commitments):
        raise ValueError("Serve un nonce per ogni impegno.")

    proofs = tuple(
        prove_schnorr(
            secret=guardian.coefficients[position],
            public_value=commitments[position],
            params=params,
            context=(base_hash, guardian.index, position),
            nonce=None if nonces is None else nonces[position],
        )
        for position in range(len(commitments))
    )

    return GuardianRecord(
        index=guardian.index,
        commitments=commitments,
        proofs=proofs,
    )


def verify_guardian_record(
    record: GuardianRecord,
    quorum: int,
    params: GroupParameters,
    base_hash: int,
) -> bool:
    """
    Controlla la parte pubblica di un garante.

    Verifichiamo:
    - l'indice del garante;
    - il numero di impegni e di prove, pari al quorum;
    - l'appartenenza di ogni impegno al sottogruppo;
    - ogni prova di Schnorr, con il contesto corretto.

    È il controllo V2 del verificatore.
    """

    if record.index < 1:
        return False

    if len(record.commitments) != quorum:
        return False

    if len(record.proofs) != quorum:
        return False

    for position, commitment in enumerate(record.commitments):
        if not is_subgroup_element(commitment, params):
            return False

        valid = verify_schnorr(
            public_value=commitment,
            proof=record.proofs[position],
            params=params,
            context=(base_hash, record.index, position),
        )

        if not valid:
            return False

    return True


def compute_share(
    guardian: Guardian,
    recipient_index: int,
    params: GroupParameters,
) -> int:
    """
    Calcola la share che il garante invia al collega recipient_index.

        P_i(l) mod q

    La share è privata: non finisce mai nel registro pubblico.
    """

    if recipient_index < 1:
        raise ValueError("L'indice del destinatario deve essere almeno 1.")

    return evaluate_polynomial(
        guardian.coefficients,
        recipient_index,
        params,
    )


def _commitment_product(
    commitments: tuple[int, ...],
    point: int,
    params: GroupParameters,
) -> int:
    """
    Calcola il prodotto degli impegni valutati in un punto.

        ∏_j K_j^(point^j) mod p

    Corrisponde a g^(P(point)) quando gli impegni sono coerenti
    con il polinomio, ed è il cuore della verifica di Feldman.
    """

    product = 1

    for position, commitment in enumerate(commitments):
        exponent = mod_pow(point, position, params.q)

        product = (
            product
            * mod_pow(commitment, exponent, params.p)
        ) % params.p

    return product


def verify_share(
    share: int,
    recipient_index: int,
    record: GuardianRecord,
    params: GroupParameters,
) -> bool:
    """
    Verifica una share con gli impegni di Feldman del mittente.

        g^(P_i(l)) = ∏_j K_i,j^(l^j) mod p

    Se il controllo fallisce, la share non corrisponde al polinomio
    che il garante ha dichiarato pubblicamente.
    """

    if recipient_index < 1:
        return False

    if not 0 <= share < params.q:
        return False

    if not record.commitments:
        return False

    for commitment in record.commitments:
        if not is_subgroup_element(commitment, params):
            return False

    left = mod_pow(params.g, share, params.p)

    right = _commitment_product(
        record.commitments,
        recipient_index,
        params,
    )

    return left == right


def aggregate_shares(
    shares: tuple[int, ...],
    params: GroupParameters,
) -> int:
    """
    Calcola la share aggregata di un garante.

        s_l = Σ_i P_i(l) mod q

    Poiché S(x) = Σ_i P_i(x) ha grado quorum - 1 e S(0) è la chiave
    segreta dell'elezione, s_l è una share di Shamir di quella chiave.
    """

    if not shares:
        raise ValueError("Serve almeno una share da aggregare.")

    total = 0

    for share in shares:
        if not 0 <= share < params.q:
            raise ValueError("Ogni share deve essere compresa tra 0 e q - 1.")

        total = (total + share) % params.q

    return total


def compute_verification_key(
    guardian_index: int,
    records: tuple[GuardianRecord, ...],
    params: GroupParameters,
) -> int:
    """
    Calcola la chiave di verifica pubblica del garante.

        V_l = g^(s_l) = ∏_i ∏_j K_i,j^(l^j) mod p

    Chiunque può ricalcolarla dagli impegni: serve al verificatore
    per controllare le prove delle share di decifratura.
    """

    if guardian_index < 1:
        raise ValueError("L'indice del garante deve essere almeno 1.")

    if not records:
        raise ValueError("Serve almeno un garante.")

    verification_key = 1

    for record in records:
        verification_key = (
            verification_key
            * _commitment_product(
                record.commitments,
                guardian_index,
                params,
            )
        ) % params.p

    return verification_key


def compute_joint_public_key(
    records: tuple[GuardianRecord, ...],
    params: GroupParameters,
) -> int:
    """
    Calcola la chiave pubblica dell'elezione.

        K = ∏_i K_i,0 = g^(Σ_i a_i,0) mod p

    La chiave segreta corrispondente non esiste in nessun punto.
    """

    if not records:
        raise ValueError("Serve almeno un garante.")

    joint_public_key = 1

    for record in records:
        if not record.commitments:
            raise ValueError("Ogni garante deve avere almeno un impegno.")

        joint_public_key = (
            joint_public_key
            * record.commitments[0]
        ) % params.p

    return joint_public_key


def run_key_ceremony(
    guardian_count: int,
    quorum: int,
    params: GroupParameters,
    election_id: int,
    coefficients: tuple[tuple[int, ...], ...] | None = None,
) -> KeyCeremony:
    """
    Esegue l'intera cerimonia delle chiavi con i garanti simulati.

    I passaggi sono quelli della fase 1 del protocollo:
    1. ogni garante sceglie il polinomio segreto;
    2. pubblica impegni e prove di Schnorr;
    3. invia una share a ogni collega;
    4. ogni share viene verificata con gli impegni del mittente;
    5. ogni garante somma le share ricevute;
    6. dagli impegni si ricava la chiave pubblica congiunta.

    Se un impegno o una share non superano i controlli, la cerimonia
    si interrompe con un ValueError che indica il garante responsabile.
    Non implementiamo una fase di reclamo.
    """

    if guardian_count < 1:
        raise ValueError("Il numero di garanti deve essere almeno 1.")

    if not 1 <= quorum <= guardian_count:
        raise ValueError(
            "Il quorum deve essere compreso tra 1 e il numero di garanti."
        )

    if coefficients is not None and len(coefficients) != guardian_count:
        raise ValueError("Serve un polinomio per ogni garante.")

    base_hash = compute_base_hash(
        params,
        guardian_count,
        quorum,
        election_id,
    )

    indexes = tuple(range(1, guardian_count + 1))

    guardians = tuple(
        create_guardian(
            index=index,
            quorum=quorum,
            params=params,
            coefficients=None if coefficients is None else coefficients[index - 1],
        )
        for index in indexes
    )

    records = tuple(
        create_guardian_record(
            guardian,
            params,
            base_hash,
        )
        for guardian in guardians
    )

    for record in records:
        if not verify_guardian_record(record, quorum, params, base_hash):
            raise ValueError(
                f"Gli impegni del garante {record.index} non sono validi."
            )

    # Ogni garante invia una share a ogni collega, se stesso compreso.
    secret_shares: dict[int, int] = {}

    for recipient in indexes:
        received = []

        for guardian, record in zip(guardians, records, strict=True):
            share = compute_share(guardian, recipient, params)

            if not verify_share(share, recipient, record, params):
                raise ValueError(
                    f"La share del garante {guardian.index} "
                    f"per il garante {recipient} non è valida."
                )

            received.append(share)

        secret_shares[recipient] = aggregate_shares(
            tuple(received),
            params,
        )

    joint_public_key = compute_joint_public_key(records, params)

    extended_base_hash = compute_extended_base_hash(
        base_hash,
        joint_public_key,
        params,
    )

    return KeyCeremony(
        records=records,
        joint_public_key=joint_public_key,
        base_hash=base_hash,
        extended_base_hash=extended_base_hash,
        secret_shares=secret_shares,
    )
