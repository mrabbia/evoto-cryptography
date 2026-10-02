"""
Verificatore indipendente del progetto evoto.

Questo modulo non importa la libreria evoto.
I controlli vengono ricostruiti in modo indipendente
a partire dai dati pubblici dell'elezione.
"""

import gmpy2
import hashlib
import json
import math
from fractions import Fraction


def _to_hex(value: int) -> str:
    """
    Converte un intero non negativo
    nel formato esadecimale canonico.

    Usa lettere maiuscole e una lunghezza pari.
    """

    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(
            "Il valore da serializzare deve essere un intero."
        )

    if value < 0:
        raise ValueError(
            "Il valore da serializzare non può essere negativo."
        )

    encoded = format(value, "X")

    if len(encoded) % 2 != 0:
        encoded = "0" + encoded

    return encoded


def hash_to_q(
    q: int,
    *values: int,
) -> int:
    """
    Calcola l'hash canonico del progetto e lo riduce modulo q.
    """

    digest = hashlib.sha256(b"|")

    for value in values:
        digest.update(
            (_to_hex(value) + "|").encode()
        )

    return int.from_bytes(
        digest.digest(),
        "big",
    ) % q


def is_subgroup_element(
    value: int,
    p: int,
    q: int,
) -> bool:
    """
    Verifica che un valore appartenga al sottogruppo di ordine q.
    """

    if not isinstance(value, int):
        return False

    if not 0 < value < p:
        return False

    return int(
        gmpy2.powmod(
            value,
            q,
            p,
        )
    ) == 1


def _mod_pow(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Calcola un'esponenziazione modulare efficiente.
    """

    return int(
        gmpy2.powmod(
            base,
            exponent,
            modulus,
        )
    )


def compute_joint_public_key(
    commitment_sets: tuple[tuple[int, ...], ...],
    p: int,
    q: int,
) -> int:
    """
    Ricalcola la chiave pubblica congiunta
    dagli impegni costanti dei garanti.

    K = prodotto di K_i,0 modulo p.
    """

    if not commitment_sets:
        raise ValueError(
            "È richiesto almeno un insieme di impegni."
        )

    result = 1

    for commitments in commitment_sets:
        if not commitments:
            raise ValueError(
                "Ogni garante deve avere almeno un impegno."
            )

        first_commitment = commitments[0]

        if not is_subgroup_element(
            first_commitment,
            p,
            q,
        ):
            raise ValueError(
                "L'impegno costante deve appartenere al sottogruppo."
            )

        result = (
            result * first_commitment
        ) % p

    return result


def compute_verification_key(
    guardian_index: int,
    commitment_sets: tuple[tuple[int, ...], ...],
    p: int,
    q: int,
) -> int:
    """
    Ricalcola la chiave di verifica V_l
    di un garante dagli impegni di Feldman.

    V_l = prodotto di K_i,j^(l^j) modulo p.
    """

    if guardian_index < 1:
        raise ValueError(
            "L'indice del garante deve essere almeno 1."
        )

    if not commitment_sets:
        raise ValueError(
            "È richiesto almeno un insieme di impegni."
        )

    verification_key = 1

    for commitments in commitment_sets:
        if not commitments:
            raise ValueError(
                "Ogni garante deve avere almeno un impegno."
            )

        guardian_product = 1

        for coefficient_index, commitment in enumerate(
            commitments
        ):
            if not is_subgroup_element(
                commitment,
                p,
                q,
            ):
                raise ValueError(
                    "Ogni impegno deve appartenere al sottogruppo."
                )

            exponent = _mod_pow(
                guardian_index,
                coefficient_index,
                q,
            )

            guardian_product = (
                guardian_product
                * _mod_pow(
                    commitment,
                    exponent,
                    p,
                )
            ) % p

        verification_key = (
            verification_key
            * guardian_product
        ) % p

    return verification_key


def multiply_ciphertexts(
    ciphertexts: tuple[tuple[int, int], ...],
    p: int,
    q: int,
) -> tuple[int, int]:
    """
    Moltiplica una sequenza di ciphertext ElGamal.

    Ogni ciphertext è rappresentato come:
    (alpha, beta).

    La sequenza vuota produce l'identità (1, 1).
    """

    for alpha, beta in ciphertexts:
        if not is_subgroup_element(
            alpha,
            p,
            q,
        ):
            raise ValueError(
                "Alpha deve appartenere al sottogruppo."
            )

        if not is_subgroup_element(
            beta,
            p,
            q,
        ):
            raise ValueError(
                "Beta deve appartenere al sottogruppo."
            )

    result_alpha = 1
    result_beta = 1

    for alpha, beta in ciphertexts:
        result_alpha = (
            result_alpha * alpha
        ) % p

        result_beta = (
            result_beta * beta
        ) % p

    return (
        result_alpha,
        result_beta,
    )


def divide_ciphertexts(
    numerator: tuple[int, int],
    denominator: tuple[int, int],
    p: int,
    q: int,
) -> tuple[int, int]:
    """
    Divide due ciphertext ElGamal componente per componente.
    """

    numerator_alpha, numerator_beta = numerator
    denominator_alpha, denominator_beta = denominator

    elements = (
        numerator_alpha,
        numerator_beta,
        denominator_alpha,
        denominator_beta,
    )

    if not all(
        is_subgroup_element(
            value,
            p,
            q,
        )
        for value in elements
    ):
        raise ValueError(
            "I ciphertext devono appartenere al sottogruppo."
        )

    result_alpha = (
        numerator_alpha
        * pow(
            denominator_alpha,
            -1,
            p,
        )
    ) % p

    result_beta = (
        numerator_beta
        * pow(
            denominator_beta,
            -1,
            p,
        )
    ) % p

    return (
        result_alpha,
        result_beta,
    )


def verify_r2_rule(
    ciphertexts: tuple[tuple[int, int], ...],
    branches: tuple[
        tuple[int, int, int, int],
        ...,
    ],
    p: int,
    q: int,
    g: int,
    public_key: int,
    context: int,
) -> bool:
    """
    Verifica R2.

    Il prodotto dei ciphertext delle liste e della scheda
    bianca deve cifrare esattamente il valore 1.
    """

    try:
        alpha, beta = multiply_ciphertexts(
            ciphertexts=ciphertexts,
            p=p,
            q=q,
        )
    except ValueError:
        return False

    return verify_value_set_proof(
        p=p,
        q=q,
        g=g,
        public_key=public_key,
        context=context,
        alpha=alpha,
        beta=beta,
        allowed_values=(1,),
        branches=branches,
    )


def verify_r3_rule(
    list_ciphertext: tuple[int, int],
    preference_ciphertext: tuple[int, int],
    branches: tuple[
        tuple[int, int, int, int],
        ...,
    ],
    p: int,
    q: int,
    g: int,
    public_key: int,
    context: int,
) -> bool:
    """
    Verifica R3.

    La differenza tra lista e preferenza
    deve appartenere a {0, 1}.
    """

    try:
        alpha, beta = divide_ciphertexts(
            numerator=list_ciphertext,
            denominator=preference_ciphertext,
            p=p,
            q=q,
        )
    except ValueError:
        return False

    return verify_value_set_proof(
        p=p,
        q=q,
        g=g,
        public_key=public_key,
        context=context,
        alpha=alpha,
        beta=beta,
        allowed_values=(0, 1),
        branches=branches,
    )


def verify_r4_rule(
    preference_ciphertexts: tuple[
        tuple[int, int],
        ...,
    ],
    branches: tuple[
        tuple[int, int, int, int],
        ...,
    ],
    p: int,
    q: int,
    g: int,
    public_key: int,
    context: int,
    max_preferences: int,
) -> bool:
    """
    Verifica R4.

    La somma delle preferenze deve essere compresa
    tra 0 e il limite massimo configurato.
    """

    if (
        not isinstance(max_preferences, int)
        or max_preferences < 0
    ):
        return False

    try:
        alpha, beta = multiply_ciphertexts(
            ciphertexts=preference_ciphertexts,
            p=p,
            q=q,
        )
    except ValueError:
        return False

    return verify_value_set_proof(
        p=p,
        q=q,
        g=g,
        public_key=public_key,
        context=context,
        alpha=alpha,
        beta=beta,
        allowed_values=tuple(
            range(max_preferences + 1)
        ),
        branches=branches,
    )


def verify_r5_rule(
    gender_ciphertexts: tuple[
        tuple[int, int],
        ...,
    ],
    branches: tuple[
        tuple[int, int, int, int],
        ...,
    ],
    p: int,
    q: int,
    g: int,
    public_key: int,
    context: int,
    max_preferences_per_gender: int,
) -> bool:
    """
    Verifica R5 per un singolo genere.

    La somma delle preferenze del genere deve essere compresa
    tra 0 e il limite per genere configurato.
    """

    if (
        not isinstance(max_preferences_per_gender, int)
        or max_preferences_per_gender < 0
    ):
        return False

    try:
        alpha, beta = multiply_ciphertexts(
            ciphertexts=gender_ciphertexts,
            p=p,
            q=q,
        )
    except ValueError:
        return False

    return verify_value_set_proof(
        p=p,
        q=q,
        g=g,
        public_key=public_key,
        context=context,
        alpha=alpha,
        beta=beta,
        allowed_values=tuple(
            range(max_preferences_per_gender + 1)
        ),
        branches=branches,
    )


def verify_schnorr_commitment(
    p: int,
    q: int,
    g: int,
    context: int,
    guardian_index: int,
    coefficient_index: int,
    commitment: int,
    proof_commitment: int,
    challenge: int,
    response: int,
) -> bool:
    """
    Verifica la prova di Schnorr associata
    a un impegno pubblico di un garante.
    """

    if guardian_index < 1:
        return False

    if coefficient_index < 0:
        return False

    if not 0 <= context < q:
        return False

    if not 0 <= challenge < q:
        return False

    if not 0 <= response < q:
        return False

    if not is_subgroup_element(
        commitment,
        p,
        q,
    ):
        return False

    if not is_subgroup_element(
        proof_commitment,
        p,
        q,
    ):
        return False

    expected_challenge = hash_to_q(
        q,
        context,
        guardian_index,
        coefficient_index,
        g,
        commitment,
        proof_commitment,
    )

    if challenge != expected_challenge:
        return False

    left = _mod_pow(
        g,
        response,
        p,
    )

    right = (
        proof_commitment
        * _mod_pow(
            commitment,
            challenge,
            p,
        )
    ) % p

    return left == right


def verify_chaum_pedersen_share(
    p: int,
    q: int,
    g: int,
    context: int,
    guardian_index: int,
    verification_key: int,
    tally_alpha: int,
    partial_decryption: int,
    commitment_1: int,
    commitment_2: int,
    challenge: int,
    response: int,
) -> bool:
    """
    Verifica una prova Chaum-Pedersen
    associata a una share di decifratura.
    """

    if guardian_index < 1:
        return False

    if not 0 <= context < q:
        return False

    if not 0 <= challenge < q:
        return False

    if not 0 <= response < q:
        return False

    subgroup_values = (
        verification_key,
        tally_alpha,
        partial_decryption,
        commitment_1,
        commitment_2,
    )

    if not all(
        is_subgroup_element(
            value,
            p,
            q,
        )
        for value in subgroup_values
    ):
        return False

    expected_challenge = hash_to_q(
        q,
        context,
        guardian_index,
        g,
        verification_key,
        tally_alpha,
        partial_decryption,
        commitment_1,
        commitment_2,
    )

    if challenge != expected_challenge:
        return False

    first_left = _mod_pow(
        g,
        response,
        p,
    )

    first_right = (
        commitment_1
        * _mod_pow(
            verification_key,
            challenge,
            p,
        )
    ) % p

    if first_left != first_right:
        return False

    second_left = _mod_pow(
        tally_alpha,
        response,
        p,
    )

    second_right = (
        commitment_2
        * _mod_pow(
            partial_decryption,
            challenge,
            p,
        )
    ) % p

    return second_left == second_right


def verify_value_set_proof(
    p: int,
    q: int,
    g: int,
    public_key: int,
    context: int,
    alpha: int,
    beta: int,
    allowed_values: tuple[int, ...],
    branches: tuple[
        tuple[int, int, int, int],
        ...,
    ],
) -> bool:
    """
    Verifica una prova OR che dimostra che un ciphertext
    contiene uno dei valori ammessi.

    Ogni ramo contiene:
    (commitment_1, commitment_2, challenge, response).
    """

    if not allowed_values:
        return False

    if len(branches) != len(allowed_values):
        return False

    if len(set(allowed_values)) != len(
        allowed_values
    ):
        return False

    if any(
        not isinstance(value, int)
        or not 0 <= value < q
        for value in allowed_values
    ):
        return False

    if not 0 <= context < q:
        return False

    subgroup_values = (
        public_key,
        alpha,
        beta,
    )

    if not all(
        is_subgroup_element(
            value,
            p,
            q,
        )
        for value in subgroup_values
    ):
        return False

    hash_values = [
        context,
        alpha,
        beta,
    ]

    challenge_sum = 0

    for branch in branches:
        if len(branch) != 4:
            return False

        (
            commitment_1,
            commitment_2,
            challenge,
            response,
        ) = branch

        if not is_subgroup_element(
            commitment_1,
            p,
            q,
        ):
            return False

        if not is_subgroup_element(
            commitment_2,
            p,
            q,
        ):
            return False

        if not 0 <= challenge < q:
            return False

        if not 0 <= response < q:
            return False

        hash_values.extend(
            (
                commitment_1,
                commitment_2,
            )
        )

        challenge_sum = (
            challenge_sum + challenge
        ) % q

    expected_challenge = hash_to_q(
        q,
        *hash_values,
    )

    if challenge_sum != expected_challenge:
        return False

    for allowed_value, branch in zip(
        allowed_values,
        branches,
    ):
        (
            commitment_1,
            commitment_2,
            challenge,
            response,
        ) = branch

        first_left = _mod_pow(
            g,
            response,
            p,
        )

        first_right = (
            commitment_1
            * _mod_pow(
                alpha,
                challenge,
                p,
            )
        ) % p

        if first_left != first_right:
            return False

        encoded_value = _mod_pow(
            g,
            allowed_value,
            p,
        )

        adjusted_beta = (
            beta
            * pow(
                encoded_value,
                -1,
                p,
            )
        ) % p

        second_left = _mod_pow(
            public_key,
            response,
            p,
        )
        
        second_right = (
            commitment_2
            * _mod_pow(
                adjusted_beta,
                challenge,
                p,
            )
        ) % p

        if second_left != second_right:
            return False

    return True


def lagrange_coefficient_at_zero(
    guardian_index: int,
    guardian_indices: tuple[int, ...],
    q: int,
) -> int:
    """
    Calcola il coefficiente di Lagrange
    di un garante valutato nel punto zero.
    """

    if guardian_index not in guardian_indices:
        raise ValueError(
            "Il garante deve appartenere all'insieme degli indici."
        )

    if any(
        not isinstance(index, int) or index < 1
        for index in guardian_indices
    ):
        raise ValueError(
            "Gli indici dei garanti devono essere interi positivi."
        )

    if len(set(guardian_indices)) != len(
        guardian_indices
    ):
        raise ValueError(
            "Gli indici dei garanti devono essere distinti."
        )

    numerator = 1
    denominator = 1

    for other_index in guardian_indices:
        if other_index == guardian_index:
            continue

        numerator = (
            numerator * (-other_index)
        ) % q

        denominator = (
            denominator
            * (guardian_index - other_index)
        ) % q

    return (
        numerator
        * pow(
            denominator,
            -1,
            q,
        )
    ) % q


def combine_decryption_shares(
    shares: tuple[tuple[int, int], ...],
    p: int,
    q: int,
    quorum: int,
) -> int:
    """
    Combina le share di decifratura
    usando i coefficienti di Lagrange.

    Ogni elemento di shares contiene:
    (indice_garante, share_parziale).
    """

    if quorum < 1:
        raise ValueError(
            "Il quorum deve essere almeno 1."
        )

    if len(shares) < quorum:
        raise ValueError(
            "Il numero di share disponibili è inferiore al quorum."
        )

    guardian_indices = tuple(
        guardian_index
        for guardian_index, _ in shares
    )

    if any(
        not is_subgroup_element(
            partial_decryption,
            p,
            q,
        )
        for _, partial_decryption in shares
    ):
        raise ValueError(
            "Ogni share deve appartenere al sottogruppo."
        )

    result = 1

    for guardian_index, partial_decryption in shares:
        coefficient = lagrange_coefficient_at_zero(
            guardian_index=guardian_index,
            guardian_indices=guardian_indices,
            q=q,
        )

        result = (
            result
            * _mod_pow(
                partial_decryption,
                coefficient,
                p,
            )
        ) % p

    return result


def verify_v1_parameters(
    p: int,
    q: int,
    g: int,
    public_key: int,
) -> bool:
    """
    Verifica i parametri pubblici del gruppo crittografico.

    Controlla:
    - primalità di p e q;
    - divisibilità di p - 1 per q;
    - validità di g nel sottogruppo;
    - appartenenza della chiave pubblica al sottogruppo.
    """

    if not all(
        isinstance(value, int)
        for value in (
            p,
            q,
            g,
            public_key,
        )
    ):
        return False

    if p <= 2 or q <= 1:
        return False

    if not gmpy2.is_prime(p):
        return False

    if not gmpy2.is_prime(q):
        return False

    if (p - 1) % q != 0:
        return False

    if not 1 < g < p:
        return False

    if not 0 < public_key < p:
        return False

    if _mod_pow(g, q, p) != 1:
        return False

    if _mod_pow(
        public_key,
        q,
        p,
    ) != 1:
        return False

    return True


def parse_public_registry(
    serialized: str,
) -> dict[str, object]:
    """
    Legge il registro pubblico JSON.

    Il parser verifica la presenza delle sezioni principali
    senza dipendere dai moduli che hanno prodotto il registro.
    """

    try:
        registry = json.loads(serialized)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(
            "Il registro pubblico non contiene JSON valido."
        ) from exc

    if not isinstance(registry, dict):
        raise ValueError(
            "Il registro pubblico deve essere un oggetto JSON."
        )

    required_keys = (
        "configuration",
        "group",
        "election_context",
        "guardians",
        "K",
        "bulletin_board",
        "district_tallies",
        "district_results",
        "scrutiny",
    )

    missing = tuple(
        key
        for key in required_keys
        if key not in registry
    )

    if missing:
        raise ValueError(
            "Il registro pubblico è incompleto: "
            + ", ".join(missing)
        )

    if not isinstance(
        registry["configuration"],
        dict,
    ):
        raise ValueError(
            "La configurazione deve essere un oggetto JSON."
        )

    if not isinstance(
        registry["group"],
        dict,
    ):
        raise ValueError(
            "I parametri del gruppo devono essere un oggetto JSON."
        )

    if not isinstance(
        registry["election_context"],
        dict,
    ):
        raise ValueError(
            "Il contesto elettorale deve essere un oggetto JSON."
        )

    if not isinstance(
        registry["guardians"],
        list,
    ):
        raise ValueError(
            "I garanti devono essere rappresentati da una lista."
        )

    if not isinstance(
        registry["bulletin_board"],
        dict,
    ):
        raise ValueError(
            "La bacheca deve essere un oggetto JSON."
        )

    if not isinstance(
        registry["district_tallies"],
        list,
    ):
        raise ValueError(
            "I tally devono essere rappresentati da una lista."
        )

    if not isinstance(
        registry["district_results"],
        list,
    ):
        raise ValueError(
            "I risultati devono essere rappresentati da una lista."
        )

    if not isinstance(
        registry["scrutiny"],
        dict,
    ):
        raise ValueError(
            "Lo scrutinio deve essere un oggetto JSON."
        )

    return registry


def _ciphertext_from_data(
    data: object,
) -> tuple[int, int]:
    """
    Legge un ciphertext dal formato pubblico del registro.
    """

    if not isinstance(data, dict):
        raise ValueError(
            "Un ciphertext deve essere un oggetto JSON."
        )

    alpha = data.get("alpha")
    beta = data.get("beta")

    if (
        not isinstance(alpha, int)
        or isinstance(alpha, bool)
        or not isinstance(beta, int)
        or isinstance(beta, bool)
    ):
        raise ValueError(
            "Alpha e beta devono essere interi."
        )

    if alpha < 0 or beta < 0:
        raise ValueError(
            "Alpha e beta non possono essere negativi."
        )

    return (
        alpha,
        beta,
    )


def _ballot_ciphertexts_from_data(
    ballot: object,
) -> tuple[tuple[int, int], ...]:
    """
    Legge i ciphertext di una scheda nell'ordine canonico.
    """

    if not isinstance(ballot, dict):
        raise ValueError(
            "La scheda cifrata deve essere un oggetto JSON."
        )

    list_ciphertexts = ballot.get(
        "list_ciphertexts"
    )

    blank_ciphertext = ballot.get(
        "blank_ciphertext"
    )

    preference_ciphertexts = ballot.get(
        "preference_ciphertexts"
    )

    if not isinstance(list_ciphertexts, list):
        raise ValueError(
            "I ciphertext delle liste devono essere una lista."
        )

    if not isinstance(
        preference_ciphertexts,
        list,
    ):
        raise ValueError(
            "I ciphertext delle preferenze devono essere una lista."
        )

    lists = tuple(
        _ciphertext_from_data(ciphertext)
        for ciphertext in list_ciphertexts
    )

    blank = _ciphertext_from_data(
        blank_ciphertext
    )

    preferences = tuple(
        _ciphertext_from_data(ciphertext)
        for ciphertext in preference_ciphertexts
    )

    return (
        lists
        + (blank,)
        + preferences
    )


def compute_ballot_hash_from_data(
    ballot: object,
    district_index: int,
    extended_base_hash: int,
    q: int,
) -> int:
    """
    Ricalcola l'impronta pubblica di una scheda.

    L'ordine è liste, bianca, preferenze.
    """

    if (
        not isinstance(district_index, int)
        or isinstance(district_index, bool)
        or district_index < 0
    ):
        raise ValueError(
            "L'indice della circoscrizione non è valido."
        )

    ciphertexts = _ballot_ciphertexts_from_data(
        ballot
    )

    values = [
        extended_base_hash,
        district_index,
    ]

    for alpha, beta in ciphertexts:
        values.extend(
            (
                alpha,
                beta,
            )
        )

    return hash_to_q(
        q,
        *values,
    )


def verify_v4_board_chain(
    board: object,
    q: int,
) -> bool:
    """
    Verifica V4 sulla bacheca pubblica.

    Controlla genesis, sequenze, impronte,
    stati e catena dei codici di tracciamento.
    """

    if (
        not isinstance(q, int)
        or isinstance(q, bool)
        or q <= 1
    ):
        return False

    if not isinstance(board, dict):
        return False

    extended_base_hash = board.get(
        "extended_base_hash"
    )

    genesis_code = board.get(
        "genesis_code"
    )

    entries = board.get(
        "entries"
    )

    if (
        not isinstance(extended_base_hash, int)
        or isinstance(extended_base_hash, bool)
        or not 0 <= extended_base_hash < q
    ):
        return False

    if (
        not isinstance(genesis_code, int)
        or isinstance(genesis_code, bool)
    ):
        return False

    if not isinstance(entries, list):
        return False

    expected_genesis = hash_to_q(
        q,
        extended_base_hash,
    )

    if genesis_code != expected_genesis:
        return False

    previous_code = genesis_code

    state_codes = {
        "CAST": 1,
        "SPOILED": 2,
    }

    for expected_sequence, entry in enumerate(
        entries,
        start=1,
    ):
        if not isinstance(entry, dict):
            return False

        sequence = entry.get("sequence")
        district_index = entry.get(
            "district_index"
        )
        state = entry.get("state")
        ballot = entry.get("ballot")
        ballot_hash = entry.get(
            "ballot_hash"
        )
        tracking_code = entry.get(
            "tracking_code"
        )

        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence != expected_sequence
        ):
            return False

        if state not in state_codes:
            return False

        if state == "CAST":
            if "revealed_witness" in entry:
                return False

        if state == "SPOILED":
            if "revealed_witness" not in entry:
                return False

        try:
            expected_ballot_hash = (
                compute_ballot_hash_from_data(
                    ballot=ballot,
                    district_index=district_index,
                    extended_base_hash=extended_base_hash,
                    q=q,
                )
            )
        except ValueError:
            return False

        if ballot_hash != expected_ballot_hash:
            return False

        expected_tracking_code = hash_to_q(
            q,
            previous_code,
            sequence,
            state_codes[state],
            expected_ballot_hash,
        )

        if tracking_code != expected_tracking_code:
            return False

        previous_code = tracking_code

    return True


def _district_shape_from_configuration(
    configuration: object,
    district_index: int,
) -> tuple[int, int]:
    """
    Ricava il numero di liste e preferenze di una circoscrizione.
    """

    if not isinstance(configuration, dict):
        raise ValueError(
            "La configurazione deve essere un oggetto JSON."
        )

    lists = configuration.get("lists")
    districts = configuration.get("districts")

    if not isinstance(lists, list):
        raise ValueError(
            "La configurazione deve contenere la lista delle liste."
        )

    if not isinstance(districts, list):
        raise ValueError(
            "La configurazione deve contenere le circoscrizioni."
        )

    if not 0 <= district_index < len(districts):
        raise ValueError(
            "L'indice della circoscrizione non è valido."
        )

    list_names = []

    for political_list in lists:
        if not isinstance(political_list, dict):
            raise ValueError(
                "Ogni lista politica deve essere un oggetto JSON."
            )

        name = political_list.get("name")

        if not isinstance(name, str) or not name:
            raise ValueError(
                "Ogni lista politica deve avere un nome."
            )

        list_names.append(name)

    district = districts[district_index]

    if not isinstance(district, dict):
        raise ValueError(
            "La circoscrizione deve essere un oggetto JSON."
        )

    candidates = district.get("candidates")

    if not isinstance(candidates, dict):
        raise ValueError(
            "La circoscrizione deve contenere i candidati."
        )

    preference_count = 0

    for list_name in list_names:
        list_candidates = candidates.get(list_name)

        if not isinstance(list_candidates, list):
            raise ValueError(
                "Ogni lista deve avere i propri candidati."
            )

        if not list_candidates:
            raise ValueError(
                "Ogni lista deve avere almeno il capolista."
            )

        preference_count += len(list_candidates) - 1

    return (
        len(list_names),
        preference_count,
    )


def _ballot_components_from_data(
    ballot: object,
) -> tuple[
    tuple[tuple[int, int], ...],
    tuple[int, int],
    tuple[tuple[int, int], ...],
]:
    """
    Legge separatamente liste, bianca e preferenze di una scheda.
    """

    if not isinstance(ballot, dict):
        raise ValueError(
            "La scheda deve essere un oggetto JSON."
        )

    list_data = ballot.get("list_ciphertexts")
    blank_data = ballot.get("blank_ciphertext")
    preference_data = ballot.get(
        "preference_ciphertexts"
    )

    if not isinstance(list_data, list):
        raise ValueError(
            "I ciphertext delle liste devono essere una lista."
        )

    if not isinstance(preference_data, list):
        raise ValueError(
            "I ciphertext delle preferenze devono essere una lista."
        )

    lists = tuple(
        _ciphertext_from_data(ciphertext)
        for ciphertext in list_data
    )

    blank = _ciphertext_from_data(
        blank_data
    )

    preferences = tuple(
        _ciphertext_from_data(ciphertext)
        for ciphertext in preference_data
    )

    return (
        lists,
        blank,
        preferences,
    )


def _published_tally_from_data(
    tally: object,
) -> tuple[
    int,
    int,
    tuple[tuple[int, int], ...],
    tuple[int, int],
    tuple[tuple[int, int], ...],
]:
    """
    Legge un tally cifrato pubblicato nel registro.
    """

    if not isinstance(tally, dict):
        raise ValueError(
            "Il tally deve essere un oggetto JSON."
        )

    district_index = tally.get(
        "district_index"
    )

    ballot_count = tally.get(
        "ballot_count"
    )

    list_data = tally.get(
        "list_tallies"
    )

    blank_data = tally.get(
        "blank_tally"
    )

    preference_data = tally.get(
        "preference_tallies"
    )

    if (
        not isinstance(district_index, int)
        or isinstance(district_index, bool)
        or district_index < 0
    ):
        raise ValueError(
            "L'indice del tally non è valido."
        )

    if (
        not isinstance(ballot_count, int)
        or isinstance(ballot_count, bool)
        or ballot_count < 0
    ):
        raise ValueError(
            "Il numero di schede del tally non è valido."
        )

    if not isinstance(list_data, list):
        raise ValueError(
            "I tally delle liste devono essere una lista."
        )

    if not isinstance(preference_data, list):
        raise ValueError(
            "I tally delle preferenze devono essere una lista."
        )

    list_tallies = tuple(
        _ciphertext_from_data(ciphertext)
        for ciphertext in list_data
    )

    blank_tally = _ciphertext_from_data(
        blank_data
    )

    preference_tallies = tuple(
        _ciphertext_from_data(ciphertext)
        for ciphertext in preference_data
    )

    return (
        district_index,
        ballot_count,
        list_tallies,
        blank_tally,
        preference_tallies,
    )


def verify_v5_tallies(
    configuration: object,
    board: object,
    published_tallies: object,
    p: int,
    q: int,
) -> bool:
    """
    Verifica V5 ricalcolando i tally dalle sole schede CAST.
    """

    if not isinstance(configuration, dict):
        return False

    if not isinstance(board, dict):
        return False

    if not isinstance(published_tallies, list):
        return False

    districts = configuration.get("districts")
    entries = board.get("entries")

    if not isinstance(districts, list):
        return False

    if not isinstance(entries, list):
        return False

    if len(published_tallies) != len(districts):
        return False

    published_by_district = {}

    try:
        for tally in published_tallies:
            parsed = _published_tally_from_data(
                tally
            )

            district_index = parsed[0]

            if district_index in published_by_district:
                return False

            published_by_district[
                district_index
            ] = parsed
    except ValueError:
        return False

    expected_districts = set(
        range(len(districts))
    )

    if set(published_by_district) != expected_districts:
        return False

    for entry in entries:
        if not isinstance(entry, dict):
            return False

        district_index = entry.get(
            "district_index"
        )

        if (
            not isinstance(district_index, int)
            or isinstance(district_index, bool)
            or district_index not in expected_districts
        ):
            return False

    for district_index in range(
        len(districts)
    ):
        try:
            (
                list_count,
                preference_count,
            ) = _district_shape_from_configuration(
                configuration,
                district_index,
            )
        except ValueError:
            return False

        ballots = []

        for entry in entries:
            if (
                entry.get("state") == "CAST"
                and entry.get("district_index")
                == district_index
            ):
                try:
                    components = (
                        _ballot_components_from_data(
                            entry.get("ballot")
                        )
                    )
                except ValueError:
                    return False

                lists, blank, preferences = (
                    components
                )

                if len(lists) != list_count:
                    return False

                if len(preferences) != preference_count:
                    return False

                ballots.append(
                    (
                        lists,
                        blank,
                        preferences,
                    )
                )

        try:
            recomputed_lists = tuple(
                multiply_ciphertexts(
                    tuple(
                        ballot[0][list_index]
                        for ballot in ballots
                    ),
                    p=p,
                    q=q,
                )
                for list_index in range(
                    list_count
                )
            )

            recomputed_blank = (
                multiply_ciphertexts(
                    tuple(
                        ballot[1]
                        for ballot in ballots
                    ),
                    p=p,
                    q=q,
                )
            )

            recomputed_preferences = tuple(
                multiply_ciphertexts(
                    tuple(
                        ballot[2][preference_index]
                        for ballot in ballots
                    ),
                    p=p,
                    q=q,
                )
                for preference_index in range(
                    preference_count
                )
            )
        except ValueError:
            return False

        (
            published_district,
            published_count,
            published_lists,
            published_blank,
            published_preferences,
        ) = published_by_district[
            district_index
        ]

        if published_district != district_index:
            return False

        if published_count != len(ballots):
            return False

        if published_lists != recomputed_lists:
            return False

        if published_blank != recomputed_blank:
            return False

        if (
            published_preferences
            != recomputed_preferences
        ):
            return False

    return True


def _district_result_from_data(
    result: object,
) -> tuple[
    int,
    int,
    tuple[int, ...],
    int,
    tuple[int, ...],
    tuple[tuple[tuple[int, int], ...], ...],
]:
    """
    Legge un risultato pubblico di circoscrizione.
    """

    if not isinstance(result, dict):
        raise ValueError(
            "Il risultato deve essere un oggetto JSON."
        )

    district_index = result.get(
        "district_index"
    )
    ballot_count = result.get(
        "ballot_count"
    )
    list_votes = result.get(
        "list_votes"
    )
    blank_votes = result.get(
        "blank_votes"
    )
    preference_votes = result.get(
        "preference_votes"
    )
    decryption_shares = result.get(
        "decryption_shares"
    )

    if (
        not isinstance(district_index, int)
        or isinstance(district_index, bool)
        or district_index < 0
    ):
        raise ValueError(
            "L'indice della circoscrizione non è valido."
        )

    if (
        not isinstance(ballot_count, int)
        or isinstance(ballot_count, bool)
        or ballot_count < 0
    ):
        raise ValueError(
            "Il numero di schede non è valido."
        )

    if not isinstance(list_votes, list):
        raise ValueError(
            "I voti di lista devono essere una lista."
        )

    if not isinstance(preference_votes, list):
        raise ValueError(
            "I voti di preferenza devono essere una lista."
        )

    if (
        not isinstance(blank_votes, int)
        or isinstance(blank_votes, bool)
    ):
        raise ValueError(
            "Il numero di schede bianche deve essere un intero."
        )

    clear_lists = tuple(list_votes)
    clear_preferences = tuple(
        preference_votes
    )

    clear_values = (
        clear_lists
        + (blank_votes,)
        + clear_preferences
    )

    if any(
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > ballot_count
        for value in clear_values
    ):
        raise ValueError(
            "Ogni totale deve essere compreso tra zero e ballot_count."
        )

    if not isinstance(
        decryption_shares,
        list,
    ):
        raise ValueError(
            "Le share di decifratura devono essere una lista."
        )

    parsed_share_sets = []

    for share_set in decryption_shares:
        if not isinstance(share_set, list):
            raise ValueError(
                "Ogni insieme di share deve essere una lista."
            )

        parsed_shares = []

        for share in share_set:
            if not isinstance(share, dict):
                raise ValueError(
                    "Ogni share deve essere un oggetto JSON."
                )

            guardian_index = share.get(
                "guardian_index"
            )
            partial_decryption = share.get(
                "partial_decryption"
            )

            if (
                not isinstance(guardian_index, int)
                or isinstance(guardian_index, bool)
                or guardian_index < 1
            ):
                raise ValueError(
                    "L'indice del garante non è valido."
                )

            if (
                not isinstance(partial_decryption, int)
                or isinstance(
                    partial_decryption,
                    bool,
                )
            ):
                raise ValueError(
                    "La share parziale deve essere un intero."
                )

            parsed_shares.append(
                (
                    guardian_index,
                    partial_decryption,
                )
            )

        parsed_share_sets.append(
            tuple(parsed_shares)
        )

    return (
        district_index,
        ballot_count,
        clear_lists,
        blank_votes,
        clear_preferences,
        tuple(parsed_share_sets),
    )


def verify_v7_results(
    published_tallies: object,
    district_results: object,
    p: int,
    q: int,
    g: int,
    quorum: int,
) -> bool:
    """
    Verifica V7 sui risultati decifrati pubblicati.

    Per ogni totale controlla:
    B / M = g^t mod p
    """

    if (
        not isinstance(published_tallies, list)
        or not isinstance(district_results, list)
    ):
        return False

    if (
        not isinstance(quorum, int)
        or isinstance(quorum, bool)
        or quorum < 1
    ):
        return False

    if len(published_tallies) != len(
        district_results
    ):
        return False

    tallies_by_district = {}
    results_by_district = {}

    try:
        for tally in published_tallies:
            parsed_tally = (
                _published_tally_from_data(
                    tally
                )
            )

            district_index = parsed_tally[0]

            if district_index in tallies_by_district:
                return False

            tallies_by_district[
                district_index
            ] = parsed_tally

        for result in district_results:
            parsed_result = (
                _district_result_from_data(
                    result
                )
            )

            district_index = parsed_result[0]

            if district_index in results_by_district:
                return False

            results_by_district[
                district_index
            ] = parsed_result
    except ValueError:
        return False

    if set(tallies_by_district) != set(
        results_by_district
    ):
        return False

    for district_index in tallies_by_district:
        (
            _,
            tally_ballot_count,
            list_tallies,
            blank_tally,
            preference_tallies,
        ) = tallies_by_district[
            district_index
        ]

        (
            _,
            result_ballot_count,
            list_votes,
            blank_votes,
            preference_votes,
            share_sets,
        ) = results_by_district[
            district_index
        ]

        if (
            tally_ballot_count
            != result_ballot_count
        ):
            return False

        if len(list_tallies) != len(
            list_votes
        ):
            return False

        if len(preference_tallies) != len(
            preference_votes
        ):
            return False

        ciphertexts = (
            list_tallies
            + (blank_tally,)
            + preference_tallies
        )

        clear_totals = (
            list_votes
            + (blank_votes,)
            + preference_votes
        )

        if len(share_sets) != len(
            ciphertexts
        ):
            return False

        for (
            ciphertext,
            clear_total,
            shares,
        ) in zip(
            ciphertexts,
            clear_totals,
            share_sets,
            strict=True,
        ):
            alpha, beta = ciphertext

            if not is_subgroup_element(
                alpha,
                p,
                q,
            ):
                return False

            if not is_subgroup_element(
                beta,
                p,
                q,
            ):
                return False

            try:
                combined_decryption = (
                    combine_decryption_shares(
                        shares=shares,
                        p=p,
                        q=q,
                        quorum=quorum,
                    )
                )
            except ValueError:
                return False

            try:
                decoded_element = (
                    beta
                    * pow(
                        combined_decryption,
                        -1,
                        p,
                    )
                ) % p
            except ValueError:
                return False

            expected_element = _mod_pow(
                g,
                clear_total,
                p,
            )

            if decoded_element != expected_element:
                return False

    return True


def _percentage_to_fraction(
    value: object,
) -> Fraction:
    """
    Converte una percentuale JSON in una frazione esatta.
    """

    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
    ):
        raise ValueError(
            "La percentuale deve essere numerica."
        )

    result = Fraction(str(value)) / 100

    if not 0 <= result <= 1:
        raise ValueError(
            "La percentuale deve essere compresa tra 0 e 100."
        )

    return result


def _v8_largest_remainder(
    votes: tuple[int, ...],
    seats: int,
) -> tuple[int, ...]:
    """
    Ripartisce i seggi con il metodo dei più alti resti.
    """

    if seats < 0:
        raise ValueError(
            "Il numero di seggi deve essere non negativo."
        )

    if any(vote < 0 for vote in votes):
        raise ValueError(
            "I voti devono essere non negativi."
        )

    if seats == 0:
        return tuple(
            0
            for _ in votes
        )

    total = sum(votes)

    if total == 0:
        raise ValueError(
            "Non ci sono voti su cui ripartire i seggi."
        )

    allocation = [
        vote * seats // total
        for vote in votes
    ]

    remainders = [
        vote * seats % total
        for vote in votes
    ]

    order = sorted(
        range(len(votes)),
        key=lambda index: (
            -remainders[index],
            -votes[index],
            index,
        ),
    )

    remaining = seats - sum(allocation)

    for index in order[:remaining]:
        allocation[index] += 1

    return tuple(allocation)


def _v8_distribute_with_caps(
    votes: tuple[int, ...],
    seats: int,
    caps: tuple[int, ...],
) -> tuple[int, ...]:
    """
    Distribuisce i seggi senza superare i candidati disponibili.
    """

    if len(votes) != len(caps):
        raise ValueError(
            "Serve un limite per ogni circoscrizione."
        )

    if seats > sum(caps):
        raise ValueError(
            "Non ci sono abbastanza candidati per i seggi."
        )

    if seats == 0:
        return tuple(
            0
            for _ in votes
        )

    total = sum(votes)

    if total == 0:
        raise ValueError(
            "Non ci sono voti su cui ripartire i seggi."
        )

    remainders = [
        vote * seats % total
        for vote in votes
    ]

    allocation = [
        min(
            vote * seats // total,
            cap,
        )
        for vote, cap in zip(
            votes,
            caps,
            strict=True,
        )
    ]

    order = sorted(
        range(len(votes)),
        key=lambda index: (
            -remainders[index],
            -votes[index],
            index,
        ),
    )

    remaining = seats - sum(allocation)

    while remaining > 0:
        assigned = False

        for index in order:
            if remaining == 0:
                break

            if allocation[index] < caps[index]:
                allocation[index] += 1
                remaining -= 1
                assigned = True

        if not assigned:
            raise ValueError(
                "Non è possibile distribuire tutti i seggi."
            )

    return tuple(allocation)


def _v8_parse_configuration(
    configuration: object,
) -> dict[str, object]:
    """
    Legge i dati della configurazione necessari allo scrutinio.
    """

    if not isinstance(configuration, dict):
        raise ValueError(
            "La configurazione deve essere un oggetto JSON."
        )

    seats = configuration.get("seats")
    rules = configuration.get("rules")
    lists = configuration.get("lists")
    districts = configuration.get("districts")

    if (
        not isinstance(seats, int)
        or isinstance(seats, bool)
        or seats < 1
    ):
        raise ValueError(
            "Il numero di seggi deve essere positivo."
        )

    if not isinstance(rules, dict):
        raise ValueError(
            "Le regole elettorali non sono valide."
        )

    if not isinstance(lists, list) or not lists:
        raise ValueError(
            "La configurazione deve contenere le liste."
        )

    if not isinstance(districts, list) or not districts:
        raise ValueError(
            "La configurazione deve contenere le circoscrizioni."
        )

    list_names = []
    coalition_names = []
    coalition_indices: dict[str, list[int]] = {}

    for list_index, political_list in enumerate(
        lists
    ):
        if not isinstance(political_list, dict):
            raise ValueError(
                "Ogni lista deve essere un oggetto JSON."
            )

        name = political_list.get("name")
        coalition = political_list.get("coalition")

        if not isinstance(name, str) or not name:
            raise ValueError(
                "Ogni lista deve avere un nome."
            )

        if name in list_names:
            raise ValueError(
                "I nomi delle liste devono essere distinti."
            )

        if (
            coalition is not None
            and (
                not isinstance(coalition, str)
                or not coalition
            )
        ):
            raise ValueError(
                "Il nome della coalizione non è valido."
            )

        list_names.append(name)

        if coalition is not None:
            if coalition not in coalition_indices:
                coalition_names.append(
                    coalition
                )
                coalition_indices[
                    coalition
                ] = []

            coalition_indices[
                coalition
            ].append(list_index)

    parsed_districts = []

    for district in districts:
        if not isinstance(district, dict):
            raise ValueError(
                "Ogni circoscrizione deve essere un oggetto JSON."
            )

        candidates = district.get(
            "candidates"
        )

        if not isinstance(candidates, dict):
            raise ValueError(
                "Ogni circoscrizione deve contenere i candidati."
            )

        district_candidates = []

        for list_name in list_names:
            list_candidates = candidates.get(
                list_name
            )

            if (
                not isinstance(list_candidates, list)
                or not list_candidates
            ):
                raise ValueError(
                    "Ogni lista deve avere almeno il capolista."
                )

            parsed_candidates = []

            for candidate in list_candidates:
                if not isinstance(candidate, dict):
                    raise ValueError(
                        "Ogni candidato deve essere un oggetto JSON."
                    )

                name = candidate.get("name")

                if not isinstance(name, str) or not name:
                    raise ValueError(
                        "Ogni candidato deve avere un nome."
                    )

                parsed_candidates.append(
                    name
                )

            district_candidates.append(
                tuple(parsed_candidates)
            )

        parsed_districts.append(
            tuple(district_candidates)
        )

    return {
        "seats": seats,
        "list_names": tuple(list_names),
        "coalitions": tuple(
            (
                coalition_name,
                tuple(
                    coalition_indices[
                        coalition_name
                    ]
                ),
            )
            for coalition_name in coalition_names
        ),
        "districts": tuple(
            parsed_districts
        ),
        "list_threshold": _percentage_to_fraction(
            rules.get(
                "list_threshold_percent"
            )
        ),
        "coalition_threshold":
            _percentage_to_fraction(
                rules.get(
                    "coalition_threshold_percent"
                )
            ),
        "bonus_threshold":
            _percentage_to_fraction(
                rules.get(
                    "bonus_threshold_percent"
                )
            ),
        "bonus_seat_share":
            _percentage_to_fraction(
                rules.get(
                    "bonus_seats_percent"
                )
            ),
    }


def _v8_parse_results(
    district_results: object,
    config: dict[str, object],
) -> tuple[dict[str, object], ...]:
    """
    Legge i risultati in chiaro usati per rifare lo scrutinio.
    """

    if not isinstance(
        district_results,
        list,
    ):
        raise ValueError(
            "I risultati devono essere una lista."
        )

    districts = config["districts"]
    list_names = config["list_names"]

    if len(district_results) != len(
        districts
    ):
        raise ValueError(
            "Serve un risultato per ogni circoscrizione."
        )

    parsed = []

    for district_index, result in enumerate(
        district_results
    ):
        if not isinstance(result, dict):
            raise ValueError(
                "Ogni risultato deve essere un oggetto JSON."
            )

        if result.get(
            "district_index"
        ) != district_index:
            raise ValueError(
                "I risultati devono seguire l'ordine delle circoscrizioni."
            )

        list_votes = result.get(
            "list_votes"
        )
        blank_votes = result.get(
            "blank_votes"
        )
        preference_votes = result.get(
            "preference_votes"
        )

        if (
            not isinstance(list_votes, list)
            or len(list_votes) != len(
                list_names
            )
        ):
            raise ValueError(
                "Il numero dei voti di lista non è corretto."
            )

        if (
            not isinstance(blank_votes, int)
            or isinstance(blank_votes, bool)
            or blank_votes < 0
        ):
            raise ValueError(
                "Il numero delle schede bianche non è valido."
            )

        if not isinstance(
            preference_votes,
            list,
        ):
            raise ValueError(
                "I voti di preferenza devono essere una lista."
            )

        expected_preferences = sum(
            len(candidates) - 1
            for candidates in districts[
                district_index
            ]
        )

        if len(
            preference_votes
        ) != expected_preferences:
            raise ValueError(
                "Il numero dei voti di preferenza non è corretto."
            )

        all_votes = (
            list_votes
            + [blank_votes]
            + preference_votes
        )

        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            for value in all_votes
        ):
            raise ValueError(
                "I voti devono essere interi non negativi."
            )

        parsed.append(
            {
                "list_votes": tuple(
                    list_votes
                ),
                "blank_votes": blank_votes,
                "preference_votes": tuple(
                    preference_votes
                ),
            }
        )

    return tuple(parsed)


def _v8_allocate_competitor_seats(
    votes: tuple[int, ...],
    valid_votes: int,
    seats: int,
    bonus_threshold: Fraction,
    bonus_seat_share: Fraction,
) -> tuple[tuple[int, ...], int | None]:
    """
    Ripartisce i seggi tra i competitori e applica il premio.
    """

    proportional = _v8_largest_remainder(
        votes,
        seats,
    )

    best = max(votes)

    leaders = [
        index
        for index, vote in enumerate(
            votes
        )
        if vote == best
    ]

    if len(leaders) != 1:
        return (
            proportional,
            None,
        )

    winner = leaders[0]

    if (
        Fraction(votes[winner])
        < bonus_threshold * valid_votes
    ):
        return (
            proportional,
            None,
        )

    bonus_seats = math.ceil(
        bonus_seat_share * seats
    )

    if proportional[winner] >= bonus_seats:
        return (
            proportional,
            None,
        )

    others = tuple(
        index
        for index in range(len(votes))
        if index != winner
    )

    if not others:
        return (
            proportional,
            None,
        )

    others_seats = _v8_largest_remainder(
        tuple(
            votes[index]
            for index in others
        ),
        seats - bonus_seats,
    )

    allocation = [
        0
        for _ in votes
    ]

    allocation[winner] = bonus_seats

    for index, seat_count in zip(
        others,
        others_seats,
        strict=True,
    ):
        allocation[index] = seat_count

    return (
        tuple(allocation),
        winner,
    )


def recompute_v8_scrutiny(
    configuration: object,
    district_results: object,
) -> dict[str, object]:
    """
    Rifà integralmente lo scrutinio usando solo dati pubblici.
    """

    config = _v8_parse_configuration(
        configuration
    )

    results = _v8_parse_results(
        district_results,
        config,
    )

    list_names = config["list_names"]
    coalitions = config["coalitions"]
    districts = config["districts"]
    seats = config["seats"]

    list_count = len(list_names)

    list_votes = tuple(
        sum(
            result["list_votes"][
                list_index
            ]
            for result in results
        )
        for list_index in range(
            list_count
        )
    )

    blank_votes = sum(
        result["blank_votes"]
        for result in results
    )

    valid_votes = sum(list_votes)

    if valid_votes == 0:
        raise ValueError(
            "Non ci sono voti validi."
        )

    coalition_votes = tuple(
        sum(
            list_votes[list_index]
            for list_index in list_indices
        )
        for _, list_indices in coalitions
    )

    list_admitted = tuple(
        vote > 0
        and Fraction(vote)
        >= config["list_threshold"]
        * valid_votes
        for vote in list_votes
    )

    competitors = []
    lists_in_admitted_coalitions = set()

    for (
        coalition_index,
        (
            coalition_name,
            list_indices,
        ),
    ) in enumerate(coalitions):
        votes = coalition_votes[
            coalition_index
        ]

        eligible = tuple(
            list_index
            for list_index in list_indices
            if list_admitted[
                list_index
            ]
        )

        if (
            Fraction(votes)
            >= config[
                "coalition_threshold"
            ]
            * valid_votes
            and eligible
        ):
            competitors.append(
                {
                    "name": coalition_name,
                    "list_indices": eligible,
                    "votes": votes,
                    "is_coalition": True,
                }
            )

            lists_in_admitted_coalitions.update(
                list_indices
            )

    for list_index, list_name in enumerate(
        list_names
    ):
        if (
            list_index
            in lists_in_admitted_coalitions
        ):
            continue

        if list_admitted[list_index]:
            competitors.append(
                {
                    "name": list_name,
                    "list_indices": (
                        list_index,
                    ),
                    "votes": list_votes[
                        list_index
                    ],
                    "is_coalition": False,
                }
            )

    if not competitors:
        raise ValueError(
            "Nessun competitore supera le soglie."
        )

    (
        competitor_seats,
        bonus_competitor,
    ) = _v8_allocate_competitor_seats(
        votes=tuple(
            competitor["votes"]
            for competitor in competitors
        ),
        valid_votes=valid_votes,
        seats=seats,
        bonus_threshold=config[
            "bonus_threshold"
        ],
        bonus_seat_share=config[
            "bonus_seat_share"
        ],
    )

    list_seats = [
        0
        for _ in list_names
    ]

    for competitor, seat_count in zip(
        competitors,
        competitor_seats,
        strict=True,
    ):
        member_seats = (
            _v8_largest_remainder(
                tuple(
                    list_votes[index]
                    for index
                    in competitor[
                        "list_indices"
                    ]
                ),
                seat_count,
            )
        )

        for (
            list_index,
            member_seat_count,
        ) in zip(
            competitor[
                "list_indices"
            ],
            member_seats,
            strict=True,
        ):
            list_seats[
                list_index
            ] = member_seat_count

    district_list_seats = [
        [
            0
            for _ in list_names
        ]
        for _ in districts
    ]

    for list_index in range(
        list_count
    ):
        if list_seats[list_index] == 0:
            continue

        allocation = (
            _v8_distribute_with_caps(
                votes=tuple(
                    result[
                        "list_votes"
                    ][list_index]
                    for result in results
                ),
                seats=list_seats[
                    list_index
                ],
                caps=tuple(
                    len(
                        district[
                            list_index
                        ]
                    )
                    for district in districts
                ),
            )
        )

        for (
            district_index,
            seat_count,
        ) in enumerate(allocation):
            district_list_seats[
                district_index
            ][list_index] = seat_count

    elected = []

    for (
        district_index,
        district,
    ) in enumerate(districts):
        preference_map = {}
        preference_offset = 0

        for (
            list_index,
            candidates,
        ) in enumerate(district):
            for position in range(
                1,
                len(candidates),
            ):
                preference_map[
                    (
                        list_index,
                        position,
                    )
                ] = results[
                    district_index
                ][
                    "preference_votes"
                ][preference_offset]

                preference_offset += 1

        for (
            list_index,
            candidates,
        ) in enumerate(district):
            seat_count = (
                district_list_seats[
                    district_index
                ][list_index]
            )

            if seat_count == 0:
                continue

            ranking = sorted(
                range(
                    1,
                    len(candidates),
                ),
                key=lambda position: (
                    -preference_map[
                        (
                            list_index,
                            position,
                        )
                    ],
                    position,
                ),
            )

            positions = (
                [0]
                + ranking[
                    :seat_count - 1
                ]
            )

            for position in positions:
                elected.append(
                    {
                        "district_index":
                            district_index,
                        "list_index":
                            list_index,
                        "name":
                            candidates[
                                position
                            ],
                        "position":
                            position,
                        "preferences": (
                            0
                            if position == 0
                            else preference_map[
                                (
                                    list_index,
                                    position,
                                )
                            ]
                        ),
                    }
                )

    return {
        "valid_votes": valid_votes,
        "blank_votes": blank_votes,
        "list_votes": list(
            list_votes
        ),
        "coalition_votes": list(
            coalition_votes
        ),
        "competitors": [
            {
                "name":
                    competitor["name"],
                "list_indices": list(
                    competitor[
                        "list_indices"
                    ]
                ),
                "votes":
                    competitor["votes"],
                "is_coalition":
                    competitor[
                        "is_coalition"
                    ],
            }
            for competitor in competitors
        ],
        "competitor_seats": list(
            competitor_seats
        ),
        "bonus_competitor":
            bonus_competitor,
        "list_seats": list(
            list_seats
        ),
        "district_list_seats": [
            list(row)
            for row
            in district_list_seats
        ],
        "elected": elected,
    }


def verify_v8_scrutiny(
    configuration: object,
    district_results: object,
    published_scrutiny: object,
) -> bool:
    """
    Verifica V8 rifacendo interamente lo scrutinio.
    """

    if not isinstance(
        published_scrutiny,
        dict,
    ):
        return False

    try:
        expected = (
            recompute_v8_scrutiny(
                configuration=
                    configuration,
                district_results=
                    district_results,
            )
        )
    except (
        ValueError,
        KeyError,
        TypeError,
        IndexError,
    ):
        return False

    return expected == published_scrutiny


def _proof_branches_from_data(
    proof: object,
) -> tuple[
    tuple[int, int, int, int],
    ...,
]:
    """
    Legge i rami di una prova OR dal registro.
    """

    if not isinstance(proof, dict):
        raise ValueError(
            "La prova OR deve essere un oggetto JSON."
        )

    branches = proof.get("branches")

    if not isinstance(branches, list):
        raise ValueError(
            "La prova OR deve contenere i rami."
        )

    parsed = []

    for branch in branches:
        if not isinstance(branch, dict):
            raise ValueError(
                "Ogni ramo deve essere un oggetto JSON."
            )

        values = (
            branch.get("commitment_1"),
            branch.get("commitment_2"),
            branch.get("challenge"),
            branch.get("response"),
        )

        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            for value in values
        ):
            raise ValueError(
                "I valori della prova OR devono essere interi."
            )

        parsed.append(values)

    return tuple(parsed)


def _preference_metadata_from_configuration(
    configuration: object,
    district_index: int,
) -> tuple[tuple[int, str], ...]:
    """
    Ricostruisce lista e genere di ogni casella di preferenza.
    """

    if not isinstance(configuration, dict):
        raise ValueError(
            "La configurazione non è valida."
        )

    lists = configuration.get("lists")
    districts = configuration.get("districts")

    if (
        not isinstance(lists, list)
        or not isinstance(districts, list)
    ):
        raise ValueError(
            "Liste o circoscrizioni mancanti."
        )

    if not 0 <= district_index < len(districts):
        raise ValueError(
            "La circoscrizione non è valida."
        )

    district = districts[district_index]

    if not isinstance(district, dict):
        raise ValueError(
            "La circoscrizione non è valida."
        )

    candidates = district.get("candidates")

    if not isinstance(candidates, dict):
        raise ValueError(
            "I candidati non sono validi."
        )

    metadata = []

    for list_index, political_list in enumerate(
        lists
    ):
        if not isinstance(political_list, dict):
            raise ValueError(
                "La lista politica non è valida."
            )

        list_name = political_list.get("name")

        if not isinstance(list_name, str):
            raise ValueError(
                "Il nome della lista non è valido."
            )

        list_candidates = candidates.get(
            list_name
        )

        if (
            not isinstance(list_candidates, list)
            or not list_candidates
        ):
            raise ValueError(
                "I candidati della lista non sono validi."
            )

        for candidate in list_candidates[1:]:
            if not isinstance(candidate, dict):
                raise ValueError(
                    "Il candidato non è valido."
                )

            gender = candidate.get("gender")

            if not isinstance(gender, str):
                raise ValueError(
                    "Il genere del candidato non è valido."
                )

            metadata.append(
                (
                    list_index,
                    gender,
                )
            )

    return tuple(metadata)


def verify_v2_guardians(
    registry: object,
) -> bool:
    """
    Verifica V2 e i contesti pubblici della cerimonia.
    """

    if not isinstance(registry, dict):
        return False

    try:
        group = registry["group"]
        context = registry["election_context"]
        guardians = registry["guardians"]
        configuration = registry["configuration"]
        public_key = registry["K"]

        if (
            not isinstance(group, dict)
            or not isinstance(context, dict)
            or not isinstance(guardians, list)
            or not isinstance(configuration, dict)
        ):
            return False

        p = group["p"]
        q = group["q"]
        g = group["g"]

        n = context["n"]
        quorum = context["quorum"]
        election_id = context["e"]
        base_hash = context["Q"]
        extended_base_hash = context["Q_bar"]

        values = (
            p,
            q,
            g,
            n,
            quorum,
            election_id,
            base_hash,
            extended_base_hash,
            public_key,
        )

        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            for value in values
        ):
            return False

        if configuration.get(
            "election_id"
        ) != election_id:
            return False

        if n != len(guardians):
            return False

        if not 1 <= quorum <= n:
            return False

        expected_q = hash_to_q(
            q,
            p,
            q,
            g,
            n,
            quorum,
            election_id,
        )

        if base_hash != expected_q:
            return False

        commitment_sets = []

        for expected_index, guardian in enumerate(
            guardians,
            start=1,
        ):
            if not isinstance(guardian, dict):
                return False

            guardian_index = guardian.get(
                "index"
            )
            commitments = guardian.get(
                "commitments"
            )
            proofs = guardian.get(
                "proofs"
            )

            if guardian_index != expected_index:
                return False

            if (
                not isinstance(commitments, list)
                or not isinstance(proofs, list)
            ):
                return False

            if (
                len(commitments) != quorum
                or len(proofs) != quorum
            ):
                return False

            parsed_commitments = tuple(
                commitments
            )

            for coefficient_index, (
                commitment,
                proof,
            ) in enumerate(
                zip(
                    parsed_commitments,
                    proofs,
                    strict=True,
                )
            ):
                if not isinstance(proof, dict):
                    return False

                if not verify_schnorr_commitment(
                    p=p,
                    q=q,
                    g=g,
                    context=base_hash,
                    guardian_index=guardian_index,
                    coefficient_index=
                        coefficient_index,
                    commitment=commitment,
                    proof_commitment=proof.get(
                        "commitment"
                    ),
                    challenge=proof.get(
                        "challenge"
                    ),
                    response=proof.get(
                        "response"
                    ),
                ):
                    return False

            commitment_sets.append(
                parsed_commitments
            )

        expected_key = compute_joint_public_key(
            commitment_sets=tuple(
                commitment_sets
            ),
            p=p,
            q=q,
        )

        if public_key != expected_key:
            return False

        expected_q_bar = hash_to_q(
            q,
            base_hash,
            public_key,
        )

        if (
            extended_base_hash
            != expected_q_bar
        ):
            return False

        board = registry["bulletin_board"]

        if not isinstance(board, dict):
            return False

        if board.get(
            "extended_base_hash"
        ) != extended_base_hash:
            return False

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return False

    return True


def verify_v3_ballots(
    registry: object,
) -> bool:
    """
    Verifica R1-R5 di tutte le schede pubblicate.
    """

    if not isinstance(registry, dict):
        return False

    try:
        group = registry["group"]
        context = registry["election_context"]
        configuration = registry["configuration"]
        board = registry["bulletin_board"]
        public_key = registry["K"]

        p = group["p"]
        q = group["q"]
        g = group["g"]
        q_bar = context["Q_bar"]

        rules = configuration["rules"]

        max_preferences = rules[
            "max_preferences"
        ]
        max_per_gender = rules[
            "max_preferences_per_gender"
        ]

        entries = board["entries"]

        if not isinstance(entries, list):
            return False

        for entry in entries:
            if not isinstance(entry, dict):
                return False

            district_index = entry.get(
                "district_index"
            )

            (
                list_ciphertexts,
                blank_ciphertext,
                preference_ciphertexts,
            ) = _ballot_components_from_data(
                entry.get("ballot")
            )

            metadata = (
                _preference_metadata_from_configuration(
                    configuration,
                    district_index,
                )
            )

            if len(
                preference_ciphertexts
            ) != len(metadata):
                return False

            proofs = entry.get("proofs")

            if not isinstance(proofs, dict):
                return False

            r1_proofs = proofs.get(
                "r1_proofs"
            )
            r3_proofs = proofs.get(
                "r3_proofs"
            )
            r5_proofs = proofs.get(
                "r5_proofs"
            )

            if (
                not isinstance(r1_proofs, list)
                or not isinstance(r3_proofs, list)
                or not isinstance(r5_proofs, list)
            ):
                return False

            canonical = (
                list_ciphertexts
                + (blank_ciphertext,)
                + preference_ciphertexts
            )

            if len(r1_proofs) != len(
                canonical
            ):
                return False

            for ciphertext, proof in zip(
                canonical,
                r1_proofs,
                strict=True,
            ):
                if not verify_value_set_proof(
                    p=p,
                    q=q,
                    g=g,
                    public_key=public_key,
                    context=q_bar,
                    alpha=ciphertext[0],
                    beta=ciphertext[1],
                    allowed_values=(0, 1),
                    branches=
                        _proof_branches_from_data(
                            proof
                        ),
                ):
                    return False

            if not verify_r2_rule(
                ciphertexts=(
                    list_ciphertexts
                    + (blank_ciphertext,)
                ),
                branches=
                    _proof_branches_from_data(
                        proofs.get(
                            "r2_proof"
                        )
                    ),
                p=p,
                q=q,
                g=g,
                public_key=public_key,
                context=q_bar,
            ):
                return False

            if len(r3_proofs) != len(
                metadata
            ):
                return False

            for (
                preference_index,
                (
                    list_index,
                    _,
                ),
            ) in enumerate(metadata):
                if not verify_r3_rule(
                    list_ciphertext=
                        list_ciphertexts[
                            list_index
                        ],
                    preference_ciphertext=
                        preference_ciphertexts[
                            preference_index
                        ],
                    branches=
                        _proof_branches_from_data(
                            r3_proofs[
                                preference_index
                            ]
                        ),
                    p=p,
                    q=q,
                    g=g,
                    public_key=public_key,
                    context=q_bar,
                ):
                    return False

            if not verify_r4_rule(
                preference_ciphertexts=
                    preference_ciphertexts,
                branches=
                    _proof_branches_from_data(
                        proofs.get(
                            "r4_proof"
                        )
                    ),
                p=p,
                q=q,
                g=g,
                public_key=public_key,
                context=q_bar,
                max_preferences=
                    max_preferences,
            ):
                return False

            gender_order = []

            for _, gender in metadata:
                if gender not in gender_order:
                    gender_order.append(
                        gender
                    )

            if len(r5_proofs) != len(
                gender_order
            ):
                return False

            for gender_index, gender in enumerate(
                gender_order
            ):
                gender_ciphertexts = tuple(
                    preference_ciphertexts[
                        preference_index
                    ]
                    for preference_index, (
                        _,
                        preference_gender,
                    ) in enumerate(metadata)
                    if preference_gender == gender
                )

                if not verify_r5_rule(
                    gender_ciphertexts=
                        gender_ciphertexts,
                    branches=
                        _proof_branches_from_data(
                            r5_proofs[
                                gender_index
                            ]
                        ),
                    p=p,
                    q=q,
                    g=g,
                    public_key=public_key,
                    context=q_bar,
                    max_preferences_per_gender=
                        max_per_gender,
                ):
                    return False

    except (
        KeyError,
        TypeError,
        ValueError,
        IndexError,
    ):
        return False

    return True


def verify_v6_decryption_shares(
    registry: object,
) -> bool:
    """
    Verifica tutte le prove delle share di decifratura.
    """

    if not isinstance(registry, dict):
        return False

    try:
        group = registry["group"]
        context = registry["election_context"]
        guardians = registry["guardians"]
        tallies = registry[
            "district_tallies"
        ]
        results = registry[
            "district_results"
        ]

        p = group["p"]
        q = group["q"]
        g = group["g"]
        q_bar = context["Q_bar"]
        quorum = context["quorum"]

        commitment_sets = tuple(
            tuple(
                guardian["commitments"]
            )
            for guardian in guardians
        )

        tallies_by_district = {}

        for tally in tallies:
            parsed = (
                _published_tally_from_data(
                    tally
                )
            )

            tallies_by_district[
                parsed[0]
            ] = parsed

        for result in results:
            if not isinstance(result, dict):
                return False

            district_index = result.get(
                "district_index"
            )

            if (
                district_index
                not in tallies_by_district
            ):
                return False

            (
                _,
                _,
                list_tallies,
                blank_tally,
                preference_tallies,
            ) = tallies_by_district[
                district_index
            ]

            ciphertexts = (
                list_tallies
                + (blank_tally,)
                + preference_tallies
            )

            share_sets = result.get(
                "decryption_shares"
            )

            if not isinstance(
                share_sets,
                list,
            ):
                return False

            if len(share_sets) != len(
                ciphertexts
            ):
                return False

            for ciphertext, share_set in zip(
                ciphertexts,
                share_sets,
                strict=True,
            ):
                if (
                    not isinstance(
                        share_set,
                        list,
                    )
                    or len(share_set)
                    < quorum
                ):
                    return False

                used_guardians = set()

                for share in share_set:
                    if not isinstance(
                        share,
                        dict,
                    ):
                        return False

                    guardian_index = (
                        share.get(
                            "guardian_index"
                        )
                    )

                    if (
                        not isinstance(
                            guardian_index,
                            int,
                        )
                        or isinstance(
                            guardian_index,
                            bool,
                        )
                        or not 1
                        <= guardian_index
                        <= len(guardians)
                        or guardian_index
                        in used_guardians
                    ):
                        return False

                    used_guardians.add(
                        guardian_index
                    )

                    verification_key = (
                        compute_verification_key(
                            guardian_index=
                                guardian_index,
                            commitment_sets=
                                commitment_sets,
                            p=p,
                            q=q,
                        )
                    )

                    proof = share.get(
                        "proof"
                    )

                    if not isinstance(
                        proof,
                        dict,
                    ):
                        return False

                    if not verify_chaum_pedersen_share(
                        p=p,
                        q=q,
                        g=g,
                        context=q_bar,
                        guardian_index=
                            guardian_index,
                        verification_key=
                            verification_key,
                        tally_alpha=
                            ciphertext[0],
                        partial_decryption=
                            share.get(
                                "partial_decryption"
                            ),
                        commitment_1=
                            proof.get(
                                "commitment_1"
                            ),
                        commitment_2=
                            proof.get(
                                "commitment_2"
                            ),
                        challenge=
                            proof.get(
                                "challenge"
                            ),
                        response=
                            proof.get(
                                "response"
                            ),
                    ):
                        return False

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return False

    return True


def verify_public_registry(
    serialized: str,
) -> dict[str, bool]:
    """
    Esegue tutti i controlli V1-V8 sul registro pubblico.
    """

    try:
        registry = parse_public_registry(
            serialized
        )
    except ValueError:
        return {
            "V1": False,
            "V2": False,
            "V3": False,
            "V4": False,
            "V5": False,
            "V6": False,
            "V7": False,
            "V8": False,
            "overall": False,
        }

    try:
        group = registry["group"]
        context = registry[
            "election_context"
        ]

        p = group["p"]
        q = group["q"]
        g = group["g"]
        public_key = registry["K"]
        quorum = context["quorum"]

        v1 = verify_v1_parameters(
            p=p,
            q=q,
            g=g,
            public_key=public_key,
        )

        v2 = verify_v2_guardians(
            registry
        )

        v3 = verify_v3_ballots(
            registry
        )

        v4 = (
            verify_v4_board_chain(
                board=registry[
                    "bulletin_board"
                ],
                q=q,
            )
            and verify_v4_board_rules(
                board=registry[
                    "bulletin_board"
                ],
                public_key=public_key,
                p=p,
                q=q,
                g=g,
            )
        )

        v5 = verify_v5_tallies(
            configuration=registry[
                "configuration"
            ],
            board=registry[
                "bulletin_board"
            ],
            published_tallies=registry[
                "district_tallies"
            ],
            p=p,
            q=q,
        )

        v6 = verify_v6_decryption_shares(
            registry
        )

        v7 = verify_v7_results(
            published_tallies=registry[
                "district_tallies"
            ],
            district_results=registry[
                "district_results"
            ],
            p=p,
            q=q,
            g=g,
            quorum=quorum,
        )

        v8 = verify_v8_scrutiny(
            configuration=registry[
                "configuration"
            ],
            district_results=registry[
                "district_results"
            ],
            published_scrutiny=registry[
                "scrutiny"
            ],
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return {
            "V1": False,
            "V2": False,
            "V3": False,
            "V4": False,
            "V5": False,
            "V6": False,
            "V7": False,
            "V8": False,
            "overall": False,
        }

    checks = {
        "V1": v1,
        "V2": v2,
        "V3": v3,
        "V4": v4,
        "V5": v5,
        "V6": v6,
        "V7": v7,
        "V8": v8,
    }

    checks["overall"] = all(
        checks.values()
    )

    return checks


def _encrypt_from_public_data(
    message: int,
    nonce: int,
    public_key: int,
    p: int,
    q: int,
    g: int,
) -> tuple[int, int]:
    """
    Ricifra un valore usando soltanto dati pubblici.
    """

    if (
        not isinstance(message, int)
        or isinstance(message, bool)
        or message < 0
    ):
        raise ValueError(
            "Il plaintext deve essere un intero non negativo."
        )

    if (
        not isinstance(nonce, int)
        or isinstance(nonce, bool)
        or not 1 <= nonce < q
    ):
        raise ValueError(
            "Il nonce deve essere compreso tra 1 e q - 1."
        )

    if not is_subgroup_element(
        public_key,
        p,
        q,
    ):
        raise ValueError(
            "La chiave pubblica non appartiene al sottogruppo."
        )

    alpha = _mod_pow(
        g,
        nonce,
        p,
    )

    beta = (
        _mod_pow(
            g,
            message,
            p,
        )
        * _mod_pow(
            public_key,
            nonce,
            p,
        )
    ) % p

    return (
        alpha,
        beta,
    )


def verify_spoiled_witness_from_data(
    ballot: object,
    witness: object,
    public_key: int,
    p: int,
    q: int,
    g: int,
) -> bool:
    """
    Verifica una scheda SPOILED ricifrandone il witness.
    """

    if not isinstance(witness, dict):
        return False

    try:
        ciphertexts = (
            _ballot_ciphertexts_from_data(
                ballot
            )
        )

        list_plaintexts = witness.get(
            "list_plaintexts"
        )
        blank_plaintext = witness.get(
            "blank_plaintext"
        )
        preference_plaintexts = witness.get(
            "preference_plaintexts"
        )

        list_nonces = witness.get(
            "list_nonces"
        )
        blank_nonce = witness.get(
            "blank_nonce"
        )
        preference_nonces = witness.get(
            "preference_nonces"
        )

        if (
            not isinstance(list_plaintexts, list)
            or not isinstance(
                preference_plaintexts,
                list,
            )
            or not isinstance(list_nonces, list)
            or not isinstance(
                preference_nonces,
                list,
            )
        ):
            return False

        plaintexts = (
            tuple(list_plaintexts)
            + (blank_plaintext,)
            + tuple(
                preference_plaintexts
            )
        )

        nonces = (
            tuple(list_nonces)
            + (blank_nonce,)
            + tuple(
                preference_nonces
            )
        )

        if not (
            len(ciphertexts)
            == len(plaintexts)
            == len(nonces)
        ):
            return False

        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value not in (0, 1)
            for value in plaintexts
        ):
            return False

        for (
            ciphertext,
            plaintext,
            nonce,
        ) in zip(
            ciphertexts,
            plaintexts,
            nonces,
            strict=True,
        ):
            expected = (
                _encrypt_from_public_data(
                    message=plaintext,
                    nonce=nonce,
                    public_key=public_key,
                    p=p,
                    q=q,
                    g=g,
                )
            )

            if expected != ciphertext:
                return False

    except (
        TypeError,
        ValueError,
    ):
        return False

    return True


def verify_v4_board_rules(
    board: object,
    public_key: int,
    p: int,
    q: int,
    g: int,
) -> bool:
    """
    Verifica le regole pubbliche aggiuntive della bacheca.
    """

    if not isinstance(board, dict):
        return False

    entries = board.get("entries")

    if not isinstance(entries, list):
        return False

    seen_ballots = set()

    for entry in entries:
        if not isinstance(entry, dict):
            return False

        state = entry.get("state")
        ballot = entry.get("ballot")

        try:
            ciphertexts = (
                _ballot_ciphertexts_from_data(
                    ballot
                )
            )
        except ValueError:
            return False

        if ciphertexts in seen_ballots:
            return False

        seen_ballots.add(
            ciphertexts
        )

        if state == "CAST":
            if "revealed_witness" in entry:
                return False

        elif state == "SPOILED":
            if "revealed_witness" not in entry:
                return False

            if not verify_spoiled_witness_from_data(
                ballot=ballot,
                witness=entry[
                    "revealed_witness"
                ],
                public_key=public_key,
                p=p,
                q=q,
                g=g,
            ):
                return False

        else:
            return False

    return True