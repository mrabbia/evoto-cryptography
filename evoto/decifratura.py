"""
Decifratura a soglia del progetto evoto.

Questo modulo contiene:
- i coefficienti di Lagrange valutati in zero;
- la share di decifratura di un garante, con la sua prova Chaum-Pedersen;
- la verifica di una share di decifratura;
- la combinazione delle share dei garanti presenti;
- la decifratura del tally.

Segue la specifica condivisa docs/spec_f1.md,
in particolare le sezioni 21, 23, 24 e 36.

Non viene mai decifrata una singola scheda: si decifrano soltanto
i totali ottenuti dal conteggio omomorfico.
"""

from dataclasses import dataclass

from evoto.elgamal import (
    Ciphertext,
    bounded_discrete_log,
)
from evoto.gruppo import (
    GroupParameters,
    is_subgroup_element,
    mod_inverse,
    mod_pow,
)
from evoto.prove import (
    ChaumPedersenProof,
    prove_chaum_pedersen,
    verify_chaum_pedersen,
)


@dataclass(frozen=True)
class DecryptionShare:
    """
    Contributo pubblico di un garante alla decifratura di un tally.

    guardian_index: numero del garante.
    partial_decryption: M_l = A^(s_l) mod p.
    proof: prova che log_g(V_l) = log_A(M_l).
    """

    guardian_index: int
    partial_decryption: int
    proof: ChaumPedersenProof


def lagrange_coefficient(
    index: int,
    available_indices: tuple[int, ...],
    params: GroupParameters,
) -> int:
    """
    Calcola il coefficiente di Lagrange del garante index, valutato in zero.

        λ_i = ∏ j / (j - i) mod q      per j in S, j diverso da i

    Serve perché la somma dei λ_i s_i ricostruisce S(0), cioè la chiave
    segreta dell'elezione, senza che nessuno la veda mai.
    """

    if not available_indices:
        raise ValueError("L'insieme dei garanti presenti non può essere vuoto.")

    if len(set(available_indices)) != len(available_indices):
        raise ValueError("Gli indici dei garanti presenti devono essere distinti.")

    if index not in available_indices:
        raise ValueError("Il garante deve appartenere ai garanti presenti.")

    for available in available_indices:
        if available < 1:
            raise ValueError("Gli indici dei garanti devono essere almeno 1.")

    numerator = 1
    denominator = 1

    for available in available_indices:
        if available == index:
            continue

        numerator = (numerator * available) % params.q
        denominator = (denominator * (available - index)) % params.q

    return (
        numerator
        * mod_inverse(denominator, params.q)
    ) % params.q


def compute_decryption_share(
    guardian_index: int,
    secret_share: int,
    tally: Ciphertext,
    params: GroupParameters,
    extended_base_hash: int,
    nonce: int | None = None,
) -> DecryptionShare:
    """
    Calcola il contributo di un garante alla decifratura del tally.

        M_l = A^(s_l) mod p

    La prova Chaum-Pedersen dimostra che lo stesso esponente s_l lega
    la chiave di verifica pubblica V_l = g^(s_l) e la share M_l,
    quindi che il garante ha usato davvero la sua share e non un altro
    valore. Il contesto della prova è (Q_bar, l).

    Il nonce della prova può essere passato esplicitamente nei test.
    """

    if guardian_index < 1:
        raise ValueError("L'indice del garante deve essere almeno 1.")

    if not 0 <= secret_share < params.q:
        raise ValueError("La share deve essere compresa tra 0 e q - 1.")

    if not is_subgroup_element(tally.alpha, params):
        raise ValueError("alpha del tally non appartiene al sottogruppo.")

    if not is_subgroup_element(tally.beta, params):
        raise ValueError("beta del tally non appartiene al sottogruppo.")

    verification_key = mod_pow(params.g, secret_share, params.p)

    partial_decryption = mod_pow(tally.alpha, secret_share, params.p)

    proof = prove_chaum_pedersen(
        secret=secret_share,
        base_1=params.g,
        public_1=verification_key,
        base_2=tally.alpha,
        public_2=partial_decryption,
        params=params,
        context=(extended_base_hash, guardian_index),
        nonce=nonce,
    )

    return DecryptionShare(
        guardian_index=guardian_index,
        partial_decryption=partial_decryption,
        proof=proof,
    )


def verify_decryption_share(
    share: DecryptionShare,
    verification_key: int,
    tally: Ciphertext,
    params: GroupParameters,
    extended_base_hash: int,
) -> bool:
    """
    Verifica il contributo di un garante alla decifratura.

    La chiave di verifica V_l va ricalcolata dagli impegni di Feldman
    con compute_verification_key, non presa dal garante stesso.

    È il controllo V6 del verificatore.
    """

    if share.guardian_index < 1:
        return False

    if not is_subgroup_element(verification_key, params):
        return False

    if not is_subgroup_element(share.partial_decryption, params):
        return False

    if not is_subgroup_element(tally.alpha, params):
        return False

    return verify_chaum_pedersen(
        base_1=params.g,
        public_1=verification_key,
        base_2=tally.alpha,
        public_2=share.partial_decryption,
        proof=share.proof,
        params=params,
        context=(extended_base_hash, share.guardian_index),
    )


def combine_decryption_shares(
    shares: tuple[DecryptionShare, ...],
    quorum: int,
    params: GroupParameters,
) -> int:
    """
    Combina le share dei garanti presenti con i coefficienti di Lagrange.

        M = ∏ M_l^(λ_l) mod p = A^s

    Bastano quorum garanti qualsiasi: chi è assente semplicemente
    non compare nell'insieme S.
    """

    if quorum < 1:
        raise ValueError("Il quorum deve essere almeno 1.")

    if len(shares) < quorum:
        raise ValueError("I garanti presenti sono meno del quorum.")

    available_indices = tuple(
        share.guardian_index
        for share in shares
    )

    if len(set(available_indices)) != len(available_indices):
        raise ValueError("Un garante non può presentare due share.")

    combined = 1

    for share in shares:
        if not is_subgroup_element(share.partial_decryption, params):
            raise ValueError(
                f"La share del garante {share.guardian_index} "
                "non appartiene al sottogruppo."
            )

        coefficient = lagrange_coefficient(
            share.guardian_index,
            available_indices,
            params,
        )

        combined = (
            combined
            * mod_pow(share.partial_decryption, coefficient, params.p)
        ) % params.p

    return combined


def decrypt_tally(
    tally: Ciphertext,
    shares: tuple[DecryptionShare, ...],
    quorum: int,
    params: GroupParameters,
    max_total: int,
) -> int:
    """
    Decifra un tally aggregato a partire dalle share dei garanti.

        B / M = g^t

    Il totale t si ricava con il logaritmo discreto limitato: il valore
    cercato è un conteggio elettorale, quindi non supera il numero di
    schede indicato da max_total.

    Le prove delle share vanno verificate prima di chiamare questa
    funzione, con verify_decryption_share.
    """

    combined = combine_decryption_shares(shares, quorum, params)

    encoded_total = (
        tally.beta
        * mod_inverse(combined, params.p)
    ) % params.p

    total = bounded_discrete_log(
        encoded_total,
        params,
        max_total,
    )

    if total is None:
        raise ValueError(
            "Il totale non è stato trovato entro il limite richiesto."
        )

    return total
