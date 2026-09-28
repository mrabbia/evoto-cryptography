"""
Verificatore indipendente del progetto evoto.

Questo modulo non importa la libreria evoto.
I controlli vengono ricostruiti in modo indipendente
a partire dai dati pubblici dell'elezione.
"""

import gmpy2
import hashlib


def _to_hex(value: int) -> str:
    """
    Converte un intero nel formato esadecimale canonico.

    Usa lettere maiuscole e una lunghezza pari.
    """

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

    return pow(value, q, p) == 1


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

            exponent = pow(
                guardian_index,
                coefficient_index,
                q,
            )

            guardian_product = (
                guardian_product
                * pow(
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
    """

    if not ciphertexts:
        raise ValueError(
            "È richiesto almeno un ciphertext."
        )

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
) -> bool:
    """
    Verifica R4.

    La somma delle preferenze deve appartenere
    a {0, 1, 2, 3}.
    """

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
        allowed_values=(0, 1, 2, 3),
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
) -> bool:
    """
    Verifica R5 per un singolo genere.

    La somma delle preferenze deve appartenere
    a {0, 1, 2}.
    """

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
        allowed_values=(0, 1, 2),
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

    left = pow(
        g,
        response,
        p,
    )

    right = (
        proof_commitment
        * pow(
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

    first_left = pow(
        g,
        response,
        p,
    )

    first_right = (
        commitment_1
        * pow(
            verification_key,
            challenge,
            p,
        )
    ) % p

    if first_left != first_right:
        return False

    second_left = pow(
        tally_alpha,
        response,
        p,
    )

    second_right = (
        commitment_2
        * pow(
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

        first_left = pow(
            g,
            response,
            p,
        )

        first_right = (
            commitment_1
            * pow(
                alpha,
                challenge,
                p,
            )
        ) % p

        if first_left != first_right:
            return False

        encoded_value = pow(
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

        second_left = pow(
            public_key,
            response,
            p,
        )

        second_right = (
            commitment_2
            * pow(
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
            * pow(
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

    if pow(g, q, p) != 1:
        return False

    if pow(public_key, q, p) != 1:
        return False

    return True