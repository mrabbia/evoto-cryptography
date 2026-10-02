"""
Test del verificatore indipendente.

Questi test verificano i controlli che non dipendono
dal formato futuro del registro pubblico.
"""

import pytest

from verifica.verifica import (
    hash_to_q,
    is_subgroup_element,
    verify_schnorr_commitment,
    verify_v1_parameters,
    combine_decryption_shares,
    lagrange_coefficient_at_zero,
    verify_chaum_pedersen_share,
    verify_value_set_proof,
    divide_ciphertexts,
    multiply_ciphertexts,
    verify_r2_rule,
    verify_r3_rule,
    verify_r4_rule,
    verify_r5_rule,
    compute_joint_public_key,
    compute_verification_key,
)


P = 467
Q = 233
G = 4

SECRET_KEY = 123
PUBLIC_KEY = pow(
    G,
    SECRET_KEY,
    P,
)


REFERENCE_COMMITMENTS = (
    (
        2228,
        1370,
    ),
    (
        523,
        2277,
    ),
    (
        299,
        1502,
    ),
)


def test_v1_accepts_valid_group_parameters():
    """
    V1 accetta parametri validi e una chiave
    appartenente al sottogruppo.
    """

    assert verify_v1_parameters(
        p=P,
        q=Q,
        g=G,
        public_key=PUBLIC_KEY,
    )


def test_v1_rejects_non_prime_p():
    """
    V1 rifiuta un modulo p non primo.
    """

    assert not verify_v1_parameters(
        p=465,
        q=Q,
        g=G,
        public_key=PUBLIC_KEY,
    )


def test_v1_rejects_non_prime_q():
    """
    V1 rifiuta un ordine q non primo.
    """

    assert not verify_v1_parameters(
        p=P,
        q=232,
        g=G,
        public_key=PUBLIC_KEY,
    )


def test_v1_rejects_q_not_dividing_p_minus_one():
    """
    V1 rifiuta un q che non divide p meno uno.
    """

    assert not verify_v1_parameters(
        p=P,
        q=229,
        g=G,
        public_key=PUBLIC_KEY,
    )


def test_v1_rejects_invalid_generator():
    """
    V1 rifiuta un generatore fuori dal sottogruppo.
    """

    assert not verify_v1_parameters(
        p=P,
        q=Q,
        g=2,
        public_key=PUBLIC_KEY,
    )


def test_v1_rejects_public_key_outside_subgroup():
    """
    V1 rifiuta una chiave pubblica fuori dal sottogruppo.
    """

    assert not verify_v1_parameters(
        p=P,
        q=Q,
        g=G,
        public_key=2,
    )


def test_independent_hash_matches_reference_vector():
    """
    L'hash indipendente deve produrre il valore
    di riferimento fissato nella specifica.
    """

    assert hash_to_q(
        1289,
        2579,
        1289,
        4,
        3,
        2,
        1,
    ) == 889


def test_subgroup_check_accepts_valid_element():
    """
    Un elemento valido del sottogruppo viene accettato.
    """

    assert is_subgroup_element(
        2228,
        2579,
        1289,
    )


def test_subgroup_check_rejects_invalid_element():
    """
    Un elemento esterno al sottogruppo viene rifiutato.
    """

    assert not is_subgroup_element(
        2,
        2579,
        1289,
    )


def test_v2_accepts_reference_schnorr_proof():
    """
    V2 accetta la prova Schnorr numerica
    fissata nella specifica.
    """

    assert verify_schnorr_commitment(
        p=2579,
        q=1289,
        g=4,
        context=889,
        guardian_index=1,
        coefficient_index=0,
        commitment=2228,
        proof_commitment=910,
        challenge=957,
        response=949,
    )


def test_v2_rejects_tampered_schnorr_challenge():
    """
    V2 rifiuta una prova Schnorr con challenge alterata.
    """

    assert not verify_schnorr_commitment(
        p=2579,
        q=1289,
        g=4,
        context=889,
        guardian_index=1,
        coefficient_index=0,
        commitment=2228,
        proof_commitment=910,
        challenge=958,
        response=949,
    )


def test_v2_rejects_tampered_schnorr_response():
    """
    V2 rifiuta una prova Schnorr con risposta alterata.
    """

    assert not verify_schnorr_commitment(
        p=2579,
        q=1289,
        g=4,
        context=889,
        guardian_index=1,
        coefficient_index=0,
        commitment=2228,
        proof_commitment=910,
        challenge=957,
        response=950,
    )


def test_v2_rejects_schnorr_commitment_outside_subgroup():
    """
    V2 rifiuta una prova con un commitment
    esterno al sottogruppo.
    """

    assert not verify_schnorr_commitment(
        p=2579,
        q=1289,
        g=4,
        context=889,
        guardian_index=1,
        coefficient_index=0,
        commitment=2,
        proof_commitment=910,
        challenge=957,
        response=949,
    )


def test_v6_accepts_reference_chaum_pedersen_proof():
    """
    V6 accetta la prova Chaum-Pedersen
    numerica fissata nella specifica.
    """

    assert verify_chaum_pedersen_share(
        p=2579,
        q=1289,
        g=4,
        context=744,
        guardian_index=1,
        verification_key=2502,
        tally_alpha=1196,
        partial_decryption=60,
        commitment_1=910,
        commitment_2=1033,
        challenge=524,
        response=828,
    )


def test_v6_rejects_tampered_chaum_pedersen_challenge():
    """
    V6 rifiuta una prova Chaum-Pedersen
    con challenge alterata.
    """

    assert not verify_chaum_pedersen_share(
        p=2579,
        q=1289,
        g=4,
        context=744,
        guardian_index=1,
        verification_key=2502,
        tally_alpha=1196,
        partial_decryption=60,
        commitment_1=910,
        commitment_2=1033,
        challenge=525,
        response=828,
    )


def test_v6_rejects_tampered_chaum_pedersen_response():
    """
    V6 rifiuta una prova Chaum-Pedersen
    con risposta alterata.
    """

    assert not verify_chaum_pedersen_share(
        p=2579,
        q=1289,
        g=4,
        context=744,
        guardian_index=1,
        verification_key=2502,
        tally_alpha=1196,
        partial_decryption=60,
        commitment_1=910,
        commitment_2=1033,
        challenge=524,
        response=829,
    )


def test_v6_rejects_share_outside_subgroup():
    """
    V6 rifiuta una share di decifratura
    esterna al sottogruppo.
    """

    assert not verify_chaum_pedersen_share(
        p=2579,
        q=1289,
        g=4,
        context=744,
        guardian_index=1,
        verification_key=2502,
        tally_alpha=1196,
        partial_decryption=2,
        commitment_1=910,
        commitment_2=1033,
        challenge=524,
        response=828,
    )


def test_v6_lagrange_coefficients_match_reference_vector():
    """
    I coefficienti di Lagrange devono coincidere
    con il vettore numerico di riferimento.
    """

    indices = (1, 3)

    assert lagrange_coefficient_at_zero(
        guardian_index=1,
        guardian_indices=indices,
        q=1289,
    ) == 646

    assert lagrange_coefficient_at_zero(
        guardian_index=3,
        guardian_indices=indices,
        q=1289,
    ) == 644


def test_v6_lagrange_rejects_duplicate_indices():
    """
    Lagrange rifiuta indici di garanti duplicati.
    """

    with pytest.raises(ValueError):
        lagrange_coefficient_at_zero(
            guardian_index=1,
            guardian_indices=(1, 1),
            q=1289,
        )


def test_v6_lagrange_rejects_non_positive_index():
    """
    Lagrange rifiuta l'indice zero.
    """

    with pytest.raises(ValueError):
        lagrange_coefficient_at_zero(
            guardian_index=1,
            guardian_indices=(0, 1),
            q=1289,
        )


def test_v6_combines_reference_decryption_shares():
    """
    La combinazione delle share deve produrre
    il fattore di decifratura di riferimento.
    """

    combined = combine_decryption_shares(
        shares=(
            (1, 60),
            (3, 1894),
        ),
        p=2579,
        q=1289,
        quorum=2,
    )

    assert combined == 332


def test_v6_combination_is_independent_of_valid_guardian_subset():
    """
    Due sottoinsiemi validi di garanti devono
    ricostruire lo stesso fattore di decifratura.
    """

    first = combine_decryption_shares(
        shares=(
            (1, 60),
            (3, 1894),
        ),
        p=2579,
        q=1289,
        quorum=2,
    )

    second = combine_decryption_shares(
        shares=(
            (1, 60),
            (2, 508),
        ),
        p=2579,
        q=1289,
        quorum=2,
    )

    assert first == 332
    assert second == 332


def test_v6_rejects_decryption_below_quorum():
    """
    V6 rifiuta una decifratura con meno
    share rispetto al quorum richiesto.
    """

    with pytest.raises(ValueError):
        combine_decryption_shares(
            shares=(
                (1, 60),
            ),
            p=2579,
            q=1289,
            quorum=2,
        )


def test_v3_accepts_reference_binary_or_proof():
    """
    V3 accetta una prova OR valida
    per un ciphertext che contiene 1.
    """

    assert verify_value_set_proof(
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        alpha=850,
        beta=2375,
        allowed_values=(0, 1),
        branches=(
            (
                1102,
                1692,
                100,
                200,
            ),
            (
                910,
                1860,
                1081,
                297,
            ),
        ),
    )


def test_v3_rejects_tampered_or_challenge():
    """
    V3 rifiuta una prova OR con una
    challenge parziale alterata.
    """

    assert not verify_value_set_proof(
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        alpha=850,
        beta=2375,
        allowed_values=(0, 1),
        branches=(
            (
                1102,
                1692,
                101,
                200,
            ),
            (
                910,
                1860,
                1081,
                297,
            ),
        ),
    )


def test_v3_rejects_tampered_or_response():
    """
    V3 rifiuta una prova OR con una risposta alterata.
    """

    assert not verify_value_set_proof(
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        alpha=850,
        beta=2375,
        allowed_values=(0, 1),
        branches=(
            (
                1102,
                1692,
                100,
                201,
            ),
            (
                910,
                1860,
                1081,
                297,
            ),
        ),
    )


def test_v3_rejects_wrong_number_of_or_branches():
    """
    V3 rifiuta una prova OR con un numero di rami
    diverso dal numero di valori ammessi.
    """

    assert not verify_value_set_proof(
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        alpha=850,
        beta=2375,
        allowed_values=(0, 1),
        branches=(
            (
                1102,
                1692,
                100,
                200,
            ),
        ),
    )


def test_v3_rejects_ciphertext_outside_subgroup():
    """
    V3 rifiuta un ciphertext con elementi
    esterni al sottogruppo.
    """

    assert not verify_value_set_proof(
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        alpha=2,
        beta=2375,
        allowed_values=(0, 1),
        branches=(
            (
                1102,
                1692,
                100,
                200,
            ),
            (
                910,
                1860,
                1081,
                297,
            ),
        ),
    )


def test_ciphertext_product_matches_reference_tally():
    """
    Il prodotto omomorfico dei ciphertext
    deve coincidere con il tally di riferimento.
    """

    result = multiply_ciphertexts(
        ciphertexts=(
            (850, 2375),
            (380, 22),
            (625, 670),
        ),
        p=2579,
        q=1289,
    )

    assert result == (
        1196,
        154,
    )


def test_ciphertext_division_of_equal_values_gives_identity():
    """
    La divisione di un ciphertext per sé stesso
    deve produrre l'elemento neutro.
    """

    result = divide_ciphertexts(
        numerator=(850, 2375),
        denominator=(850, 2375),
        p=2579,
        q=1289,
    )

    assert result == (
        1,
        1,
    )


def test_ciphertext_division_matches_reference_computation():
    """
    La divisione componente per componente
    deve coincidere con il calcolo modulare atteso.
    """

    result = divide_ciphertexts(
        numerator=(850, 2375),
        denominator=(380, 22),
        p=2579,
        q=1289,
    )

    assert result == (
        1156,
        1163,
    )


def test_ciphertext_operations_reject_elements_outside_subgroup():
    """
    Le operazioni sui ciphertext rifiutano
    elementi esterni al sottogruppo.
    """

    with pytest.raises(ValueError):
        multiply_ciphertexts(
            ciphertexts=(
                (2, 2375),
            ),
            p=2579,
            q=1289,
        )

    with pytest.raises(ValueError):
        divide_ciphertexts(
            numerator=(850, 2375),
            denominator=(2, 22),
            p=2579,
            q=1289,
        )


def _encrypt_for_verifier_test(
    value: int,
    nonce: int,
) -> tuple[int, int]:
    """
    Crea un ciphertext di test senza usare evoto.
    """

    p = 2579
    g = 4
    public_key = 530

    alpha = pow(
        g,
        nonce,
        p,
    )

    beta = (
        pow(
            g,
            value,
            p,
        )
        * pow(
            public_key,
            nonce,
            p,
        )
    ) % p

    return (
        alpha,
        beta,
    )


def _build_value_set_test_proof(
    plaintext: int,
    nonce: int,
    allowed_values: tuple[int, ...],
) -> tuple[
    tuple[int, int],
    tuple[
        tuple[int, int, int, int],
        ...,
    ],
]:
    """
    Costruisce una prova OR deterministica
    usata esclusivamente nei test del verificatore.
    """

    p = 2579
    q = 1289
    g = 4
    public_key = 530
    context = 744

    alpha, beta = _encrypt_for_verifier_test(
        plaintext,
        nonce,
    )

    honest_index = allowed_values.index(
        plaintext
    )

    mutable_branches = []

    for index, allowed_value in enumerate(
        allowed_values
    ):
        if index == honest_index:
            mutable_branches.append(None)
            continue

        challenge = (
            100 + 37 * index
        ) % q

        response = (
            200 + 53 * index
        ) % q

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

        commitment_1 = (
            pow(
                g,
                response,
                p,
            )
            * pow(
                pow(
                    alpha,
                    challenge,
                    p,
                ),
                -1,
                p,
            )
        ) % p

        commitment_2 = (
            pow(
                public_key,
                response,
                p,
            )
            * pow(
                pow(
                    adjusted_beta,
                    challenge,
                    p,
                ),
                -1,
                p,
            )
        ) % p

        mutable_branches.append(
            [
                commitment_1,
                commitment_2,
                challenge,
                response,
            ]
        )

    honest_nonce = 7

    honest_commitment_1 = pow(
        g,
        honest_nonce,
        p,
    )

    honest_commitment_2 = pow(
        public_key,
        honest_nonce,
        p,
    )

    mutable_branches[honest_index] = [
        honest_commitment_1,
        honest_commitment_2,
        0,
        0,
    ]

    hash_values = [
        context,
        alpha,
        beta,
    ]

    for branch in mutable_branches:
        hash_values.extend(
            (
                branch[0],
                branch[1],
            )
        )

    total_challenge = hash_to_q(
        q,
        *hash_values,
    )

    simulated_challenge_sum = sum(
        branch[2]
        for index, branch in enumerate(
            mutable_branches
        )
        if index != honest_index
    ) % q

    honest_challenge = (
        total_challenge
        - simulated_challenge_sum
    ) % q

    honest_response = (
        honest_nonce
        + honest_challenge * nonce
    ) % q

    mutable_branches[honest_index][2] = (
        honest_challenge
    )

    mutable_branches[honest_index][3] = (
        honest_response
    )

    branches = tuple(
        tuple(branch)
        for branch in mutable_branches
    )

    return (
        (alpha, beta),
        branches,
    )


def test_v3_r2_rule_accepts_exactly_one_choice():
    """
    R2 accetta un aggregato che cifra esattamente 1.
    """

    first = _encrypt_for_verifier_test(
        1,
        10,
    )

    second = _encrypt_for_verifier_test(
        0,
        20,
    )

    third = _encrypt_for_verifier_test(
        0,
        30,
    )

    _, branches = _build_value_set_test_proof(
        plaintext=1,
        nonce=60,
        allowed_values=(1,),
    )

    assert verify_r2_rule(
        ciphertexts=(
            first,
            second,
            third,
        ),
        branches=branches,
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
    )


def test_v3_r3_rule_accepts_valid_list_preference_relation():
    """
    R3 accetta una preferenza appartenente
    alla lista selezionata.
    """

    list_ciphertext = (
        _encrypt_for_verifier_test(
            1,
            40,
        )
    )

    preference_ciphertext = (
        _encrypt_for_verifier_test(
            1,
            15,
        )
    )

    _, branches = _build_value_set_test_proof(
        plaintext=0,
        nonce=25,
        allowed_values=(0, 1),
    )

    assert verify_r3_rule(
        list_ciphertext=list_ciphertext,
        preference_ciphertext=(
            preference_ciphertext
        ),
        branches=branches,
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
    )


def test_v3_r4_rule_accepts_three_preferences():
    """
    R4 accetta un totale di tre preferenze.
    """

    ciphertexts = (
        _encrypt_for_verifier_test(1, 10),
        _encrypt_for_verifier_test(1, 20),
        _encrypt_for_verifier_test(1, 30),
        _encrypt_for_verifier_test(0, 40),
    )

    _, branches = _build_value_set_test_proof(
        plaintext=3,
        nonce=100,
        allowed_values=(0, 1, 2, 3),
    )

    assert verify_r4_rule(
        preference_ciphertexts=ciphertexts,
        branches=branches,
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        max_preferences=3,
    )


def test_v3_r5_rule_accepts_two_preferences_same_gender():
    """
    R5 accetta al massimo due preferenze
    dello stesso genere.
    """

    ciphertexts = (
        _encrypt_for_verifier_test(1, 10),
        _encrypt_for_verifier_test(1, 20),
        _encrypt_for_verifier_test(0, 30),
    )

    _, branches = _build_value_set_test_proof(
        plaintext=2,
        nonce=60,
        allowed_values=(0, 1, 2),
    )

    assert verify_r5_rule(
        gender_ciphertexts=ciphertexts,
        branches=branches,
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        max_preferences_per_gender=2,
    )


def test_v3_rule_rejects_proof_for_different_derived_ciphertext():
    """
    Una prova valida per un ciphertext diverso
    non deve verificare sul ciphertext derivato.
    """

    ciphertexts = (
        _encrypt_for_verifier_test(1, 10),
        _encrypt_for_verifier_test(0, 20),
    )

    _, branches = _build_value_set_test_proof(
        plaintext=1,
        nonce=99,
        allowed_values=(1,),
    )

    assert not verify_r2_rule(
        ciphertexts=ciphertexts,
        branches=branches,
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
    )


def test_v2_reconstructs_reference_joint_public_key():
    """
    V2 ricalcola la chiave pubblica congiunta
    dagli impegni costanti dei garanti.
    """

    assert compute_joint_public_key(
        commitment_sets=REFERENCE_COMMITMENTS,
        p=2579,
        q=1289,
    ) == 530


@pytest.mark.parametrize(
    ("guardian_index", "expected_key"),
    [
        (1, 2502),
        (2, 2488),
        (3, 2237),
    ],
)
def test_v6_reconstructs_reference_verification_keys(
    guardian_index,
    expected_key,
):
    """
    V6 ricalcola le chiavi di verifica
    dei garanti dagli impegni pubblici.
    """

    assert compute_verification_key(
        guardian_index=guardian_index,
        commitment_sets=REFERENCE_COMMITMENTS,
        p=2579,
        q=1289,
    ) == expected_key


def test_feldman_helpers_reject_invalid_commitment():
    """
    Le ricostruzioni Feldman rifiutano
    impegni esterni al sottogruppo.
    """

    invalid_commitments = (
        (
            2228,
            1370,
        ),
        (
            523,
            2,
        ),
    )

    with pytest.raises(ValueError):
        compute_verification_key(
            guardian_index=1,
            commitment_sets=invalid_commitments,
            p=2579,
            q=1289,
        )


def test_joint_public_key_rejects_invalid_constant_commitment():
    """
    La chiave congiunta non accetta
    un impegno costante non valido.
    """

    with pytest.raises(ValueError):
        compute_joint_public_key(
            commitment_sets=(
                (2228, 1370),
                (2, 2277),
            ),
            p=2579,
            q=1289,
        )


def test_v3_r4_rule_uses_configured_limit():
    """
    R4 usa il limite massimo configurato.
    """

    ciphertexts = (
        _encrypt_for_verifier_test(1, 10),
        _encrypt_for_verifier_test(1, 20),
        _encrypt_for_verifier_test(0, 30),
    )

    _, branches = _build_value_set_test_proof(
        plaintext=2,
        nonce=60,
        allowed_values=(0, 1, 2),
    )

    assert verify_r4_rule(
        preference_ciphertexts=ciphertexts,
        branches=branches,
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        max_preferences=2,
    )


def test_v3_r5_rule_uses_configured_limit():
    """
    R5 usa il limite per genere configurato.
    """

    ciphertexts = (
        _encrypt_for_verifier_test(1, 10),
        _encrypt_for_verifier_test(0, 20),
    )

    _, branches = _build_value_set_test_proof(
        plaintext=1,
        nonce=30,
        allowed_values=(0, 1),
    )

    assert verify_r5_rule(
        gender_ciphertexts=ciphertexts,
        branches=branches,
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        max_preferences_per_gender=1,
    )


def test_v3_r4_rule_rejects_negative_limit():
    """
    R4 rifiuta un limite negativo.
    """

    assert not verify_r4_rule(
        preference_ciphertexts=(
            _encrypt_for_verifier_test(0, 10),
        ),
        branches=(),
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        max_preferences=-1,
    )


def test_v3_r5_rule_rejects_negative_limit():
    """
    R5 rifiuta un limite per genere negativo.
    """

    assert not verify_r5_rule(
        gender_ciphertexts=(
            _encrypt_for_verifier_test(0, 10),
        ),
        branches=(),
        p=2579,
        q=1289,
        g=4,
        public_key=530,
        context=744,
        max_preferences_per_gender=-1,
    )


def test_hash_rejects_negative_value():
    """
    L'hash canonico rifiuta interi negativi.
    """

    with pytest.raises(ValueError):
        hash_to_q(
            1289,
            -1,
        )


def test_empty_ciphertext_product_gives_identity():
    """
    Il prodotto vuoto dei ciphertext produce l'identità.
    """

    assert multiply_ciphertexts(
        ciphertexts=(),
        p=2579,
        q=1289,
    ) == (
        1,
        1,
    )