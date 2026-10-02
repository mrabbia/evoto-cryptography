"""
Test del verificatore indipendente.

I controlli vengono verificati senza utilizzare
le implementazioni della libreria evoto.
"""

import pytest
import json

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
    compute_ballot_hash_from_data,
    parse_public_registry,
    verify_v4_board_chain,
    verify_v5_tallies,
    verify_v7_results,
    recompute_v8_scrutiny,
    verify_v8_scrutiny,
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


def _minimal_registry_data() -> dict[str, object]:
    """
    Costruisce un registro minimo valido per testare il parser.
    """

    return {
        "configuration": {},
        "group": {},
        "election_context": {},
        "guardians": [],
        "K": 1,
        "bulletin_board": {},
        "district_tallies": [],
        "district_results": [],
        "scrutiny": {},
    }


def test_registry_parser_accepts_complete_json():
    """
    Il parser accetta un registro con tutte le sezioni richieste.
    """

    data = _minimal_registry_data()

    parsed = parse_public_registry(
        json.dumps(data)
    )

    assert parsed == data


def test_registry_parser_rejects_invalid_json():
    """
    Il parser rifiuta un documento che non contiene JSON valido.
    """

    with pytest.raises(ValueError):
        parse_public_registry(
            "{registro non valido"
        )


def test_registry_parser_rejects_missing_section():
    """
    Il parser rifiuta un registro privo di una sezione obbligatoria.
    """

    data = _minimal_registry_data()

    del data["bulletin_board"]

    with pytest.raises(ValueError):
        parse_public_registry(
            json.dumps(data)
        )


def _v4_test_ballot() -> dict[str, object]:
    """
    Costruisce una scheda pubblica minima per i test V4.
    """

    return {
        "list_ciphertexts": [
            {
                "alpha": 4,
                "beta": 16,
            },
            {
                "alpha": 16,
                "beta": 64,
            },
        ],
        "blank_ciphertext": {
            "alpha": 64,
            "beta": 256,
        },
        "preference_ciphertexts": [
            {
                "alpha": 256,
                "beta": 90,
            },
        ],
    }


def _v4_test_board() -> dict[str, object]:
    """
    Costruisce una piccola catena V4 corretta.
    """

    q = 1289
    q_bar = 744

    genesis = hash_to_q(
        q,
        q_bar,
    )

    first_ballot = _v4_test_ballot()

    first_hash = compute_ballot_hash_from_data(
        ballot=first_ballot,
        district_index=0,
        extended_base_hash=q_bar,
        q=q,
    )

    first_code = hash_to_q(
        q,
        genesis,
        1,
        1,
        first_hash,
    )

    second_ballot = {
        "list_ciphertexts": [
            {
                "alpha": 1024,
                "beta": 742,
            },
            {
                "alpha": 742,
                "beta": 389,
            },
        ],
        "blank_ciphertext": {
            "alpha": 389,
            "beta": 1556,
        },
        "preference_ciphertexts": [
            {
                "alpha": 1556,
                "beta": 1066,
            },
        ],
    }

    second_hash = compute_ballot_hash_from_data(
        ballot=second_ballot,
        district_index=1,
        extended_base_hash=q_bar,
        q=q,
    )

    second_code = hash_to_q(
        q,
        first_code,
        2,
        2,
        second_hash,
    )

    return {
        "extended_base_hash": q_bar,
        "genesis_code": genesis,
        "entries": [
            {
                "sequence": 1,
                "district_index": 0,
                "state": "CAST",
                "ballot": first_ballot,
                "proofs": {},
                "ballot_hash": first_hash,
                "tracking_code": first_code,
            },
            {
                "sequence": 2,
                "district_index": 1,
                "state": "SPOILED",
                "ballot": second_ballot,
                "proofs": {},
                "ballot_hash": second_hash,
                "tracking_code": second_code,
                "revealed_witness": {},
            },
        ],
    }


def test_v4_accepts_valid_board_chain():
    """
    V4 accetta una bacheca con catena corretta.
    """

    assert verify_v4_board_chain(
        board=_v4_test_board(),
        q=1289,
    )


def test_v4_rejects_modified_ballot():
    """
    V4 rileva una scheda modificata dopo la pubblicazione.
    """

    board = _v4_test_board()

    board["entries"][0]["ballot"][
        "blank_ciphertext"
    ]["beta"] += 1

    assert not verify_v4_board_chain(
        board=board,
        q=1289,
    )


def test_v4_rejects_modified_tracking_code():
    """
    V4 rileva una modifica alla catena dei tracking code.
    """

    board = _v4_test_board()

    board["entries"][0]["tracking_code"] += 1

    assert not verify_v4_board_chain(
        board=board,
        q=1289,
    )


def test_v4_rejects_reordered_sequences():
    """
    V4 richiede sequenze consecutive a partire da uno.
    """

    board = _v4_test_board()

    board["entries"][1]["sequence"] = 3

    assert not verify_v4_board_chain(
        board=board,
        q=1289,
    )


def test_v4_rejects_cast_witness():
    """
    V4 rifiuta una scheda CAST che rivela il witness.
    """

    board = _v4_test_board()

    board["entries"][0]["revealed_witness"] = {
        "list_plaintexts": [1],
    }

    assert not verify_v4_board_chain(
        board=board,
        q=1289,
    )


def test_v4_rejects_spoiled_without_witness():
    """
    V4 rifiuta una scheda SPOILED senza dati rivelati.
    """

    board = _v4_test_board()

    del board["entries"][1]["revealed_witness"]

    assert not verify_v4_board_chain(
        board=board,
        q=1289,
    )


def _v5_configuration() -> dict[str, object]:
    """
    Costruisce una configurazione minima con due circoscrizioni.
    """

    return {
        "lists": [
            {
                "name": "Lista A",
                "coalition": None,
            },
            {
                "name": "Lista B",
                "coalition": None,
            },
        ],
        "districts": [
            {
                "name": "Nord",
                "candidates": {
                    "Lista A": [
                        {
                            "name": "A0",
                            "gender": "M",
                        },
                        {
                            "name": "A1",
                            "gender": "F",
                        },
                    ],
                    "Lista B": [
                        {
                            "name": "B0",
                            "gender": "F",
                        },
                    ],
                },
            },
            {
                "name": "Sud",
                "candidates": {
                    "Lista A": [
                        {
                            "name": "A0",
                            "gender": "M",
                        },
                        {
                            "name": "A1",
                            "gender": "F",
                        },
                    ],
                    "Lista B": [
                        {
                            "name": "B0",
                            "gender": "F",
                        },
                    ],
                },
            },
        ],
    }


def _v5_board_and_tallies() -> tuple[
    dict[str, object],
    list[dict[str, object]],
]:
    """
    Costruisce bacheca e tally coerenti per i test V5.
    """

    p = 2579
    q = 1289

    first_list = _encrypt_for_verifier_test(
        1,
        10,
    )
    second_list = _encrypt_for_verifier_test(
        0,
        20,
    )
    blank = _encrypt_for_verifier_test(
        0,
        30,
    )
    preference = _encrypt_for_verifier_test(
        1,
        40,
    )

    spoiled_list = _encrypt_for_verifier_test(
        0,
        50,
    )

    board = {
        "entries": [
            {
                "sequence": 1,
                "district_index": 0,
                "state": "CAST",
                "ballot": {
                    "list_ciphertexts": [
                        {
                            "alpha": first_list[0],
                            "beta": first_list[1],
                        },
                        {
                            "alpha": second_list[0],
                            "beta": second_list[1],
                        },
                    ],
                    "blank_ciphertext": {
                        "alpha": blank[0],
                        "beta": blank[1],
                    },
                    "preference_ciphertexts": [
                        {
                            "alpha": preference[0],
                            "beta": preference[1],
                        },
                    ],
                },
            },
            {
                "sequence": 2,
                "district_index": 0,
                "state": "SPOILED",
                "ballot": {
                    "list_ciphertexts": [
                        {
                            "alpha": spoiled_list[0],
                            "beta": spoiled_list[1],
                        },
                        {
                            "alpha": spoiled_list[0],
                            "beta": spoiled_list[1],
                        },
                    ],
                    "blank_ciphertext": {
                        "alpha": spoiled_list[0],
                        "beta": spoiled_list[1],
                    },
                    "preference_ciphertexts": [
                        {
                            "alpha": spoiled_list[0],
                            "beta": spoiled_list[1],
                        },
                    ],
                },
            },
        ],
    }

    tallies = [
        {
            "district_index": 0,
            "ballot_count": 1,
            "list_tallies": [
                {
                    "alpha": first_list[0],
                    "beta": first_list[1],
                },
                {
                    "alpha": second_list[0],
                    "beta": second_list[1],
                },
            ],
            "blank_tally": {
                "alpha": blank[0],
                "beta": blank[1],
            },
            "preference_tallies": [
                {
                    "alpha": preference[0],
                    "beta": preference[1],
                },
            ],
        },
        {
            "district_index": 1,
            "ballot_count": 0,
            "list_tallies": [
                {
                    "alpha": 1,
                    "beta": 1,
                },
                {
                    "alpha": 1,
                    "beta": 1,
                },
            ],
            "blank_tally": {
                "alpha": 1,
                "beta": 1,
            },
            "preference_tallies": [
                {
                    "alpha": 1,
                    "beta": 1,
                },
            ],
        },
    ]

    return (
        board,
        tallies,
    )


def test_v5_accepts_correct_tallies():
    """
    V5 accetta tally ricalcolati dalle sole schede CAST.
    """

    board, tallies = _v5_board_and_tallies()

    assert verify_v5_tallies(
        configuration=_v5_configuration(),
        board=board,
        published_tallies=tallies,
        p=2579,
        q=1289,
    )


def test_v5_ignores_spoiled_ballots():
    """
    V5 non include le schede SPOILED nel conteggio.
    """

    board, tallies = _v5_board_and_tallies()

    spoiled = board["entries"][1]["ballot"]

    spoiled["list_ciphertexts"][0][
        "alpha"
    ] = 1

    spoiled["list_ciphertexts"][0][
        "beta"
    ] = 1

    assert verify_v5_tallies(
        configuration=_v5_configuration(),
        board=board,
        published_tallies=tallies,
        p=2579,
        q=1289,
    )


def test_v5_rejects_modified_encrypted_tally():
    """
    V5 rileva la modifica di un tally cifrato pubblicato.
    """

    board, tallies = _v5_board_and_tallies()

    tallies[0]["list_tallies"][0][
        "beta"
    ] = 1

    assert not verify_v5_tallies(
        configuration=_v5_configuration(),
        board=board,
        published_tallies=tallies,
        p=2579,
        q=1289,
    )


def test_v5_rejects_wrong_ballot_count():
    """
    V5 ricalcola autonomamente il numero di schede CAST.
    """

    board, tallies = _v5_board_and_tallies()

    tallies[0]["ballot_count"] = 2

    assert not verify_v5_tallies(
        configuration=_v5_configuration(),
        board=board,
        published_tallies=tallies,
        p=2579,
        q=1289,
    )


def test_v5_accepts_empty_district_identity_tally():
    """
    V5 verifica correttamente una circoscrizione senza voti.
    """

    board, tallies = _v5_board_and_tallies()

    assert tallies[1]["ballot_count"] == 0

    assert tallies[1]["blank_tally"] == {
        "alpha": 1,
        "beta": 1,
    }

    assert verify_v5_tallies(
        configuration=_v5_configuration(),
        board=board,
        published_tallies=tallies,
        p=2579,
        q=1289,
    )


def _v7_tallies_and_results() -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
]:
    """
    Costruisce un totale decifrabile con una share.
    """

    p = 2579
    g = 4

    secret = 123
    nonce = 17
    clear_total = 3

    public_key = pow(
        g,
        secret,
        p,
    )

    alpha = pow(
        g,
        nonce,
        p,
    )

    beta = (
        pow(
            g,
            clear_total,
            p,
        )
        * pow(
            public_key,
            nonce,
            p,
        )
    ) % p

    partial_decryption = pow(
        alpha,
        secret,
        p,
    )

    tallies = [
        {
            "district_index": 0,
            "ballot_count": 5,
            "list_tallies": [
                {
                    "alpha": alpha,
                    "beta": beta,
                },
            ],
            "blank_tally": {
                "alpha": 1,
                "beta": 1,
            },
            "preference_tallies": [],
        },
    ]

    results = [
        {
            "district_index": 0,
            "ballot_count": 5,
            "list_votes": [
                clear_total,
            ],
            "blank_votes": 0,
            "preference_votes": [],
            "decryption_shares": [
                [
                    {
                        "guardian_index": 1,
                        "partial_decryption":
                            partial_decryption,
                        "proof": {},
                    },
                ],
                [
                    {
                        "guardian_index": 1,
                        "partial_decryption": 1,
                        "proof": {},
                    },
                ],
            ],
        },
    ]

    return (
        tallies,
        results,
    )


def test_v7_accepts_correct_decrypted_totals():
    """
    V7 accetta un totale coerente con le share pubblicate.
    """

    tallies, results = (
        _v7_tallies_and_results()
    )

    assert verify_v7_results(
        published_tallies=tallies,
        district_results=results,
        p=2579,
        q=1289,
        g=4,
        quorum=1,
    )


def test_v7_rejects_modified_clear_total():
    """
    V7 rileva la modifica del totale in chiaro.
    """

    tallies, results = (
        _v7_tallies_and_results()
    )

    results[0]["list_votes"][0] = 4

    assert not verify_v7_results(
        published_tallies=tallies,
        district_results=results,
        p=2579,
        q=1289,
        g=4,
        quorum=1,
    )


def test_v7_rejects_modified_decryption_share():
    """
    V7 rileva una share che produce una decifratura diversa.
    """

    tallies, results = (
        _v7_tallies_and_results()
    )

    results[0]["decryption_shares"][0][0][
        "partial_decryption"
    ] = 1

    assert not verify_v7_results(
        published_tallies=tallies,
        district_results=results,
        p=2579,
        q=1289,
        g=4,
        quorum=1,
    )


def test_v7_rejects_missing_share_set():
    """
    V7 richiede un insieme di share per ogni totale.
    """

    tallies, results = (
        _v7_tallies_and_results()
    )

    results[0]["decryption_shares"].pop()

    assert not verify_v7_results(
        published_tallies=tallies,
        district_results=results,
        p=2579,
        q=1289,
        g=4,
        quorum=1,
    )


def test_v7_rejects_different_ballot_count():
    """
    V7 richiede lo stesso ballot_count tra tally e risultato.
    """

    tallies, results = (
        _v7_tallies_and_results()
    )

    results[0]["ballot_count"] = 4

    assert not verify_v7_results(
        published_tallies=tallies,
        district_results=results,
        p=2579,
        q=1289,
        g=4,
        quorum=1,
    )


def _v8_test_data() -> tuple[
    dict[str, object],
    list[dict[str, object]],
]:
    """
    Costruisce un piccolo scrutinio deterministico.
    """

    configuration = {
        "name": "Elezione V8",
        "election_id": 1,
        "seats": 3,
        "rules": {
            "max_preferences": 1,
            "max_preferences_per_gender": 1,
            "list_threshold_percent": 0,
            "coalition_threshold_percent": 0,
            "bonus_threshold_percent": 100,
            "bonus_seats_percent": 60,
        },
        "lists": [
            {
                "name": "Lista A",
                "coalition": None,
            },
            {
                "name": "Lista B",
                "coalition": None,
            },
        ],
        "districts": [
            {
                "name": "Nord",
                "candidates": {
                    "Lista A": [
                        {
                            "name": "A0",
                            "gender": "M",
                        },
                        {
                            "name": "A1",
                            "gender": "F",
                        },
                    ],
                    "Lista B": [
                        {
                            "name": "B0",
                            "gender": "F",
                        },
                        {
                            "name": "B1",
                            "gender": "M",
                        },
                    ],
                },
            },
            {
                "name": "Sud",
                "candidates": {
                    "Lista A": [
                        {
                            "name": "A2",
                            "gender": "F",
                        },
                        {
                            "name": "A3",
                            "gender": "M",
                        },
                    ],
                    "Lista B": [
                        {
                            "name": "B2",
                            "gender": "M",
                        },
                        {
                            "name": "B3",
                            "gender": "F",
                        },
                    ],
                },
            },
        ],
    }

    results = [
        {
            "district_index": 0,
            "ballot_count": 6,
            "list_votes": [
                4,
                2,
            ],
            "blank_votes": 0,
            "preference_votes": [
                3,
                1,
            ],
            "decryption_shares": [],
        },
        {
            "district_index": 1,
            "ballot_count": 4,
            "list_votes": [
                2,
                2,
            ],
            "blank_votes": 0,
            "preference_votes": [
                1,
                2,
            ],
            "decryption_shares": [],
        },
    ]

    return (
        configuration,
        results,
    )


def test_v8_recomputes_complete_scrutiny():
    """
    V8 ricostruisce voti, seggi ed eletti.
    """

    configuration, results = (
        _v8_test_data()
    )

    scrutiny = recompute_v8_scrutiny(
        configuration=configuration,
        district_results=results,
    )

    assert scrutiny[
        "valid_votes"
    ] == 10

    assert scrutiny[
        "list_votes"
    ] == [
        6,
        4,
    ]

    assert sum(
        scrutiny["list_seats"]
    ) == 3

    assert len(
        scrutiny["elected"]
    ) == 3


def test_v8_accepts_matching_published_scrutiny():
    """
    V8 accetta lo scrutinio pubblico corretto.
    """

    configuration, results = (
        _v8_test_data()
    )

    published = (
        recompute_v8_scrutiny(
            configuration,
            results,
        )
    )

    assert verify_v8_scrutiny(
        configuration=configuration,
        district_results=results,
        published_scrutiny=published,
    )


def test_v8_rejects_modified_list_seats():
    """
    V8 rileva una modifica ai seggi di lista.
    """

    configuration, results = (
        _v8_test_data()
    )

    published = (
        recompute_v8_scrutiny(
            configuration,
            results,
        )
    )

    published["list_seats"][0] += 1

    assert not verify_v8_scrutiny(
        configuration=configuration,
        district_results=results,
        published_scrutiny=published,
    )


def test_v8_rejects_modified_elected_candidate():
    """
    V8 rileva la modifica di un candidato eletto.
    """

    configuration, results = (
        _v8_test_data()
    )

    published = (
        recompute_v8_scrutiny(
            configuration,
            results,
        )
    )

    published["elected"][0][
        "name"
    ] = "Candidato falso"

    assert not verify_v8_scrutiny(
        configuration=configuration,
        district_results=results,
        published_scrutiny=published,
    )


def test_v8_rejects_modified_clear_votes():
    """
    V8 cambia risultato se vengono alterati i voti pubblici.
    """

    configuration, results = (
        _v8_test_data()
    )

    published = (
        recompute_v8_scrutiny(
            configuration,
            results,
        )
    )

    results[0]["list_votes"][0] += 1

    assert not verify_v8_scrutiny(
        configuration=configuration,
        district_results=results,
        published_scrutiny=published,
    )