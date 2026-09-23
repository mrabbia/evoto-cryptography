"""
Test unitari per evoto.garanti.

I valori attesi sono quelli dell'esempio numerico della specifica
F1 v0.2, sezione 38: tre garanti con quorum 2 nel gruppo didattico,
i cui polinomi sommati danno S(x) = 765 + 100x.
"""

import pytest

from evoto.garanti import (
    GuardianRecord,
    aggregate_shares,
    compute_base_hash,
    compute_commitments,
    compute_extended_base_hash,
    compute_joint_public_key,
    compute_share,
    compute_verification_key,
    create_guardian,
    create_guardian_record,
    evaluate_polynomial,
    run_key_ceremony,
    verify_guardian_record,
    verify_share,
)
from evoto.gruppo import TEST_PARAMS, mod_pow


# Polinomi dell'esempio della specifica.
REFERENCE_COEFFICIENTS = (
    (300, 40),
    (400, 50),
    (65, 10),
)

REFERENCE_GUARDIAN_COUNT = 3
REFERENCE_QUORUM = 2
REFERENCE_ELECTION_ID = 1

# Contesti attesi.
REFERENCE_BASE_HASH = 889
REFERENCE_EXTENDED_BASE_HASH = 744

# Impegni di Feldman attesi.
REFERENCE_COMMITMENTS = (
    (2228, 1370),
    (523, 2277),
    (299, 1502),
)

# Share aggregate e chiavi di verifica attese.
REFERENCE_SECRET_SHARES = {
    1: 865,
    2: 965,
    3: 1065,
}

REFERENCE_VERIFICATION_KEYS = {
    1: 2502,
    2: 2488,
    3: 2237,
}

REFERENCE_JOINT_PUBLIC_KEY = 530


def reference_guardians():
    """
    Costruisce i tre garanti dell'esempio della specifica.
    """

    return tuple(
        create_guardian(
            index=index,
            quorum=REFERENCE_QUORUM,
            params=TEST_PARAMS,
            coefficients=REFERENCE_COEFFICIENTS[index - 1],
        )
        for index in (1, 2, 3)
    )


def reference_records():
    """
    Costruisce le parti pubbliche dei tre garanti dell'esempio.
    """

    return tuple(
        create_guardian_record(
            guardian,
            TEST_PARAMS,
            REFERENCE_BASE_HASH,
        )
        for guardian in reference_guardians()
    )


def test_base_hash_reference_vector():
    """
    Il contesto della cerimonia è H(p, q, g, n, k, e).
    """

    base_hash = compute_base_hash(
        TEST_PARAMS,
        REFERENCE_GUARDIAN_COUNT,
        REFERENCE_QUORUM,
        REFERENCE_ELECTION_ID,
    )

    assert base_hash == REFERENCE_BASE_HASH


def test_extended_base_hash_reference_vector():
    """
    Il contesto esteso H(Q, K) lega le prove alla chiave dell'elezione.
    """

    extended = compute_extended_base_hash(
        REFERENCE_BASE_HASH,
        REFERENCE_JOINT_PUBLIC_KEY,
        TEST_PARAMS,
    )

    assert extended == REFERENCE_EXTENDED_BASE_HASH


def test_base_hash_rejects_quorum_greater_than_guardians():
    """
    Il quorum non può superare il numero di garanti.
    """

    with pytest.raises(ValueError):
        compute_base_hash(TEST_PARAMS, 3, 4, 1)


def test_evaluate_polynomial_reference_vector():
    """
    Le share del primo garante dell'esempio sono 340, 380 e 420.
    """

    coefficients = REFERENCE_COEFFICIENTS[0]

    shares = tuple(
        evaluate_polynomial(coefficients, point, TEST_PARAMS)
        for point in (1, 2, 3)
    )

    assert shares == (340, 380, 420)


def test_evaluate_polynomial_at_zero_is_the_secret():
    """
    P_i(0) è il contributo segreto del garante.

    È il motivo per cui i garanti sono numerati a partire da 1.
    """

    secret = evaluate_polynomial(
        REFERENCE_COEFFICIENTS[0],
        0,
        TEST_PARAMS,
    )

    assert secret == 300


def test_create_guardian_rejects_wrong_number_of_coefficients():
    """
    Il polinomio deve avere esattamente quorum coefficienti.
    """

    with pytest.raises(ValueError):
        create_guardian(
            index=1,
            quorum=3,
            params=TEST_PARAMS,
            coefficients=(300, 40),
        )


def test_create_guardian_rejects_index_zero():
    """
    L'indice 0 non è ammesso perché corrisponde al segreto.
    """

    with pytest.raises(ValueError):
        create_guardian(
            index=0,
            quorum=2,
            params=TEST_PARAMS,
            coefficients=(300, 40),
        )


def test_create_guardian_generates_coefficients_in_range():
    """
    Senza coefficienti espliciti il polinomio viene generato a caso.
    """

    guardian = create_guardian(
        index=1,
        quorum=3,
        params=TEST_PARAMS,
    )

    assert len(guardian.coefficients) == 3

    for coefficient in guardian.coefficients:
        assert 0 <= coefficient < TEST_PARAMS.q


def test_commitments_reference_vector():
    """
    Gli impegni di Feldman dei tre garanti dell'esempio.
    """

    commitments = tuple(
        compute_commitments(guardian, TEST_PARAMS)
        for guardian in reference_guardians()
    )

    assert commitments == REFERENCE_COMMITMENTS


def test_guardian_record_is_valid():
    """
    Ogni impegno è accompagnato da una prova di Schnorr valida.
    """

    for record in reference_records():
        assert verify_guardian_record(
            record,
            REFERENCE_QUORUM,
            TEST_PARAMS,
            REFERENCE_BASE_HASH,
        )


def test_guardian_record_rejects_wrong_quorum():
    """
    Il numero di impegni deve coincidere con il quorum dichiarato.
    """

    record = reference_records()[0]

    assert not verify_guardian_record(
        record,
        3,
        TEST_PARAMS,
        REFERENCE_BASE_HASH,
    )


def test_guardian_record_rejects_wrong_base_hash():
    """
    Le prove sono legate al contesto dell'elezione.

    Con un altro Q la challenge non coincide più.
    """

    record = reference_records()[0]

    assert not verify_guardian_record(
        record,
        REFERENCE_QUORUM,
        TEST_PARAMS,
        REFERENCE_BASE_HASH + 1,
    )


def test_guardian_record_rejects_tampered_commitment():
    """
    Se un impegno viene sostituito, la prova non regge più.
    """

    record = reference_records()[0]

    tampered_record = GuardianRecord(
        index=record.index,
        commitments=(530, record.commitments[1]),
        proofs=record.proofs,
    )

    assert not verify_guardian_record(
        tampered_record,
        REFERENCE_QUORUM,
        TEST_PARAMS,
        REFERENCE_BASE_HASH,
    )


def test_share_is_accepted_by_feldman():
    """
    Una share corretta supera la verifica con gli impegni del mittente.
    """

    guardians = reference_guardians()
    records = reference_records()

    for guardian, record in zip(guardians, records, strict=True):
        for recipient in (1, 2, 3):
            share = compute_share(guardian, recipient, TEST_PARAMS)

            assert verify_share(
                share,
                recipient,
                record,
                TEST_PARAMS,
            )


def test_tampered_share_is_rejected():
    """
    Una share alterata di una sola unità viene rifiutata.
    """

    guardian = reference_guardians()[0]
    record = reference_records()[0]

    share = compute_share(guardian, 1, TEST_PARAMS)

    assert not verify_share(
        share + 1,
        1,
        record,
        TEST_PARAMS,
    )


def test_share_of_another_guardian_is_rejected():
    """
    Una share va controllata con gli impegni di chi l'ha inviata.

    La share del garante 2 non supera la verifica con gli impegni
    del garante 1.
    """

    guardians = reference_guardians()
    records = reference_records()

    share = compute_share(guardians[1], 1, TEST_PARAMS)

    assert not verify_share(
        share,
        1,
        records[0],
        TEST_PARAMS,
    )


def test_aggregate_shares_reference_vector():
    """
    Il garante 1 riceve 340, 450 e 75: la sua share aggregata è 865.
    """

    aggregated = aggregate_shares(
        (340, 450, 75),
        TEST_PARAMS,
    )

    assert aggregated == REFERENCE_SECRET_SHARES[1]


def test_joint_public_key_reference_vector():
    """
    La chiave pubblica è il prodotto dei termini noti impegnati.

    Corrisponde a g^765, cioè 530 nel gruppo didattico.
    """

    joint_public_key = compute_joint_public_key(
        reference_records(),
        TEST_PARAMS,
    )

    assert joint_public_key == REFERENCE_JOINT_PUBLIC_KEY


def test_verification_key_reference_vector():
    """
    Le chiavi di verifica si ricalcolano dai soli impegni pubblici.
    """

    records = reference_records()

    for index, expected in REFERENCE_VERIFICATION_KEYS.items():
        assert compute_verification_key(
            index,
            records,
            TEST_PARAMS,
        ) == expected


def test_key_ceremony_reference_vector():
    """
    La cerimonia completa riproduce tutti i valori della sezione 38.
    """

    ceremony = run_key_ceremony(
        guardian_count=REFERENCE_GUARDIAN_COUNT,
        quorum=REFERENCE_QUORUM,
        params=TEST_PARAMS,
        election_id=REFERENCE_ELECTION_ID,
        coefficients=REFERENCE_COEFFICIENTS,
    )

    assert ceremony.base_hash == REFERENCE_BASE_HASH
    assert ceremony.extended_base_hash == REFERENCE_EXTENDED_BASE_HASH
    assert ceremony.joint_public_key == REFERENCE_JOINT_PUBLIC_KEY
    assert ceremony.secret_shares == REFERENCE_SECRET_SHARES

    commitments = tuple(
        record.commitments
        for record in ceremony.records
    )

    assert commitments == REFERENCE_COMMITMENTS


def test_key_ceremony_with_random_polynomials():
    """
    Con polinomi casuali devono comunque valere le proprietà attese:

    - ogni parte pubblica è valida;
    - la chiave di verifica di ogni garante è g^(s_l);
    - la chiave pubblica appartiene al sottogruppo.

    La seconda proprietà è quella che permette al verificatore di
    controllare le share di decifratura senza conoscere i segreti.
    """

    ceremony = run_key_ceremony(
        guardian_count=5,
        quorum=3,
        params=TEST_PARAMS,
        election_id=7,
    )

    for record in ceremony.records:
        assert verify_guardian_record(
            record,
            3,
            TEST_PARAMS,
            ceremony.base_hash,
        )

    for index, secret_share in ceremony.secret_shares.items():
        expected = mod_pow(
            TEST_PARAMS.g,
            secret_share,
            TEST_PARAMS.p,
        )

        assert compute_verification_key(
            index,
            ceremony.records,
            TEST_PARAMS,
        ) == expected


def test_key_ceremony_rejects_quorum_greater_than_guardians():
    """
    Non si può chiedere un quorum superiore al numero di garanti.
    """

    with pytest.raises(ValueError):
        run_key_ceremony(
            guardian_count=3,
            quorum=4,
            params=TEST_PARAMS,
            election_id=1,
        )


def test_key_ceremony_rejects_wrong_number_of_polynomials():
    """
    Serve un polinomio per ogni garante.
    """

    with pytest.raises(ValueError):
        run_key_ceremony(
            guardian_count=3,
            quorum=2,
            params=TEST_PARAMS,
            election_id=1,
            coefficients=((300, 40), (400, 50)),
        )
