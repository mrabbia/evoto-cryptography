"""
Test del modello della scheda politica.

In questo primo blocco verifichiamo la regola R1:
ogni casella della scheda deve contenere un bit 0 oppure 1.
"""

import pytest

from evoto.elgamal import (
    encrypt,
    public_key_from_secret,
)
from evoto.gruppo import TEST_PARAMS
from evoto.scheda import (
    prove_r1,
    verify_r1,
    prove_r2,
    verify_r2,
    prove_r3,
    verify_r3,
    prove_r4,
    verify_r4,
    prove_r5,
    verify_r5,
)


PUBLIC_KEY = public_key_from_secret(
    123,
    TEST_PARAMS,
)

CONTEXT = 744


@pytest.mark.parametrize("value", [0, 1])
def test_r1_accepts_binary_value(value):
    """R1 deve accettare sia 0 sia 1."""

    nonce = 50 + value

    ciphertext = encrypt(
        value,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=nonce,
    )

    proof = prove_r1(
        ciphertext=ciphertext,
        plaintext=value,
        nonce=nonce,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r1(
        ciphertext=ciphertext,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_r1_rejects_non_binary_plaintext():
    """R1 non deve permettere di provare il valore 2."""

    ciphertext = encrypt(
        2,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=52,
    )

    with pytest.raises(ValueError):
        prove_r1(
            ciphertext=ciphertext,
            plaintext=2,
            nonce=52,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r2_accepts_exactly_one_choice():
    """R2 accetta una sola scelta tra liste e scheda bianca."""

    plaintexts = (0, 1, 0)
    nonces = (10, 20, 30)

    ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(plaintexts, nonces)
    )

    proof = prove_r2(
        ciphertexts=ciphertexts,
        plaintexts=plaintexts,
        nonces=nonces,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r2(
        ciphertexts=ciphertexts,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


@pytest.mark.parametrize(
    "plaintexts",
    [
        (0, 0, 0),
        (1, 1, 0),
    ],
)
def test_r2_rejects_invalid_number_of_choices(plaintexts):
    """R2 rifiuta zero scelte o più di una scelta."""

    nonces = (10, 20, 30)

    ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(plaintexts, nonces)
    )

    with pytest.raises(ValueError):
        prove_r2(
            ciphertexts=ciphertexts,
            plaintexts=plaintexts,
            nonces=nonces,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r2_accepts_zero_derived_nonce():
    """
    R2 deve accettare una randomness aggregata uguale a 0 modulo q.
    """

    plaintexts = (1, 0)
    nonces = (600, 689)

    assert sum(nonces) % TEST_PARAMS.q == 0

    ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(plaintexts, nonces)
    )

    proof = prove_r2(
        ciphertexts=ciphertexts,
        plaintexts=plaintexts,
        nonces=nonces,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r2(
        ciphertexts=ciphertexts,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


@pytest.mark.parametrize(
    ("list_value", "preference_value"),
    [
        (0, 0),
        (1, 0),
        (1, 1),
    ],
)
def test_r3_accepts_valid_preference_relation(
    list_value,
    preference_value,
):
    """
    R3 accetta tutti i casi coerenti tra lista e preferenza.
    """

    list_nonce = 100
    preference_nonce = 40

    list_ciphertext = encrypt(
        list_value,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=list_nonce,
    )

    preference_ciphertext = encrypt(
        preference_value,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=preference_nonce,
    )

    proof = prove_r3(
        list_ciphertext=list_ciphertext,
        preference_ciphertext=preference_ciphertext,
        list_plaintext=list_value,
        preference_plaintext=preference_value,
        list_nonce=list_nonce,
        preference_nonce=preference_nonce,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r3(
        list_ciphertext=list_ciphertext,
        preference_ciphertext=preference_ciphertext,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_r3_rejects_preference_outside_selected_list():
    """
    R3 rifiuta una preferenza quando la lista non è selezionata.
    """

    list_ciphertext = encrypt(
        0,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=100,
    )

    preference_ciphertext = encrypt(
        1,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=40,
    )

    with pytest.raises(ValueError):
        prove_r3(
            list_ciphertext=list_ciphertext,
            preference_ciphertext=preference_ciphertext,
            list_plaintext=0,
            preference_plaintext=1,
            list_nonce=100,
            preference_nonce=40,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r3_accepts_zero_derived_nonce():
    """
    R3 deve accettare una randomness derivata uguale a 0 modulo q.
    """

    list_nonce = 600
    preference_nonce = 600

    assert (
        list_nonce - preference_nonce
    ) % TEST_PARAMS.q == 0

    list_ciphertext = encrypt(
        1,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=list_nonce,
    )

    preference_ciphertext = encrypt(
        1,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=preference_nonce,
    )

    proof = prove_r3(
        list_ciphertext=list_ciphertext,
        preference_ciphertext=preference_ciphertext,
        list_plaintext=1,
        preference_plaintext=1,
        list_nonce=list_nonce,
        preference_nonce=preference_nonce,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r3(
        list_ciphertext=list_ciphertext,
        preference_ciphertext=preference_ciphertext,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


@pytest.mark.parametrize(
    "preference_plaintexts",
    [
        (0, 0, 0, 0),
        (1, 0, 0, 0),
        (1, 1, 0, 0),
        (1, 1, 1, 0),
    ],
)
def test_r4_accepts_up_to_three_preferences(
    preference_plaintexts,
):
    """
    R4 accetta da zero a tre preferenze complessive.
    """

    preference_nonces = (10, 20, 30, 40)

    preference_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            preference_plaintexts,
            preference_nonces,
        )
    )

    proof = prove_r4(
        preference_ciphertexts=preference_ciphertexts,
        preference_plaintexts=preference_plaintexts,
        preference_nonces=preference_nonces,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r4(
        preference_ciphertexts=preference_ciphertexts,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_r4_rejects_four_preferences():
    """
    R4 rifiuta una scheda con quattro preferenze.
    """

    preference_plaintexts = (1, 1, 1, 1)
    preference_nonces = (10, 20, 30, 40)

    preference_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            preference_plaintexts,
            preference_nonces,
        )
    )

    with pytest.raises(ValueError):
        prove_r4(
            preference_ciphertexts=preference_ciphertexts,
            preference_plaintexts=preference_plaintexts,
            preference_nonces=preference_nonces,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r4_accepts_zero_derived_nonce():
    """
    R4 accetta una randomness aggregata uguale a 0 modulo q.
    """

    preference_plaintexts = (1, 1)
    preference_nonces = (600, 689)

    assert sum(preference_nonces) % TEST_PARAMS.q == 0

    preference_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            preference_plaintexts,
            preference_nonces,
        )
    )

    proof = prove_r4(
        preference_ciphertexts=preference_ciphertexts,
        preference_plaintexts=preference_plaintexts,
        preference_nonces=preference_nonces,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r4(
        preference_ciphertexts=preference_ciphertexts,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


@pytest.mark.parametrize(
    "gender_plaintexts",
    [
        (0, 0, 0),
        (1, 0, 0),
        (1, 1, 0),
    ],
)
def test_r5_accepts_up_to_two_preferences_same_gender(
    gender_plaintexts,
):
    """
    R5 accetta da zero a due preferenze dello stesso genere.
    """

    gender_nonces = (10, 20, 30)

    gender_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            gender_plaintexts,
            gender_nonces,
        )
    )

    proof = prove_r5(
        gender_ciphertexts=gender_ciphertexts,
        gender_plaintexts=gender_plaintexts,
        gender_nonces=gender_nonces,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r5(
        gender_ciphertexts=gender_ciphertexts,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_r5_rejects_three_preferences_same_gender():
    """
    R5 rifiuta tre preferenze appartenenti allo stesso genere.
    """

    gender_plaintexts = (1, 1, 1)
    gender_nonces = (10, 20, 30)

    gender_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            gender_plaintexts,
            gender_nonces,
        )
    )

    with pytest.raises(ValueError):
        prove_r5(
            gender_ciphertexts=gender_ciphertexts,
            gender_plaintexts=gender_plaintexts,
            gender_nonces=gender_nonces,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r5_accepts_zero_derived_nonce():
    """
    R5 accetta una randomness aggregata uguale a 0 modulo q.
    """

    gender_plaintexts = (1, 1)
    gender_nonces = (600, 689)

    assert sum(gender_nonces) % TEST_PARAMS.q == 0

    gender_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            gender_plaintexts,
            gender_nonces,
        )
    )

    proof = prove_r5(
        gender_ciphertexts=gender_ciphertexts,
        gender_plaintexts=gender_plaintexts,
        gender_nonces=gender_nonces,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r5(
        gender_ciphertexts=gender_ciphertexts,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )