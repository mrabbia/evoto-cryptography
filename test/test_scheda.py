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