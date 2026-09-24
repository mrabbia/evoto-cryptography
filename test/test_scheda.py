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