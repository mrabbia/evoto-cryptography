"""
Test unitari per evoto.elgamal.

Usiamo il gruppo didattico condiviso definito in evoto.gruppo.
"""

import pytest

from evoto.elgamal import (
    Ciphertext,
    bounded_discrete_log,
    divide_ciphertexts,
    encrypt,
    generate_secret_key,
    multiply_ciphertexts,
    public_key_from_secret,
)
from evoto.gruppo import TEST_PARAMS


def test_generate_secret_key_range():
    """
    La chiave segreta deve stare tra 1 e q - 1.
    """

    secret_key = generate_secret_key(TEST_PARAMS)

    assert 1 <= secret_key < TEST_PARAMS.q


def test_public_key_from_secret():
    """
    Verifica la chiave pubblica dell'esempio numerico.

    Con s = 765:
        K = g^s mod p = 530
    """

    public_key = public_key_from_secret(
        765,
        TEST_PARAMS,
    )

    assert public_key == 530


def test_public_key_rejects_zero_secret():
    """
    La chiave segreta 0 non è ammessa.
    """

    with pytest.raises(ValueError):
        public_key_from_secret(0, TEST_PARAMS)


def test_encrypt_reference_vector_vote_one():
    """
    Vettore di riferimento della specifica.

    message = 1
    nonce = 11
    K = 530

    ciphertext atteso:
        (850, 2375)
    """

    ciphertext = encrypt(
        message=1,
        public_key=530,
        params=TEST_PARAMS,
        nonce=11,
    )

    assert ciphertext == Ciphertext(
        alpha=850,
        beta=2375,
    )


def test_encrypt_reference_vector_vote_zero():
    """
    Secondo vettore di riferimento.

    message = 0
    nonce = 22
    """

    ciphertext = encrypt(
        message=0,
        public_key=530,
        params=TEST_PARAMS,
        nonce=22,
    )

    assert ciphertext == Ciphertext(
        alpha=380,
        beta=22,
    )


def test_encrypt_reference_vector_third_vote():
    """
    Terzo vettore di riferimento.

    message = 1
    nonce = 33
    """

    ciphertext = encrypt(
        message=1,
        public_key=530,
        params=TEST_PARAMS,
        nonce=33,
    )

    assert ciphertext == Ciphertext(
        alpha=625,
        beta=670,
    )


def test_encrypt_rejects_negative_message():
    """
    Il plaintext non può essere negativo.
    """

    with pytest.raises(ValueError):
        encrypt(
            message=-1,
            public_key=530,
            params=TEST_PARAMS,
            nonce=11,
        )


def test_encrypt_rejects_zero_nonce():
    """
    Il nonce 0 non è ammesso secondo la convenzione aggiornata.
    """

    with pytest.raises(ValueError):
        encrypt(
            message=1,
            public_key=530,
            params=TEST_PARAMS,
            nonce=0,
        )


def test_multiply_ciphertexts_reference_tally():
    """
    Moltiplicando i tre ciphertext dell'esempio
    otteniamo il tally cifrato ufficiale:

        (A, B) = (1196, 154)
    """

    c1 = Ciphertext(850, 2375)
    c2 = Ciphertext(380, 22)
    c3 = Ciphertext(625, 670)

    partial = multiply_ciphertexts(
        c1,
        c2,
        TEST_PARAMS,
    )

    tally = multiply_ciphertexts(
        partial,
        c3,
        TEST_PARAMS,
    )

    assert tally == Ciphertext(
        alpha=1196,
        beta=154,
    )


def test_divide_ciphertexts_restores_first_ciphertext():
    """
    Se moltiplichiamo C1 e C2 e poi dividiamo per C2,
    dobbiamo riottenere C1.
    """

    c1 = Ciphertext(850, 2375)
    c2 = Ciphertext(380, 22)

    product = multiply_ciphertexts(
        c1,
        c2,
        TEST_PARAMS,
    )

    restored = divide_ciphertexts(
        product,
        c2,
        TEST_PARAMS,
    )

    assert restored == c1


def test_bounded_discrete_log():
    """
    Verifica un logaritmo discreto piccolo.

    4^2 mod 2579 = 16
    quindi il logaritmo di 16 in base 4 è 2.
    """

    result = bounded_discrete_log(
        value=16,
        params=TEST_PARAMS,
        max_exponent=10,
    )

    assert result == 2


def test_bounded_discrete_log_returns_none_outside_bound():
    """
    Se il valore esiste ma l'esponente supera il limite,
    la funzione deve restituire None.
    """

    value = pow(
        TEST_PARAMS.g,
        20,
        TEST_PARAMS.p,
    )

    result = bounded_discrete_log(
        value=value,
        params=TEST_PARAMS,
        max_exponent=10,
    )

    assert result is None