"""
Test unitari per evoto.urna.

Usiamo i tre cifrati dell'esempio numerico della specifica F1 v0.2,
sezione 38, che aggregati danno il tally (1196, 154).
"""

from evoto.elgamal import Ciphertext, encrypt
from evoto.gruppo import TEST_PARAMS
from evoto.urna import aggregate_ciphertexts


REFERENCE_CIPHERTEXTS = (
    Ciphertext(alpha=850, beta=2375),
    Ciphertext(alpha=380, beta=22),
    Ciphertext(alpha=625, beta=670),
)


def test_aggregate_reference_vector():
    """
    Il prodotto dei cifrati dei voti 1, 0, 1 è il tally dell'esempio.
    """

    tally = aggregate_ciphertexts(
        REFERENCE_CIPHERTEXTS,
        TEST_PARAMS,
    )

    assert tally == Ciphertext(alpha=1196, beta=154)


def test_aggregate_without_ciphertexts():
    """
    Senza schede il tally è Enc(0), cioè l'elemento neutro (1, 1).
    """

    tally = aggregate_ciphertexts((), TEST_PARAMS)

    assert tally == Ciphertext(alpha=1, beta=1)


def test_aggregate_of_a_single_ciphertext():
    """
    Con una sola scheda il tally coincide con la scheda stessa.
    """

    ciphertext = encrypt(
        message=1,
        public_key=530,
        params=TEST_PARAMS,
        nonce=11,
    )

    tally = aggregate_ciphertexts(
        (ciphertext,),
        TEST_PARAMS,
    )

    assert tally == ciphertext
