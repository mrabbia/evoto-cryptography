"""
Bacheca pubblica e conteggio omomorfico del progetto evoto.

Per ora il modulo contiene soltanto l'aggregazione dei cifrati, che serve
al referendum sì/no end-to-end di F2 e F3.

Codici di tracciamento, catena di hash, cast-or-spoil e conteggio per
circoscrizione arriveranno con F5.
"""

from evoto.elgamal import (
    Ciphertext,
    multiply_ciphertexts,
)
from evoto.gruppo import GroupParameters


def aggregate_ciphertexts(
    ciphertexts: tuple[Ciphertext, ...],
    params: GroupParameters,
) -> Ciphertext:
    """
    Somma i voti restando sui cifrati.

        (A, B) = (∏ alpha_j, ∏ beta_j) = Enc(Σ v_j)

    Nessuna scheda viene decifrata: il risultato è il tally cifrato,
    l'unico valore che i garanti decifreranno.

    Con una lista vuota restituisce Enc(0) = (1, 1), cioè l'elemento
    neutro del prodotto.
    """

    tally = Ciphertext(
        alpha=1,
        beta=1,
    )

    for ciphertext in ciphertexts:
        tally = multiply_ciphertexts(
            tally,
            ciphertext,
            params,
        )

    return tally
