"""
Test unitari per evoto.decifratura.

I valori attesi sono quelli dell'esempio numerico della specifica
F1 v0.2, sezione 38: tre garanti con quorum 2, tally (1196, 154)
ottenuto dai voti 1, 0, 1 e totale finale 2.
"""

import pytest

from evoto.decifratura import (
    DecryptionShare,
    combine_decryption_shares,
    compute_decryption_share,
    decrypt_tally,
    lagrange_coefficient,
    verify_decryption_share,
)
from evoto.elgamal import Ciphertext
from evoto.gruppo import TEST_PARAMS
from evoto.prove import ChaumPedersenProof


REFERENCE_QUORUM = 2
REFERENCE_EXTENDED_BASE_HASH = 744

REFERENCE_TALLY = Ciphertext(
    alpha=1196,
    beta=154,
)

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

REFERENCE_PARTIAL_DECRYPTIONS = {
    1: 60,
    2: 508,
    3: 1894,
}

REFERENCE_COMBINED = 332
REFERENCE_TOTAL = 2


def reference_share(index: int) -> DecryptionShare:
    """
    Calcola la share di decifratura di un garante dell'esempio.
    """

    return compute_decryption_share(
        guardian_index=index,
        secret_share=REFERENCE_SECRET_SHARES[index],
        tally=REFERENCE_TALLY,
        params=TEST_PARAMS,
        extended_base_hash=REFERENCE_EXTENDED_BASE_HASH,
        nonce=7,
    )


def test_lagrange_reference_vectors():
    """
    Coefficienti attesi per i vari insiemi di garanti presenti.
    """

    expected_by_set = {
        (1, 3): (646, 644),
        (1, 2): (2, 1288),
        (2, 3): (3, 1287),
        (1, 2, 3): (3, 1286, 1),
    }

    for available, expected in expected_by_set.items():
        coefficients = tuple(
            lagrange_coefficient(index, available, TEST_PARAMS)
            for index in available
        )

        assert coefficients == expected


def test_lagrange_with_a_single_guardian():
    """
    Con un solo garante il coefficiente vale 1.
    """

    assert lagrange_coefficient(1, (1,), TEST_PARAMS) == 1


def test_lagrange_rejects_duplicated_indices():
    """
    Un garante non può comparire due volte nell'insieme.
    """

    with pytest.raises(ValueError):
        lagrange_coefficient(1, (1, 1, 2), TEST_PARAMS)


def test_lagrange_rejects_index_outside_the_set():
    """
    Il coefficiente ha senso solo per un garante presente.
    """

    with pytest.raises(ValueError):
        lagrange_coefficient(4, (1, 2), TEST_PARAMS)


def test_decryption_share_reference_vector():
    """
    Vettore ufficiale della specifica F1 v0.2.

    Garante 1, share 865, tally (1196, 154), nonce 7:

        M_1 = 60
        a = 910, b = 1033, c = 524, z = 828
    """

    share = reference_share(1)

    assert share.partial_decryption == REFERENCE_PARTIAL_DECRYPTIONS[1]

    assert share.proof == ChaumPedersenProof(
        commitment_1=910,
        commitment_2=1033,
        challenge=524,
        response=828,
    )


def test_partial_decryptions_reference_vector():
    """
    Le tre share di decifratura dell'esempio.
    """

    for index, expected in REFERENCE_PARTIAL_DECRYPTIONS.items():
        assert reference_share(index).partial_decryption == expected


def test_decryption_share_is_verified():
    """
    La prova viene accettata usando la chiave di verifica pubblica.
    """

    for index in (1, 2, 3):
        assert verify_decryption_share(
            share=reference_share(index),
            verification_key=REFERENCE_VERIFICATION_KEYS[index],
            tally=REFERENCE_TALLY,
            params=TEST_PARAMS,
            extended_base_hash=REFERENCE_EXTENDED_BASE_HASH,
        )


def test_verification_rejects_wrong_verification_key():
    """
    La share del garante 1 non passa con la chiave del garante 2.

    È il controllo che impedisce a un garante di decifrare
    al posto di un altro.
    """

    assert not verify_decryption_share(
        share=reference_share(1),
        verification_key=REFERENCE_VERIFICATION_KEYS[2],
        tally=REFERENCE_TALLY,
        params=TEST_PARAMS,
        extended_base_hash=REFERENCE_EXTENDED_BASE_HASH,
    )


def test_verification_rejects_tampered_partial_decryption():
    """
    Un garante che pubblica un M_l diverso viene scoperto.
    """

    share = reference_share(1)

    tampered_share = DecryptionShare(
        guardian_index=share.guardian_index,
        partial_decryption=508,
        proof=share.proof,
    )

    assert not verify_decryption_share(
        share=tampered_share,
        verification_key=REFERENCE_VERIFICATION_KEYS[1],
        tally=REFERENCE_TALLY,
        params=TEST_PARAMS,
        extended_base_hash=REFERENCE_EXTENDED_BASE_HASH,
    )


def test_verification_rejects_wrong_context():
    """
    La prova è legata all'elezione tramite Q_bar.
    """

    assert not verify_decryption_share(
        share=reference_share(1),
        verification_key=REFERENCE_VERIFICATION_KEYS[1],
        tally=REFERENCE_TALLY,
        params=TEST_PARAMS,
        extended_base_hash=REFERENCE_EXTENDED_BASE_HASH + 1,
    )


def test_combine_reference_vectors():
    """
    Qualsiasi insieme di garanti presenti ricostruisce A^s = 332.
    """

    for available in ((1, 3), (1, 2), (2, 3), (1, 2, 3)):
        shares = tuple(
            reference_share(index)
            for index in available
        )

        combined = combine_decryption_shares(
            shares,
            REFERENCE_QUORUM,
            TEST_PARAMS,
        )

        assert combined == REFERENCE_COMBINED


def test_combine_rejects_fewer_shares_than_quorum():
    """
    Con meno garanti del quorum la decifratura non è possibile.
    """

    with pytest.raises(ValueError):
        combine_decryption_shares(
            (reference_share(1),),
            REFERENCE_QUORUM,
            TEST_PARAMS,
        )


def test_combine_rejects_the_same_guardian_twice():
    """
    Due share dello stesso garante non sostituiscono due garanti.
    """

    with pytest.raises(ValueError):
        combine_decryption_shares(
            (reference_share(1), reference_share(1)),
            REFERENCE_QUORUM,
            TEST_PARAMS,
        )


def test_decrypt_tally_reference_vector():
    """
    Dal tally dell'esempio si ottiene il totale 2.
    """

    total = decrypt_tally(
        tally=REFERENCE_TALLY,
        shares=(reference_share(1), reference_share(3)),
        quorum=REFERENCE_QUORUM,
        params=TEST_PARAMS,
        max_total=10,
    )

    assert total == REFERENCE_TOTAL


def test_decrypt_tally_with_an_absent_guardian():
    """
    Con il garante 1 assente il risultato non cambia.
    """

    total = decrypt_tally(
        tally=REFERENCE_TALLY,
        shares=(reference_share(2), reference_share(3)),
        quorum=REFERENCE_QUORUM,
        params=TEST_PARAMS,
        max_total=10,
    )

    assert total == REFERENCE_TOTAL


def test_decrypt_tally_with_every_guardian():
    """
    Anche con tutti i garanti presenti il totale è lo stesso.
    """

    total = decrypt_tally(
        tally=REFERENCE_TALLY,
        shares=tuple(reference_share(index) for index in (1, 2, 3)),
        quorum=REFERENCE_QUORUM,
        params=TEST_PARAMS,
        max_total=10,
    )

    assert total == REFERENCE_TOTAL


def test_decrypt_tally_rejects_total_above_the_limit():
    """
    Il logaritmo discreto è limitato al numero di schede dichiarato.
    """

    with pytest.raises(ValueError):
        decrypt_tally(
            tally=REFERENCE_TALLY,
            shares=(reference_share(1), reference_share(3)),
            quorum=REFERENCE_QUORUM,
            params=TEST_PARAMS,
            max_total=1,
        )
