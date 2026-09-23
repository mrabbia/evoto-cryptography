"""
Test d'integrazione: un referendum sì/no end-to-end.

È l'obiettivo comune di F2 e F3 e ripercorre le sei fasi del protocollo
usando soltanto la nostra libreria:

1. cerimonia delle chiavi con 5 garanti e quorum 3;
2. voto: una casella per elettore, con la prova che il valore è 0 o 1;
3. registro: qui rappresentato dalla lista delle schede e delle prove;
4. conteggio omomorfico, senza decifrare nessuna scheda;
5. decifratura a soglia con 3 garanti su 5;
6. verifica: tutte le prove vengono ricontrollate dai dati pubblici.
"""

import pytest

from evoto.decifratura import (
    compute_decryption_share,
    decrypt_tally,
    verify_decryption_share,
)
from evoto.elgamal import encrypt
from evoto.garanti import (
    compute_verification_key,
    run_key_ceremony,
    verify_guardian_record,
)
from evoto.gruppo import TEST_PARAMS
from evoto.prove import (
    prove_value_in_set,
    verify_value_in_set,
)
from evoto.urna import aggregate_ciphertexts


GUARDIAN_COUNT = 5
QUORUM = 3
ELECTION_ID = 2026

# Voti simulati e nonce fissati, per rendere il test riproducibile.
VOTES = (1, 0, 1, 1, 0, 1, 0, 1)

NONCES = (11, 22, 33, 44, 55, 66, 77, 88)

ALLOWED_VALUES = (0, 1)


def run_referendum():
    """
    Esegue la cerimonia, cifra le schede e le accompagna con le prove.

    Restituisce la cerimonia, le schede cifrate e le relative prove.
    """

    ceremony = run_key_ceremony(
        guardian_count=GUARDIAN_COUNT,
        quorum=QUORUM,
        params=TEST_PARAMS,
        election_id=ELECTION_ID,
    )

    ballots = []
    proofs = []

    for vote, nonce in zip(VOTES, NONCES, strict=True):
        ciphertext = encrypt(
            message=vote,
            public_key=ceremony.joint_public_key,
            params=TEST_PARAMS,
            nonce=nonce,
        )

        proof = prove_value_in_set(
            ciphertext=ciphertext,
            plaintext=vote,
            nonce=nonce,
            allowed_values=ALLOWED_VALUES,
            public_key=ceremony.joint_public_key,
            params=TEST_PARAMS,
            context=ceremony.extended_base_hash,
        )

        ballots.append(ciphertext)
        proofs.append(proof)

    return ceremony, tuple(ballots), tuple(proofs)


def decrypt_with_guardians(ceremony, tally, present_guardians):
    """
    Decifra il tally con i garanti indicati, verificando ogni share.
    """

    shares = []

    for index in present_guardians:
        share = compute_decryption_share(
            guardian_index=index,
            secret_share=ceremony.secret_shares[index],
            tally=tally,
            params=TEST_PARAMS,
            extended_base_hash=ceremony.extended_base_hash,
        )

        verification_key = compute_verification_key(
            index,
            ceremony.records,
            TEST_PARAMS,
        )

        assert verify_decryption_share(
            share=share,
            verification_key=verification_key,
            tally=tally,
            params=TEST_PARAMS,
            extended_base_hash=ceremony.extended_base_hash,
        )

        shares.append(share)

    return decrypt_tally(
        tally=tally,
        shares=tuple(shares),
        quorum=QUORUM,
        params=TEST_PARAMS,
        max_total=len(VOTES),
    )


def test_referendum_end_to_end():
    """
    Il totale decifrato coincide con il conteggio in chiaro.

    Nessuna scheda viene mai decifrata: si decifra solo il tally.
    """

    ceremony, ballots, proofs = run_referendum()

    for record in ceremony.records:
        assert verify_guardian_record(
            record,
            QUORUM,
            TEST_PARAMS,
            ceremony.base_hash,
        )

    for ciphertext, proof in zip(ballots, proofs, strict=True):
        assert verify_value_in_set(
            ciphertext=ciphertext,
            proof=proof,
            allowed_values=ALLOWED_VALUES,
            public_key=ceremony.joint_public_key,
            params=TEST_PARAMS,
            context=ceremony.extended_base_hash,
        )

    tally = aggregate_ciphertexts(ballots, TEST_PARAMS)

    total = decrypt_with_guardians(ceremony, tally, (1, 3, 5))

    assert total == sum(VOTES)


def test_referendum_with_a_different_set_of_guardians():
    """
    Qualunque terna di garanti ottiene lo stesso risultato.

    Due garanti assenti non bloccano l'elezione.
    """

    ceremony, ballots, _ = run_referendum()

    tally = aggregate_ciphertexts(ballots, TEST_PARAMS)

    first_total = decrypt_with_guardians(ceremony, tally, (1, 3, 5))
    second_total = decrypt_with_guardians(ceremony, tally, (2, 4, 5))

    assert first_total == second_total == sum(VOTES)


def test_referendum_fails_below_the_quorum():
    """
    Con due garanti su cinque la decifratura non è possibile.
    """

    ceremony, ballots, _ = run_referendum()

    tally = aggregate_ciphertexts(ballots, TEST_PARAMS)

    with pytest.raises(ValueError):
        decrypt_with_guardians(ceremony, tally, (1, 2))


def test_ballot_outside_the_allowed_values_cannot_be_proved():
    """
    Un client scorretto non riesce a produrre la prova per un voto 2.

    È la dimostrazione che la validità della scheda non dipende
    dall'interfaccia ma dalle prove.
    """

    ceremony, _, _ = run_referendum()

    ciphertext = encrypt(
        message=2,
        public_key=ceremony.joint_public_key,
        params=TEST_PARAMS,
        nonce=99,
    )

    with pytest.raises(ValueError):
        prove_value_in_set(
            ciphertext=ciphertext,
            plaintext=2,
            nonce=99,
            allowed_values=ALLOWED_VALUES,
            public_key=ceremony.joint_public_key,
            params=TEST_PARAMS,
            context=ceremony.extended_base_hash,
        )


def test_proof_belongs_to_its_own_ballot():
    """
    La prova di una scheda non vale per un'altra scheda.
    """

    ceremony, ballots, proofs = run_referendum()

    assert not verify_value_in_set(
        ciphertext=ballots[1],
        proof=proofs[0],
        allowed_values=ALLOWED_VALUES,
        public_key=ceremony.joint_public_key,
        params=TEST_PARAMS,
        context=ceremony.extended_base_hash,
    )
