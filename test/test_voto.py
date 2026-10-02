"""
Test unitari per evoto.voto.

Usiamo un layout piccolo nel gruppo didattico: due liste,
ciascuna con quattro caselle di preferenza (F, M, F, M).
"""

import pytest

from evoto.elgamal import public_key_from_secret
from evoto.gruppo import TEST_PARAMS
from evoto.scheda import (
    BallotLayout,
    PreferenceMetadata,
    verify_ballot,
)
from evoto.urna import compute_ballot_hash
from evoto.voto import (
    VoterChoice,
    choice_to_plaintexts,
    prepare_ballot,
)


PUBLIC_KEY = public_key_from_secret(765, TEST_PARAMS)
CONTEXT = 744
DISTRICT = 0

LAYOUT = BallotLayout(
    list_count=2,
    max_preferences=3,
    max_preferences_per_gender=2,
    preference_metadata=(
        PreferenceMetadata(list_index=0, gender="F"),
        PreferenceMetadata(list_index=0, gender="M"),
        PreferenceMetadata(list_index=0, gender="F"),
        PreferenceMetadata(list_index=0, gender="M"),
        PreferenceMetadata(list_index=1, gender="F"),
        PreferenceMetadata(list_index=1, gender="M"),
        PreferenceMetadata(list_index=1, gender="F"),
        PreferenceMetadata(list_index=1, gender="M"),
    ),
)


def prepare(choice: VoterChoice, nonces=None):
    """
    Prepara una scheda con i parametri comuni ai test.
    """

    return prepare_ballot(
        layout=LAYOUT,
        district_index=DISTRICT,
        choice=choice,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        extended_base_hash=CONTEXT,
        nonces=nonces,
    )


def test_list_and_preferences_become_bits():
    """
    Lista 1 con due preferenze: un bit per ogni casella.
    """

    bits = choice_to_plaintexts(
        LAYOUT,
        VoterChoice(list_index=1, preferences=(4, 5)),
    )

    assert bits == (
        (0, 1),
        0,
        (0, 0, 0, 0, 1, 1, 0, 0),
    )


def test_preference_without_list_marks_the_list():
    """
    Una preferenza senza lista vale anche per la sua lista.
    """

    bits = choice_to_plaintexts(
        LAYOUT,
        VoterChoice(list_index=None, preferences=(2,)),
    )

    assert bits == (
        (1, 0),
        0,
        (0, 0, 1, 0, 0, 0, 0, 0),
    )


def test_empty_choice_is_a_blank_ballot():
    """
    Senza lista e senza preferenze la scheda è bianca.
    """

    bits = choice_to_plaintexts(LAYOUT, VoterChoice(list_index=None))

    assert bits == (
        (0, 0),
        1,
        (0, 0, 0, 0, 0, 0, 0, 0),
    )


def test_preferences_in_different_lists_without_list_are_rejected():
    """
    Il dispositivo non può indovinare la lista se le preferenze
    appartengono a liste diverse.
    """

    with pytest.raises(ValueError):
        choice_to_plaintexts(
            LAYOUT,
            VoterChoice(list_index=None, preferences=(0, 4)),
        )


def test_duplicated_preference_is_rejected():
    """
    La stessa casella non può essere segnata due volte.
    """

    with pytest.raises(ValueError):
        choice_to_plaintexts(
            LAYOUT,
            VoterChoice(list_index=0, preferences=(1, 1)),
        )


def test_unknown_boxes_are_rejected():
    """
    Lista e caselle devono esistere nel layout.
    """

    with pytest.raises(ValueError):
        choice_to_plaintexts(LAYOUT, VoterChoice(list_index=2))

    with pytest.raises(ValueError):
        choice_to_plaintexts(
            LAYOUT,
            VoterChoice(list_index=0, preferences=(8,)),
        )


def test_prepared_ballot_is_valid():
    """
    La scheda preparata supera la verifica completa R1-R5.
    """

    prepared = prepare(VoterChoice(list_index=0, preferences=(0, 1, 3)))

    assert verify_ballot(
        layout=LAYOUT,
        ballot=prepared.ballot,
        proofs=prepared.proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_prepared_ballot_hash_matches_the_board():
    """
    L'impronta mostrata all'elettore è quella che userà la bacheca.
    """

    prepared = prepare(VoterChoice(list_index=1))

    assert prepared.ballot_hash == compute_ballot_hash(
        prepared.ballot,
        DISTRICT,
        CONTEXT,
        TEST_PARAMS,
    )


def test_prepared_ballot_with_fixed_nonces_is_reproducible():
    """
    Con gli stessi nonce la cifratura è identica.
    """

    nonces = tuple(range(11, 22))

    first = prepare(VoterChoice(list_index=1, preferences=(5,)), nonces)
    second = prepare(VoterChoice(list_index=1, preferences=(5,)), nonces)

    assert first.ballot == second.ballot
    assert first.witness.list_nonces == (11, 12)
    assert first.witness.blank_nonce == 13
    assert first.witness.preference_nonces == tuple(range(14, 22))


def test_fresh_nonces_differ_between_ballots():
    """
    Senza nonce espliciti due schede identiche hanno cifrati diversi.
    """

    first = prepare(VoterChoice(list_index=0))
    second = prepare(VoterChoice(list_index=0))

    assert first.ballot != second.ballot


def test_wrong_number_of_nonces_is_rejected():
    """
    Serve un nonce per ogni casella.
    """

    with pytest.raises(ValueError):
        prepare(VoterChoice(list_index=0), nonces=(1, 2, 3))


def test_preference_outside_the_list_cannot_be_proved():
    """
    R3: una preferenza fuori dalla lista votata non produce una scheda.
    """

    with pytest.raises(ValueError):
        prepare(VoterChoice(list_index=0, preferences=(4,)))


def test_four_preferences_cannot_be_proved():
    """
    R4: al massimo tre preferenze.
    """

    with pytest.raises(ValueError):
        prepare(VoterChoice(list_index=0, preferences=(0, 1, 2, 3)))


def test_three_preferences_of_the_same_gender_cannot_be_proved():
    """
    R5: al massimo due preferenze dello stesso genere.

    Serve una lista con almeno tre candidate dello stesso genere,
    quindi usiamo un layout dedicato.
    """

    layout = BallotLayout(
        list_count=1,
        max_preferences=3,
        max_preferences_per_gender=2,
        preference_metadata=(
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=0, gender="M"),
        ),
    )

    with pytest.raises(ValueError):
        prepare_ballot(
            layout=layout,
            district_index=DISTRICT,
            choice=VoterChoice(list_index=0, preferences=(0, 1, 2)),
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            extended_base_hash=CONTEXT,
        )

    prepared = prepare_ballot(
        layout=layout,
        district_index=DISTRICT,
        choice=VoterChoice(list_index=0, preferences=(0, 1, 3)),
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        extended_base_hash=CONTEXT,
    )

    assert verify_ballot(
        layout=layout,
        ballot=prepared.ballot,
        proofs=prepared.proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )
