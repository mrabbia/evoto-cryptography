"""
Test d'integrazione: un'elezione politica completa (esperimento E1).

Usa la configurazione di esempio: tre circoscrizioni, sei liste in due
coalizioni e due liste singole. Gli elettori scelgono a caso, alcuni
sprecano una scheda per controllare il dispositivo.

Il risultato del percorso cifrato deve coincidere con un conteggio in
chiaro delle stesse scelte, fino ai seggi e agli eletti.
"""

from pathlib import Path
import random

from evoto.configurazione import (
    build_ballot_layout,
    load_election_config,
)
from evoto.gruppo import TEST_PARAMS
from evoto.scheda import verify_ballot
from evoto.simulazione import (
    plaintext_count,
    random_choice,
    simulate_election,
)
from evoto.urna import CAST, SPOILED, verify_spoiled_ballot
from evoto.voto import VoterChoice


CONFIG = load_election_config(
    Path(__file__).resolve().parent.parent
    / "config"
    / "elezione_esempio.json"
)

WEIGHTS = (22, 14, 12, 9, 16, 11, 7, 6)

REPORT = simulate_election(
    config=CONFIG,
    voters_per_district=15,
    guardian_count=5,
    quorum=3,
    present_guardians=(2, 4, 5),
    params=TEST_PARAMS,
    seed=1,
    list_weights=WEIGHTS,
    spoil_probability=0.2,
)


def test_encrypted_totals_match_the_plaintext_count():
    """
    Per ogni circoscrizione liste, bianche e preferenze coincidono.
    """

    for cipher, clear in zip(
        REPORT.results,
        REPORT.plaintext_results,
        strict=True,
    ):
        assert cipher.ballot_count == clear.ballot_count == 15
        assert cipher.list_votes == clear.list_votes
        assert cipher.blank_votes == clear.blank_votes
        assert cipher.preference_votes == clear.preference_votes


def test_seats_and_elected_match_the_plaintext_count():
    """
    Anche seggi, premio ed eletti coincidono.
    """

    assert REPORT.scrutiny == REPORT.plaintext_scrutiny


def test_every_seat_is_assigned():
    """
    I 30 seggi sono tutti assegnati, a 30 eletti diversi.
    """

    scrutiny = REPORT.scrutiny

    assert sum(scrutiny.list_seats) == CONFIG.seats
    assert len(scrutiny.elected) == CONFIG.seats

    elected = {
        (candidate.district_index, candidate.name)
        for candidate in scrutiny.elected
    }

    assert len(elected) == CONFIG.seats


def test_board_is_consistent():
    """
    La catena è valida, ogni scheda ha prove valide e ogni scheda
    sprecata si riapre con i dati rivelati.
    """

    assert REPORT.board_is_valid
    assert REPORT.spoiled_count > 0

    layouts = tuple(
        build_ballot_layout(CONFIG, index)
        for index in range(len(CONFIG.districts))
    )

    public_key = REPORT.ceremony.joint_public_key

    for entry in REPORT.board.entries:
        assert verify_ballot(
            layout=layouts[entry.district_index],
            ballot=entry.ballot,
            proofs=entry.proofs,
            public_key=public_key,
            params=TEST_PARAMS,
            context=REPORT.board.extended_base_hash,
        )

        if entry.state == SPOILED:
            assert verify_spoiled_ballot(
                entry.ballot,
                entry.revealed_witness,
                public_key,
                TEST_PARAMS,
            )

    cast = [entry for entry in REPORT.board.entries if entry.state == CAST]

    assert len(cast) == 45
    assert len(REPORT.board.entries) == 45 + REPORT.spoiled_count


def test_random_choices_are_always_valid():
    """
    Le scelte casuali rispettano sempre le regole della scheda:
    al massimo tre preferenze, tutte nella stessa lista, al massimo
    due per genere.
    """

    rng = random.Random(3)
    layout = build_ballot_layout(CONFIG, 1)

    for _ in range(300):
        choice = random_choice(rng, layout, WEIGHTS, 0.05, 3, 2)

        assert len(choice.preferences) <= 3

        lists = {
            layout.preference_metadata[box].list_index
            for box in choice.preferences
        }

        assert len(lists) <= 1

        if choice.list_index is not None and lists:
            assert lists == {choice.list_index}

        genders = [
            layout.preference_metadata[box].gender
            for box in choice.preferences
        ]

        assert all(genders.count(gender) <= 2 for gender in genders)


def test_plaintext_count():
    """
    Il conteggio in chiaro applica la stessa regola della scheda:
    una preferenza senza lista vale per la lista.
    """

    layout = build_ballot_layout(CONFIG, 0)

    result = plaintext_count(
        layout,
        0,
        [
            VoterChoice(list_index=1, preferences=(4,)),
            VoterChoice(list_index=None, preferences=(0, 1)),
            VoterChoice(list_index=None),
        ],
    )

    assert result.ballot_count == 3
    assert result.list_votes[:2] == (1, 1)
    assert result.blank_votes == 1
    assert result.preference_votes[:5] == (1, 1, 0, 0, 1)
