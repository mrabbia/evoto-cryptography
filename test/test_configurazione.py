"""
Test unitari per evoto.configurazione.

Usiamo sia il file config/elezione_esempio.json sia piccole
configurazioni costruite nel test per i casi di errore.
"""

import copy
from fractions import Fraction
from pathlib import Path

import pytest

from evoto.configurazione import (
    build_ballot_layout,
    coalition_of,
    load_election_config,
    parse_election_config,
    preference_candidates,
)
from evoto.scheda import PreferenceMetadata


EXAMPLE_PATH = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "elezione_esempio.json"
)


def small_config_data() -> dict:
    """
    Configurazione minima: due liste in coalizione, una singola,
    una circoscrizione.
    """

    return {
        "name": "Test",
        "election_id": 5,
        "seats": 10,
        "rules": {
            "max_preferences": 3,
            "max_preferences_per_gender": 2,
            "list_threshold_percent": 3,
            "coalition_threshold_percent": 10,
            "bonus_threshold_percent": 42,
            "bonus_seats_percent": 55,
        },
        "lists": [
            {"name": "Lista A", "coalition": "Alfa"},
            {"name": "Lista B", "coalition": "Alfa"},
            {"name": "Lista C", "coalition": None},
        ],
        "districts": [
            {
                "name": "Unica",
                "candidates": {
                    "Lista A": [
                        {"name": "A0", "gender": "M"},
                        {"name": "A1", "gender": "F"},
                        {"name": "A2", "gender": "M"},
                    ],
                    "Lista B": [
                        {"name": "B0", "gender": "F"},
                    ],
                    "Lista C": [
                        {"name": "C0", "gender": "F"},
                        {"name": "C1", "gender": "M"},
                    ],
                },
            },
        ],
    }


def test_example_config_is_valid():
    """
    Il file di esempio rispetta la struttura richiesta dall'esperimento E1:
    tre circoscrizioni, sei liste in due coalizioni e due liste singole.
    """

    config = load_election_config(EXAMPLE_PATH)

    assert config.election_id == 1
    assert config.seats == 30
    assert len(config.list_names) == 8
    assert len(config.districts) == 3

    coalitions = {
        coalition.name: coalition.list_indices
        for coalition in config.coalitions
    }

    assert coalitions == {
        "Coalizione Alfa": (0, 1, 3),
        "Coalizione Beta": (4, 5, 6),
    }


def test_example_config_rules_are_exact_fractions():
    """
    Le soglie sono frazioni esatte, non numeri in virgola mobile.
    """

    rules = load_election_config(EXAMPLE_PATH).rules

    assert rules.list_threshold == Fraction(3, 100)
    assert rules.coalition_threshold == Fraction(10, 100)
    assert rules.bonus_threshold == Fraction(42, 100)
    assert rules.bonus_seat_share == Fraction(55, 100)


def test_example_layout_of_the_first_district():
    """
    Nella circoscrizione Nord ogni lista ha capolista e quattro candidati:
    8 liste per 4 caselle danno 32 caselle di preferenza.

    Le prime quattro sono quelle della Lista A dell'esempio della
    proposta di progetto: Galli M., Conti L., Marino P., Greco S.
    """

    config = load_election_config(EXAMPLE_PATH)

    layout = build_ballot_layout(config, 0)

    assert layout.list_count == 8
    assert len(layout.preference_metadata) == 32

    assert layout.preference_metadata[:4] == (
        PreferenceMetadata(list_index=0, gender="M"),
        PreferenceMetadata(list_index=0, gender="F"),
        PreferenceMetadata(list_index=0, gender="M"),
        PreferenceMetadata(list_index=0, gender="F"),
    )


def test_parse_small_config():
    """
    Le coalizioni sono ricavate dal campo coalition delle liste.
    """

    config = parse_election_config(small_config_data())

    assert config.list_names == ("Lista A", "Lista B", "Lista C")
    assert len(config.coalitions) == 1
    assert config.coalitions[0].name == "Alfa"
    assert config.coalitions[0].list_indices == (0, 1)


def test_coalition_of():
    """
    Una lista non coalizzata non ha coalizione.
    """

    config = parse_election_config(small_config_data())

    assert coalition_of(config, 0) == 0
    assert coalition_of(config, 1) == 0
    assert coalition_of(config, 2) is None


def test_preference_candidates_skip_the_head_of_list():
    """
    Il capolista (posizione 0) non ha casella di preferenza.

    La Lista B ha solo il capolista, quindi nessuna casella.
    """

    config = parse_election_config(small_config_data())

    assert preference_candidates(config, 0) == (
        (0, 1),
        (0, 2),
        (2, 1),
    )


def test_layout_follows_preference_candidates():
    """
    Le caselle del layout seguono lo stesso ordine dei candidati.
    """

    config = parse_election_config(small_config_data())

    layout = build_ballot_layout(config, 0)

    assert layout.list_count == 3
    assert layout.preference_metadata == (
        PreferenceMetadata(list_index=0, gender="F"),
        PreferenceMetadata(list_index=0, gender="M"),
        PreferenceMetadata(list_index=2, gender="M"),
    )


def test_decimal_percentages_are_exact():
    """
    Una soglia del 2,5% diventa esattamente 1/40.
    """

    data = small_config_data()
    data["rules"]["list_threshold_percent"] = 2.5

    config = parse_election_config(data)

    assert config.rules.list_threshold == Fraction(1, 40)


def test_rejects_duplicated_list_names():
    """
    Due liste non possono avere lo stesso nome.
    """

    data = small_config_data()
    data["lists"][1]["name"] = "Lista A"

    with pytest.raises(ValueError):
        parse_election_config(data)


def test_rejects_district_without_a_list():
    """
    Ogni circoscrizione deve avere candidati per tutte le liste.
    """

    data = small_config_data()
    del data["districts"][0]["candidates"]["Lista C"]

    with pytest.raises(ValueError):
        parse_election_config(data)


def test_rejects_list_without_head_of_list():
    """
    Ogni lista deve avere almeno il capolista.
    """

    data = small_config_data()
    data["districts"][0]["candidates"]["Lista B"] = []

    with pytest.raises(ValueError):
        parse_election_config(data)


def test_rejects_missing_field():
    """
    Un campo mancante produce un ValueError, non un KeyError.
    """

    data = small_config_data()
    del data["rules"]["bonus_threshold_percent"]

    with pytest.raises(ValueError):
        parse_election_config(data)


def test_rejects_percentage_above_one_hundred():
    """
    Una percentuale deve stare tra 0 e 100.
    """

    data = small_config_data()
    data["rules"]["coalition_threshold_percent"] = 120

    with pytest.raises(ValueError):
        parse_election_config(data)


def test_rejects_non_positive_seats():
    """
    Il numero di seggi deve essere positivo.
    """

    data = small_config_data()
    data["seats"] = 0

    with pytest.raises(ValueError):
        parse_election_config(data)


def test_layout_uses_configured_preference_limits():
    """
    Il layout usa i limiti definiti nella configurazione.
    """

    data = copy.deepcopy(small_config_data())
    data["rules"]["max_preferences"] = 2
    data["rules"]["max_preferences_per_gender"] = 1

    config = parse_election_config(data)
    layout = build_ballot_layout(config, 0)

    assert layout.max_preferences == 2
    assert layout.max_preferences_per_gender == 1


def test_layout_rejects_unknown_district():
    """
    L'indice della circoscrizione deve esistere.
    """

    config = parse_election_config(small_config_data())

    with pytest.raises(ValueError):
        build_ballot_layout(config, 1)
