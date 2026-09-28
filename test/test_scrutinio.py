"""
Test unitari per evoto.scrutinio.

Ogni scenario usa 10 seggi, le liste A e B nella coalizione Alfa,
le liste C e D singole, e le regole della configurazione di esempio:
soglia di lista 3%, di coalizione 10%, premio al 42% con 55% dei seggi.

I risultati attesi sono calcolati a mano nelle docstring.
"""

import pytest

from evoto.configurazione import parse_election_config
from evoto.scrutinio import (
    distribute_with_caps,
    largest_remainder,
    run_scrutiny,
)
from evoto.urna import DistrictResult


def config_data(
    district_count: int = 1,
    candidate_counts: dict | None = None,
    default_count: int = 5,
) -> dict:
    """
    Configurazione di prova.

    candidate_counts permette di cambiare il numero di candidati
    di una lista in una circoscrizione: {(d, "Lista A"): 2}.
    Di default ogni lista ha capolista e quattro candidati.
    """

    candidate_counts = candidate_counts or {}
    list_names = ("Lista A", "Lista B", "Lista C", "Lista D")
    genders = ("M", "F", "M", "F", "M", "F", "M")

    districts = []

    for district_index in range(district_count):
        candidates = {}

        for list_name in list_names:
            count = candidate_counts.get(
                (district_index, list_name),
                default_count,
            )

            candidates[list_name] = [
                {
                    "name": f"{list_name[-1]}{district_index}-{position}",
                    "gender": genders[position],
                }
                for position in range(count)
            ]

        districts.append(
            {
                "name": f"Circoscrizione {district_index}",
                "candidates": candidates,
            }
        )

    return {
        "name": "Test scrutinio",
        "election_id": 1,
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
            {"name": "Lista D", "coalition": None},
        ],
        "districts": districts,
    }


def result(
    district_index: int,
    list_votes: tuple[int, ...],
    preference_votes: tuple[int, ...] | None = None,
    blank_votes: int = 0,
    preference_count: int = 16,
) -> DistrictResult:
    """
    Risultato in chiaro di una circoscrizione, senza share.
    """

    if preference_votes is None:
        preference_votes = (0,) * preference_count

    return DistrictResult(
        district_index=district_index,
        ballot_count=sum(list_votes) + blank_votes,
        list_votes=list_votes,
        blank_votes=blank_votes,
        preference_votes=preference_votes,
        decryption_shares=(),
    )


def scrutiny_single_district(list_votes: tuple[int, ...]):
    """
    Scrutinio con una sola circoscrizione.

    Ogni lista ha capolista e sei candidati, così anche una lista
    con 6 seggi ha abbastanza candidati da eleggere.
    """

    config = parse_election_config(config_data(default_count=7))

    return run_scrutiny(
        config,
        (result(0, list_votes, preference_count=24),),
    )


def test_largest_remainder_textbook_example():
    """
    Esempio classico: voti 47, 16, 15, 12, 6, 4 e 10 seggi.

    Quozienti 4,7 1,6 1,5 1,2 0,6 0,4: parti intere 4, 1, 1, 1, 0, 0.
    I tre seggi rimasti vanno ai resti 0,7 e ai due resti 0,6.
    """

    assert largest_remainder((47, 16, 15, 12, 6, 4), 10) == (
        5, 2, 1, 1, 1, 0,
    )


def test_largest_remainder_exact_quotas():
    """
    Quando i quozienti sono interi non ci sono resti.
    """

    assert largest_remainder((100, 80, 20), 10) == (5, 4, 1)


def test_largest_remainder_ties():
    """
    A parità di resto vince chi ha più voti; a parità di voti chi è primo.
    """

    assert largest_remainder((1, 1), 1) == (1, 0)
    assert largest_remainder((1, 3), 2) == (0, 2)


def test_largest_remainder_edge_cases():
    """
    Zero seggi è sempre possibile; zero voti con seggi no.
    """

    assert largest_remainder((5, 7), 0) == (0, 0)

    with pytest.raises(ValueError):
        largest_remainder((0, 0), 3)


def test_distribution_respects_caps():
    """
    Senza limiti sarebbe 2, 0, 1. La prima circoscrizione ha un solo
    candidato, quindi il seggio in più passa all'ultima.
    """

    assert distribute_with_caps((10, 0, 5), 3, (1, 5, 5)) == (1, 0, 2)


def test_distribution_without_enough_candidates():
    """
    Se i candidati non bastano per i seggi vinti il calcolo si ferma.
    """

    with pytest.raises(ValueError):
        distribute_with_caps((10, 10), 5, (2, 2))


def test_bonus_is_assigned():
    """
    A 300, B 150, C 350, D 200: Alfa ha 450 voti su 1000, cioè il 45%.

    Proporzionale fra Alfa 450, C 350, D 200: 4,5 3,5 2,0, cioè 5, 3, 2
    (il resto 0,5 va ad Alfa, che ha più voti di C).
    Il premio vale ceil(0,55 · 10) = 6 seggi, più dei 5 proporzionali:
    Alfa prende 6. C e D si dividono 4 seggi: 2,55 e 1,45, cioè 3 e 1.
    In Alfa: A 300 e B 150 si dividono 6 seggi esattamente in 4 e 2.
    """

    scrutiny = scrutiny_single_district((300, 150, 350, 200))

    names = tuple(competitor.name for competitor in scrutiny.competitors)

    assert scrutiny.valid_votes == 1000
    assert scrutiny.coalition_votes == (450,)
    assert names == ("Alfa", "Lista C", "Lista D")
    assert scrutiny.bonus_competitor == 0
    assert scrutiny.competitor_seats == (6, 3, 1)
    assert scrutiny.list_seats == (4, 2, 3, 1)


def test_no_bonus_below_the_threshold():
    """
    A 150, B 100, C 400, D 350: il primo è C con il 40%, sotto il 42%.

    Proporzionale fra Alfa 250, C 400, D 350: 2,5 4,0 3,5, cioè 2, 4, 3
    più un seggio al resto 0,5 di D, che ha più voti di Alfa.
    In Alfa i 2 seggi vanno 1 ad A e 1 a B (resti 0,2 e 0,8).
    """

    scrutiny = scrutiny_single_district((150, 100, 400, 350))

    assert scrutiny.bonus_competitor is None
    assert scrutiny.competitor_seats == (2, 4, 4)
    assert scrutiny.list_seats == (1, 1, 4, 4)


def test_no_bonus_when_not_needed():
    """
    A 500, B 200, C 200, D 100: Alfa ha il 70% e già 7 seggi
    proporzionali, più dei 6 del premio. Il premio non si applica.
    """

    scrutiny = scrutiny_single_district((500, 200, 200, 100))

    assert scrutiny.bonus_competitor is None
    assert scrutiny.competitor_seats == (7, 2, 1)


def test_no_bonus_with_a_tie_for_first_place():
    """
    A 200, B 150, C 350, D 300: Alfa e C hanno entrambi 350 voti.
    Con due primi a pari voti il premio non si assegna.
    """

    scrutiny = scrutiny_single_district((200, 150, 350, 300))

    assert scrutiny.bonus_competitor is None
    assert sum(scrutiny.competitor_seats) == 10


def test_coalition_below_threshold_leaves_its_lists_alone():
    """
    A 80, B 10, C 500, D 410: Alfa ha il 9%, sotto il 10%.

    A (8%) corre da sola, B (1%) è esclusa. Competitori A, C, D.
    C ha il 50%: proporzionale 1, 5, 4, premio 6 a C,
    e A e D si dividono 4 seggi: 0,65 e 3,35, cioè 1 e 3.
    """

    scrutiny = scrutiny_single_district((80, 10, 500, 410))

    names = tuple(competitor.name for competitor in scrutiny.competitors)

    assert names == ("Lista A", "Lista C", "Lista D")
    assert scrutiny.bonus_competitor == 1
    assert scrutiny.list_seats == (1, 0, 6, 3)


def test_list_below_threshold_counts_for_its_coalition():
    """
    A 400, B 20, C 380, D 200: B ha il 2% e non ha seggi, ma i suoi
    voti contano per Alfa, che arriva esattamente al 42%: premio.

    Alfa prende 6 seggi, tutti ad A. C e D si dividono 4 seggi:
    2,62 e 1,38, cioè 3 e 1.
    """

    scrutiny = scrutiny_single_district((400, 20, 380, 200))

    assert scrutiny.competitors[0].list_indices == (0,)
    assert scrutiny.bonus_competitor == 0
    assert scrutiny.list_seats == (6, 0, 3, 1)


def test_seats_are_distributed_among_districts_and_elected():
    """
    Due circoscrizioni. A ha 200 voti nella prima e 100 nella seconda:
    i suoi 4 seggi vanno 3 e 1 (quozienti 2,67 e 1,33).

    Nella prima circoscrizione le preferenze di A sono 10, 40, 40, 5:
    eletti il capolista, poi i candidati 2 e 3 (pari merito, vince
    l'ordine di lista). Nella seconda solo il capolista.
    """

    config = parse_election_config(config_data(district_count=2))

    preferences_first = (10, 40, 40, 5) + (0,) * 12

    results = (
        result(0, (200, 100, 175, 100), preferences_first),
        result(1, (100, 50, 175, 100)),
    )

    scrutiny = run_scrutiny(config, results)

    assert scrutiny.list_seats[0] == 4
    assert scrutiny.district_list_seats[0][0] == 3
    assert scrutiny.district_list_seats[1][0] == 1

    elected_a = [
        (candidate.district_index, candidate.position, candidate.preferences)
        for candidate in scrutiny.elected
        if candidate.list_index == 0
    ]

    assert elected_a == [
        (0, 0, 0),
        (0, 2, 40),
        (0, 3, 40),
        (1, 0, 0),
    ]


def test_district_cap_moves_seats_to_another_district():
    """
    Totali: A 400, B 100, C 400, D 400. Alfa ha 500 voti su 1300,
    sotto il 42%: proporzionale 3,85 3,08 3,08, cioè 4, 3, 3.
    In Alfa: A 3,2 e B 0,8, cioè 3 e 1.

    A ha 390 voti nella prima circoscrizione e 10 nella seconda:
    senza limiti i suoi 3 seggi andrebbero tutti nella prima (2,925
    e 0,075). Ma nella prima A ha solo capolista e un candidato:
    ne restano 2 e il terzo passa alla seconda.
    """

    config = parse_election_config(
        config_data(
            district_count=2,
            candidate_counts={(0, "Lista A"): 2},
        )
    )

    results = (
        result(0, (390, 50, 200, 150), preference_count=13),
        result(1, (10, 50, 200, 250)),
    )

    scrutiny = run_scrutiny(config, results)

    assert scrutiny.bonus_competitor is None
    assert scrutiny.list_seats == (3, 1, 3, 3)
    assert scrutiny.district_list_seats[0][0] == 2
    assert scrutiny.district_list_seats[1][0] == 1


def test_list_without_votes_never_competes():
    """
    Anche con soglia 0% una lista senza voti non entra nel riparto.
    """

    data = config_data(default_count=7)
    data["rules"]["list_threshold_percent"] = 0
    data["rules"]["coalition_threshold_percent"] = 0

    config = parse_election_config(data)

    scrutiny = run_scrutiny(
        config,
        (result(0, (300, 150, 550, 0), preference_count=24),),
    )

    names = tuple(competitor.name for competitor in scrutiny.competitors)

    assert names == ("Alfa", "Lista C")
    assert scrutiny.list_seats[3] == 0


def test_every_seat_has_one_elected_candidate():
    """
    Il numero di eletti coincide con i seggi e nessuno è eletto due volte.
    """

    scrutiny = scrutiny_single_district((300, 150, 350, 200))

    names = [candidate.name for candidate in scrutiny.elected]

    assert len(names) == 10
    assert len(set(names)) == 10


def test_blank_votes_are_not_valid_votes():
    """
    Le schede bianche sono contate a parte e non pesano sulle soglie.
    """

    config = parse_election_config(config_data())

    scrutiny = run_scrutiny(
        config,
        (result(0, (300, 150, 350, 200), blank_votes=500),),
    )

    assert scrutiny.blank_votes == 500
    assert scrutiny.valid_votes == 1000
    assert scrutiny.bonus_competitor == 0


def test_results_must_match_the_configuration():
    """
    Serve un risultato per circoscrizione, con le dimensioni giuste.
    """

    config = parse_election_config(config_data(district_count=2))

    with pytest.raises(ValueError):
        run_scrutiny(config, (result(0, (1, 1, 1, 1)),))

    with pytest.raises(ValueError):
        run_scrutiny(
            config,
            (result(1, (1, 1, 1, 1)), result(0, (1, 1, 1, 1))),
        )

    with pytest.raises(ValueError):
        run_scrutiny(
            config,
            (result(0, (1, 1, 1)), result(1, (1, 1, 1, 1))),
        )


def test_scrutiny_without_valid_votes():
    """
    Con sole schede bianche non c'è nulla da ripartire.
    """

    config = parse_election_config(config_data())

    with pytest.raises(ValueError):
        run_scrutiny(config, (result(0, (0, 0, 0, 0), blank_votes=5),))
