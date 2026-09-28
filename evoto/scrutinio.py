"""
Scrutinio del progetto evoto: dai totali in chiaro ai seggi e agli eletti.

Questo modulo contiene una versione semplificata e dichiarata della legge
elettorale, con tutti i numeri presi dalla configurazione:
- voti delle liste e delle coalizioni a livello nazionale;
- soglie di sbarramento per liste e coalizioni;
- premio di governabilità per chi supera la soglia prevista;
- riparto con il metodo dei quozienti interi e dei più alti resti;
- distribuzione dei seggi di ogni lista tra le circoscrizioni;
- eletti: prima il capolista, poi per numero di preferenze.

Tutto il calcolo parte da dati pubblici ed è deterministico: il
verificatore può rifarlo identico per il controllo V8.
Segue la specifica condivisa docs/spec_f1.md, sezione 46.
"""

from dataclasses import dataclass
from fractions import Fraction
import math

from evoto.configurazione import (
    ElectionConfig,
    ElectoralRules,
    preference_candidates,
)
from evoto.urna import DistrictResult


@dataclass(frozen=True)
class Competitor:
    """
    Soggetto che partecipa al riparto nazionale dei seggi.

    È una coalizione che ha superato le soglie, oppure una lista che
    corre da sola (perché non coalizzata o perché la sua coalizione
    non ha superato la soglia).

    list_indices: liste che possono ricevere seggi.
    votes: voti usati per il riparto.
    """

    name: str
    list_indices: tuple[int, ...]
    votes: int
    is_coalition: bool


@dataclass(frozen=True)
class ElectedCandidate:
    """
    Candidato eletto.

    position: posizione nella lista della circoscrizione;
    0 è il capolista, che non riceve preferenze.
    """

    district_index: int
    list_index: int
    name: str
    position: int
    preferences: int


@dataclass(frozen=True)
class ScrutinyResult:
    """
    Risultato completo dello scrutinio.

    competitor_seats[k] sono i seggi di competitors[k].
    bonus_competitor è l'indice del competitore che ha ricevuto
    il premio, oppure None se il premio non è stato assegnato.
    district_list_seats[d][p] sono i seggi della lista p
    nella circoscrizione d.
    """

    valid_votes: int
    blank_votes: int
    list_votes: tuple[int, ...]
    coalition_votes: tuple[int, ...]
    competitors: tuple[Competitor, ...]
    competitor_seats: tuple[int, ...]
    bonus_competitor: int | None
    list_seats: tuple[int, ...]
    district_list_seats: tuple[tuple[int, ...], ...]
    elected: tuple[ElectedCandidate, ...]


def largest_remainder(
    votes: tuple[int, ...],
    seats: int,
) -> tuple[int, ...]:
    """
    Ripartisce i seggi con i quozienti interi e i più alti resti.

    Ognuno riceve la parte intera di votes_i · seats / totale;
    i seggi rimasti vanno ai resti più alti.

    In caso di resti uguali vince chi ha più voti, e a parità di voti
    chi viene prima. Il calcolo è in interi, quindi esatto.
    """

    if seats < 0:
        raise ValueError("Il numero di seggi deve essere non negativo.")

    if any(vote < 0 for vote in votes):
        raise ValueError("I voti devono essere non negativi.")

    if seats == 0:
        return tuple(0 for _ in votes)

    total = sum(votes)

    if total == 0:
        raise ValueError("Non ci sono voti su cui ripartire i seggi.")

    allocation = [vote * seats // total for vote in votes]
    remainders = [vote * seats % total for vote in votes]

    order = sorted(
        range(len(votes)),
        key=lambda index: (-remainders[index], -votes[index], index),
    )

    for index in order[:seats - sum(allocation)]:
        allocation[index] += 1

    return tuple(allocation)


def distribute_with_caps(
    votes: tuple[int, ...],
    seats: int,
    caps: tuple[int, ...],
) -> tuple[int, ...]:
    """
    Ripartisce i seggi come largest_remainder, ma senza superare i limiti.

    Serve per distribuire i seggi di una lista tra le circoscrizioni:
    in una circoscrizione non si possono eleggere più candidati di
    quelli presenti. I seggi in eccesso passano alle circoscrizioni
    con posto, nell'ordine dei resti più alti.
    """

    if len(votes) != len(caps):
        raise ValueError("Serve un limite per ogni circoscrizione.")

    if seats > sum(caps):
        raise ValueError("Non ci sono abbastanza candidati per i seggi vinti.")

    if seats == 0:
        return tuple(0 for _ in votes)

    total = sum(votes)

    if total == 0:
        raise ValueError("Non ci sono voti su cui ripartire i seggi.")

    remainders = [vote * seats % total for vote in votes]

    allocation = [
        min(vote * seats // total, cap)
        for vote, cap in zip(votes, caps, strict=True)
    ]

    order = sorted(
        range(len(votes)),
        key=lambda index: (-remainders[index], -votes[index], index),
    )

    remaining = seats - sum(allocation)

    # Ogni giro dà al massimo un seggio a ogni circoscrizione con posto,
    # nell'ordine dei resti: senza limiti coincide con i più alti resti.
    while remaining > 0:
        for index in order:
            if remaining == 0:
                break

            if allocation[index] < caps[index]:
                allocation[index] += 1
                remaining -= 1

    return tuple(allocation)


def _allocate_competitor_seats(
    votes: tuple[int, ...],
    valid_votes: int,
    seats: int,
    rules: ElectoralRules,
) -> tuple[tuple[int, ...], int | None]:
    """
    Ripartisce i seggi tra i competitori, con l'eventuale premio.

    Il premio va al competitore più votato se da solo supera la soglia
    del premio, calcolata sui voti validi nazionali. Riceve almeno
    ceil(quota del premio · seggi) seggi; gli altri si dividono i
    rimanenti in proporzione ai voti.

    Se due competitori sono primi a pari voti, il premio non si assegna.
    """

    proportional = largest_remainder(votes, seats)

    best = max(votes)
    leaders = [index for index, vote in enumerate(votes) if vote == best]

    if len(leaders) != 1:
        return proportional, None

    winner = leaders[0]

    if Fraction(votes[winner]) < rules.bonus_threshold * valid_votes:
        return proportional, None

    bonus_seats = math.ceil(rules.bonus_seat_share * seats)

    # Chi ha già abbastanza seggi con il proporzionale non ha bisogno
    # del premio.
    if proportional[winner] >= bonus_seats:
        return proportional, None

    others = tuple(
        index
        for index in range(len(votes))
        if index != winner
    )

    if not others:
        return proportional, None

    others_seats = largest_remainder(
        tuple(votes[index] for index in others),
        seats - bonus_seats,
    )

    allocation = [0] * len(votes)
    allocation[winner] = bonus_seats

    for index, seat_count in zip(others, others_seats, strict=True):
        allocation[index] = seat_count

    return tuple(allocation), winner


def _validate_results(
    config: ElectionConfig,
    results: tuple[DistrictResult, ...],
) -> None:
    """
    Controlla che ci sia un risultato per ogni circoscrizione,
    nell'ordine della configurazione e con le dimensioni giuste.
    """

    if len(results) != len(config.districts):
        raise ValueError("Serve un risultato per ogni circoscrizione.")

    for district_index, result in enumerate(results):
        if result.district_index != district_index:
            raise ValueError(
                "I risultati devono seguire l'ordine delle circoscrizioni."
            )

        if len(result.list_votes) != len(config.list_names):
            raise ValueError("Il numero di liste del risultato non è corretto.")

        expected = len(preference_candidates(config, district_index))

        if len(result.preference_votes) != expected:
            raise ValueError(
                "Il numero di preferenze del risultato non è corretto."
            )


def _admit_competitors(
    config: ElectionConfig,
    list_votes: tuple[int, ...],
    coalition_votes: tuple[int, ...],
    valid_votes: int,
) -> tuple[Competitor, ...]:
    """
    Applica le soglie di sbarramento.

    - Una coalizione è ammessa se supera la sua soglia e contiene almeno
      una lista sopra la soglia di lista; i voti di tutte le sue liste
      contano per la coalizione, ma solo le liste sopra soglia hanno seggi.
    - Una lista non coalizzata, o di una coalizione non ammessa, corre da
      sola se supera la soglia di lista.

    Una lista senza voti non è mai ammessa, anche con soglia 0%.

    Ordine: prima le coalizioni ammesse, poi le liste singole ammesse,
    ciascuna nell'ordine della configurazione.
    """

    rules = config.rules

    list_admitted = tuple(
        vote > 0
        and Fraction(vote) >= rules.list_threshold * valid_votes
        for vote in list_votes
    )

    competitors = []
    lists_in_admitted_coalitions = set()

    for coalition, votes in zip(config.coalitions, coalition_votes, strict=True):
        eligible = tuple(
            list_index
            for list_index in coalition.list_indices
            if list_admitted[list_index]
        )

        if (
            Fraction(votes) >= rules.coalition_threshold * valid_votes
            and eligible
        ):
            competitors.append(
                Competitor(
                    name=coalition.name,
                    list_indices=eligible,
                    votes=votes,
                    is_coalition=True,
                )
            )

            lists_in_admitted_coalitions.update(coalition.list_indices)

    for list_index, list_name in enumerate(config.list_names):
        if list_index in lists_in_admitted_coalitions:
            continue

        if list_admitted[list_index]:
            competitors.append(
                Competitor(
                    name=list_name,
                    list_indices=(list_index,),
                    votes=list_votes[list_index],
                    is_coalition=False,
                )
            )

    return tuple(competitors)


def _select_elected(
    config: ElectionConfig,
    results: tuple[DistrictResult, ...],
    district_list_seats: tuple[tuple[int, ...], ...],
) -> tuple[ElectedCandidate, ...]:
    """
    Sceglie gli eletti di ogni lista in ogni circoscrizione.

    Il primo seggio va al capolista bloccato; gli altri ai candidati
    con più preferenze. A parità di preferenze viene eletto chi è
    più in alto nella lista.
    """

    elected = []

    for district_index, district in enumerate(config.districts):
        preferences = {
            box: votes
            for box, votes in zip(
                preference_candidates(config, district_index),
                results[district_index].preference_votes,
                strict=True,
            )
        }

        for list_index, candidates in enumerate(district.candidates):
            seat_count = district_list_seats[district_index][list_index]

            if seat_count == 0:
                continue

            ranking = sorted(
                range(1, len(candidates)),
                key=lambda position: (
                    -preferences[(list_index, position)],
                    position,
                ),
            )

            positions = [0] + ranking[:seat_count - 1]

            for position in positions:
                elected.append(
                    ElectedCandidate(
                        district_index=district_index,
                        list_index=list_index,
                        name=candidates[position].name,
                        position=position,
                        preferences=(
                            0
                            if position == 0
                            else preferences[(list_index, position)]
                        ),
                    )
                )

    return tuple(elected)


def run_scrutiny(
    config: ElectionConfig,
    results: tuple[DistrictResult, ...],
) -> ScrutinyResult:
    """
    Esegue lo scrutinio completo a partire dai totali in chiaro.

    I passaggi sono:
    1. voti nazionali delle liste e delle coalizioni;
    2. soglie di sbarramento;
    3. riparto tra coalizioni e liste singole, con l'eventuale premio;
    4. riparto dei seggi di ogni coalizione tra le sue liste;
    5. distribuzione dei seggi di ogni lista tra le circoscrizioni;
    6. eletti.
    """

    _validate_results(config, results)

    list_count = len(config.list_names)

    list_votes = tuple(
        sum(result.list_votes[list_index] for result in results)
        for list_index in range(list_count)
    )

    blank_votes = sum(result.blank_votes for result in results)
    valid_votes = sum(list_votes)

    if valid_votes == 0:
        raise ValueError("Non ci sono voti validi per le liste.")

    coalition_votes = tuple(
        sum(list_votes[list_index] for list_index in coalition.list_indices)
        for coalition in config.coalitions
    )

    competitors = _admit_competitors(
        config,
        list_votes,
        coalition_votes,
        valid_votes,
    )

    if not competitors:
        raise ValueError("Nessuna lista o coalizione supera le soglie.")

    competitor_seats, bonus_competitor = _allocate_competitor_seats(
        tuple(competitor.votes for competitor in competitors),
        valid_votes,
        config.seats,
        config.rules,
    )

    list_seats = [0] * list_count

    for competitor, seat_count in zip(
        competitors,
        competitor_seats,
        strict=True,
    ):
        member_seats = largest_remainder(
            tuple(list_votes[index] for index in competitor.list_indices),
            seat_count,
        )

        for list_index, member_seat_count in zip(
            competitor.list_indices,
            member_seats,
            strict=True,
        ):
            list_seats[list_index] = member_seat_count

    district_count = len(config.districts)
    district_list_seats = [[0] * list_count for _ in range(district_count)]

    for list_index in range(list_count):
        if list_seats[list_index] == 0:
            continue

        allocation = distribute_with_caps(
            tuple(result.list_votes[list_index] for result in results),
            list_seats[list_index],
            tuple(
                len(district.candidates[list_index])
                for district in config.districts
            ),
        )

        for district_index, seat_count in enumerate(allocation):
            district_list_seats[district_index][list_index] = seat_count

    district_list_seats = tuple(
        tuple(row)
        for row in district_list_seats
    )

    elected = _select_elected(
        config,
        results,
        district_list_seats,
    )

    return ScrutinyResult(
        valid_votes=valid_votes,
        blank_votes=blank_votes,
        list_votes=list_votes,
        coalition_votes=coalition_votes,
        competitors=competitors,
        competitor_seats=competitor_seats,
        bonus_competitor=bonus_competitor,
        list_seats=tuple(list_seats),
        district_list_seats=district_list_seats,
        elected=elected,
    )
