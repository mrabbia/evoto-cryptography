"""
Elezione simulata del progetto evoto (esperimento E1).

Questo modulo esegue un'elezione completa con elettori simulati:
1. cerimonia delle chiavi;
2. voto con scelte casuali, schede sprecate per la sfida di Benaloh
   e deposito sulla bacheca;
3. controllo della catena dei codici;
4. conteggio omomorfico e decifratura a soglia per circoscrizione;
5. scrutinio.

Accanto al percorso cifrato tiene un conteggio in chiaro delle stesse
scelte: i due risultati devono coincidere.

Lo usano demo.py e il test d'integrazione dell'elezione politica.
"""

from dataclasses import dataclass
import random
import time

from evoto.configurazione import (
    ElectionConfig,
    build_ballot_layout,
)
from evoto.garanti import (
    KeyCeremony,
    run_key_ceremony,
)
from evoto.gruppo import GroupParameters
from evoto.scheda import BallotLayout
from evoto.scrutinio import (
    ScrutinyResult,
    run_scrutiny,
)
from evoto.urna import (
    BulletinBoard,
    DistrictResult,
    DistrictTally,
    cast_voter_ballot,
    create_bulletin_board,
    create_voter_roll,
    decrypt_district_tally,
    spoil_ballot,
    tally_district,
    verify_board_chain,
)
from evoto.voto import (
    VoterChoice,
    choice_to_plaintexts,
    prepare_ballot,
)


@dataclass(frozen=True)
class SimulationReport:
    """
    Risultato completo di una simulazione.

    tallies contiene i totali cifrati pubblici di ogni circoscrizione.
    results e scrutiny vengono dal percorso cifrato;
    plaintext_results e plaintext_scrutiny dal conteggio in chiaro.
    timings contiene i tempi delle fasi, in secondi.
    """

    config: ElectionConfig
    ceremony: KeyCeremony
    board: BulletinBoard
    board_is_valid: bool
    spoiled_count: int
    tallies: tuple[DistrictTally, ...]
    results: tuple[DistrictResult, ...]
    plaintext_results: tuple[DistrictResult, ...]
    scrutiny: ScrutinyResult
    plaintext_scrutiny: ScrutinyResult
    timings: dict[str, float]


def random_choice(
    rng: random.Random,
    layout: BallotLayout,
    list_weights: tuple[float, ...],
    blank_probability: float,
    max_preferences: int,
    max_preferences_per_gender: int,
) -> VoterChoice:
    """
    Genera una scelta casuale ma valida.

    Con probabilità blank_probability la scheda è bianca; altrimenti
    si sceglie una lista secondo i pesi e da zero a max_preferences
    preferenze nella stessa lista, rispettando il vincolo di genere.
    Ogni tanto la lista non viene segnata e resta implicita nelle
    preferenze, come ammette la scheda.
    """

    if rng.random() < blank_probability:
        return VoterChoice(list_index=None)

    list_index = rng.choices(
        range(layout.list_count),
        weights=list_weights,
    )[0]

    boxes = [
        index
        for index, metadata in enumerate(layout.preference_metadata)
        if metadata.list_index == list_index
    ]

    rng.shuffle(boxes)

    wanted = rng.randint(0, max_preferences)
    chosen: list[int] = []
    per_gender: dict[str, int] = {}

    for box in boxes:
        if len(chosen) == wanted:
            break

        gender = layout.preference_metadata[box].gender

        if per_gender.get(gender, 0) < max_preferences_per_gender:
            chosen.append(box)
            per_gender[gender] = per_gender.get(gender, 0) + 1

    preferences = tuple(sorted(chosen))

    if preferences and rng.random() < 0.1:
        return VoterChoice(list_index=None, preferences=preferences)

    return VoterChoice(list_index=list_index, preferences=preferences)


def plaintext_count(
    layout: BallotLayout,
    district_index: int,
    choices: list[VoterChoice],
) -> DistrictResult:
    """
    Conta in chiaro le scelte di una circoscrizione.

    È il termine di confronto dell'esperimento: non usa nessuna
    primitiva crittografica.
    """

    list_votes = [0] * layout.list_count
    preference_votes = [0] * len(layout.preference_metadata)
    blank_votes = 0

    for choice in choices:
        lists, blank, preferences = choice_to_plaintexts(layout, choice)

        blank_votes += blank

        for index, bit in enumerate(lists):
            list_votes[index] += bit

        for index, bit in enumerate(preferences):
            preference_votes[index] += bit

    return DistrictResult(
        district_index=district_index,
        ballot_count=len(choices),
        list_votes=tuple(list_votes),
        blank_votes=blank_votes,
        preference_votes=tuple(preference_votes),
        decryption_shares=(),
    )


def simulate_election(
    config: ElectionConfig,
    voters_per_district: int,
    guardian_count: int,
    quorum: int,
    present_guardians: tuple[int, ...],
    params: GroupParameters,
    seed: int,
    list_weights: tuple[float, ...] | None = None,
    blank_probability: float = 0.03,
    spoil_probability: float = 0.05,
) -> SimulationReport:
    """
    Esegue un'elezione completa con elettori simulati.

    seed rende riproducibili le scelte degli elettori; i nonce della
    crittografia restano casuali. Un elettore su venti circa spreca una
    scheda prima di votare, per controllare il dispositivo.
    """

    if list_weights is None:
        list_weights = tuple(
            1.0
            for _ in config.list_names
        )

    if len(list_weights) != len(config.list_names):
        raise ValueError(
            "Serve un peso per ogni lista."
        )

    rng = random.Random(seed)
    timings: dict[str, float] = {}

    # Fase 1: cerimonia delle chiavi
    start = time.perf_counter()

    ceremony = run_key_ceremony(
        guardian_count=guardian_count,
        quorum=quorum,
        params=params,
        election_id=config.election_id,
    )

    timings["cerimonia"] = (
        time.perf_counter() - start
    )

    public_key = ceremony.joint_public_key
    context = ceremony.extended_base_hash

    layouts = tuple(
        build_ballot_layout(
            config,
            district_index,
        )
        for district_index in range(
            len(config.districts)
        )
    )

    voters = {
        f"elettore-{district_index}-{number:04d}": (
            district_index
        )
        for district_index in range(
            len(config.districts)
        )
        for number in range(
            voters_per_district
        )
    }

    roll = create_voter_roll(voters)
    board = create_bulletin_board(
        context,
        params,
    )

    choices: list[list[VoterChoice]] = [
        []
        for _ in config.districts
    ]

    spoiled_count = 0

    # Fasi 2 e 3: voto e bacheca
    start = time.perf_counter()

    for voter_id, district_index in voters.items():
        layout = layouts[district_index]

        choice = random_choice(
            rng,
            layout,
            list_weights,
            blank_probability,
            config.rules.max_preferences,
            config.rules.max_preferences_per_gender,
        )

        if rng.random() < spoil_probability:
            challenged = prepare_ballot(
                layout,
                district_index,
                choice,
                public_key,
                params,
                context,
            )

            board = spoil_ballot(
                board=board,
                district_index=district_index,
                layout=layout,
                ballot=challenged.ballot,
                proofs=challenged.proofs,
                witness=challenged.witness,
                public_key=public_key,
                params=params,
            )

            spoiled_count += 1

        prepared = prepare_ballot(
            layout,
            district_index,
            choice,
            public_key,
            params,
            context,
        )

        board, roll = cast_voter_ballot(
            board=board,
            roll=roll,
            voter_id=voter_id,
            district_index=district_index,
            layout=layout,
            ballot=prepared.ballot,
            proofs=prepared.proofs,
            public_key=public_key,
            params=params,
        )

        choices[district_index].append(
            choice
        )

    timings["voto"] = (
        time.perf_counter() - start
    )

    # Controllo V4 della catena dei codici
    start = time.perf_counter()

    board_is_valid = verify_board_chain(
        board,
        params,
    )

    timings["catena"] = (
        time.perf_counter() - start
    )

    # Fasi 4 e 5: conteggio e decifratura per circoscrizione
    start = time.perf_counter()

    tallies = tuple(
        tally_district(
            board=board,
            district_index=district_index,
            layout=layout,
            params=params,
        )
        for district_index, layout in enumerate(
            layouts
        )
    )

    results = tuple(
        decrypt_district_tally(
            tally=tally,
            secret_shares=ceremony.secret_shares,
            present_guardians=present_guardians,
            records=ceremony.records,
            quorum=quorum,
            params=params,
            extended_base_hash=context,
        )
        for tally in tallies
    )

    timings["decifratura"] = (
        time.perf_counter() - start
    )

    # Fase 6: scrutinio sul risultato cifrato
    # e sul conteggio in chiaro
    start = time.perf_counter()

    scrutiny = run_scrutiny(
        config,
        results,
    )

    timings["scrutinio"] = (
        time.perf_counter() - start
    )

    plaintext_results = tuple(
        plaintext_count(
            layout,
            district_index,
            choices[district_index],
        )
        for district_index, layout in enumerate(
            layouts
        )
    )

    plaintext_scrutiny = run_scrutiny(
        config,
        plaintext_results,
    )

    return SimulationReport(
        config=config,
        ceremony=ceremony,
        board=board,
        board_is_valid=board_is_valid,
        spoiled_count=spoiled_count,
        tallies=tallies,
        results=results,
        plaintext_results=plaintext_results,
        scrutiny=scrutiny,
        plaintext_scrutiny=plaintext_scrutiny,
        timings=timings,
    )
