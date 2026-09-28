"""
Elezione politica simulata da riga di comando (esperimento E1).

Esegue un'elezione completa sulla configurazione indicata, con elettori
che scelgono a caso, e confronta il risultato cifrato con un conteggio
in chiaro delle stesse scelte.

Uso:
    uv run python demo.py
    uv run python demo.py --elettori 200 --seme 7 --presenti 2,4,5

Il gruppo usato è quello didattico: va bene per provare, non è sicuro.
"""

import argparse
from pathlib import Path

from evoto.configurazione import load_election_config
from evoto.gruppo import TEST_PARAMS
from evoto.simulazione import simulate_election


DEFAULT_CONFIG = (
    Path(__file__).resolve().parent
    / "config"
    / "elezione_esempio.json"
)

# Pesi delle liste per la configurazione di esempio: la Coalizione Alfa
# (liste A, B, D) ha circa il 46% dei voti, così si vede il premio.
EXAMPLE_WEIGHTS = (22, 14, 12, 9, 16, 11, 7, 6)


def parse_arguments() -> argparse.Namespace:
    """
    Legge le opzioni della riga di comando.
    """

    parser = argparse.ArgumentParser(
        description="Elezione politica simulata con evoto.",
    )

    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="file JSON di configurazione dell'elezione",
    )

    parser.add_argument(
        "--elettori",
        type=int,
        default=100,
        help="elettori per circoscrizione (default 100)",
    )

    parser.add_argument(
        "--garanti",
        type=int,
        default=5,
        help="numero di garanti (default 5)",
    )

    parser.add_argument(
        "--quorum",
        type=int,
        default=3,
        help="garanti necessari per decifrare (default 3)",
    )

    parser.add_argument(
        "--presenti",
        default="1,3,5",
        help="garanti presenti allo spoglio, separati da virgole",
    )

    parser.add_argument(
        "--seme",
        type=int,
        default=2026,
        help="seme delle scelte casuali degli elettori",
    )

    return parser.parse_args()


def main() -> None:
    """
    Esegue la simulazione e stampa il resoconto.
    """

    arguments = parse_arguments()

    config = load_election_config(arguments.config)

    present = tuple(
        int(index)
        for index in arguments.presenti.split(",")
    )

    weights = (
        EXAMPLE_WEIGHTS
        if len(config.list_names) == len(EXAMPLE_WEIGHTS)
        else None
    )

    report = simulate_election(
        config=config,
        voters_per_district=arguments.elettori,
        guardian_count=arguments.garanti,
        quorum=arguments.quorum,
        present_guardians=present,
        params=TEST_PARAMS,
        seed=arguments.seme,
        list_weights=weights,
    )

    scrutiny = report.scrutiny
    cast = sum(result.ballot_count for result in report.results)

    print(f"\n{config.name}")
    print("=" * len(config.name))

    print(
        f"\nCerimonia: {arguments.garanti} garanti, quorum {arguments.quorum}. "
        f"Chiave pubblica K = {report.ceremony.joint_public_key}."
    )

    print(
        f"Voto: {cast} schede depositate, {report.spoiled_count} sprecate "
        "per controllare il dispositivo."
    )

    print(
        "Catena dei codici di tracciamento: "
        + ("valida." if report.board_is_valid else "NON VALIDA.")
    )

    print(f"Spoglio con i garanti {', '.join(map(str, present))}.")

    print("\nVoti per circoscrizione")

    for district, result in zip(config.districts, report.results, strict=True):
        votes = ", ".join(
            f"{name[-1]} {vote}"
            for name, vote in zip(config.list_names, result.list_votes, strict=True)
        )

        print(f"  {district.name:<8} {votes}, bianche {result.blank_votes}")

    print(
        f"\nVoti validi: {scrutiny.valid_votes}, "
        f"schede bianche: {scrutiny.blank_votes}"
    )

    for coalition, votes in zip(
        config.coalitions,
        scrutiny.coalition_votes,
        strict=True,
    ):
        share = 100 * votes / scrutiny.valid_votes
        print(f"  {coalition.name}: {votes} voti ({share:.1f}%)")

    print(f"\nRiparto di {config.seats} seggi")

    for index, (competitor, seats) in enumerate(
        zip(scrutiny.competitors, scrutiny.competitor_seats, strict=True)
    ):
        bonus = "  <- premio" if index == scrutiny.bonus_competitor else ""
        word = "seggio" if seats == 1 else "seggi"

        print(
            f"  {competitor.name:<16} {competitor.votes:>5} voti"
            f"  {seats:>3} {word}{bonus}"
        )

    print("\nSeggi per lista")

    for name, seats in zip(config.list_names, scrutiny.list_seats, strict=True):
        if seats:
            print(f"  {name}: {seats}")

    print("\nEletti")

    for candidate in scrutiny.elected:
        district = config.districts[candidate.district_index].name
        list_name = config.list_names[candidate.list_index]
        role = (
            "capolista"
            if candidate.position == 0
            else f"{candidate.preferences} preferenze"
        )

        print(f"  {district:<8} {list_name}  {candidate.name:<16} {role}")

    same_totals = all(
        (
            cipher.list_votes,
            cipher.blank_votes,
            cipher.preference_votes,
        )
        == (
            clear.list_votes,
            clear.blank_votes,
            clear.preference_votes,
        )
        for cipher, clear in zip(
            report.results,
            report.plaintext_results,
            strict=True,
        )
    )

    same_scrutiny = report.scrutiny == report.plaintext_scrutiny

    def outcome(same: bool) -> str:
        return "coincidono" if same else "DIVERSI"

    print("\nConfronto con il conteggio in chiaro")
    print(f"  totali per circoscrizione: {outcome(same_totals)}")
    print(f"  seggi ed eletti:           {outcome(same_scrutiny)}")

    print("\nTempi")

    for phase, seconds in report.timings.items():
        print(f"  {phase:<12} {seconds:.2f} s")

    print()


if __name__ == "__main__":
    main()
