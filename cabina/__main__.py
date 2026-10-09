"""
Avvia la cabina elettorale dimostrativa nel browser.

Uso:
    uv run python -m cabina
    uv run python -m cabina --gruppo didattico --elettori 100
    uv run python -m cabina --registro registro_demo.json

All'avvio vengono eseguite la cerimonia delle chiavi e il voto degli
elettori simulati; poi il server resta in ascolto solo sul computer
locale (127.0.0.1).
"""

import argparse
from pathlib import Path
import time

from cabina.app import create_app
from cabina.sessione import ElectionSession
from evoto.configurazione import load_election_config
from evoto.gruppo import (
    DEMO_PARAMS,
    TEST_PARAMS,
)


DEFAULT_CONFIG = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "elezione_esempio.json"
)

GROUPS = {
    "demo": DEMO_PARAMS,
    "didattico": TEST_PARAMS,
}


def parse_arguments() -> argparse.Namespace:
    """
    Legge le opzioni della riga di comando.
    """

    parser = argparse.ArgumentParser(
        description="Cabina elettorale e bacheca dimostrative di eVoto.",
    )

    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="file JSON di configurazione dell'elezione",
    )

    parser.add_argument(
        "--gruppo",
        choices=tuple(GROUPS),
        default="demo",
        help="demo (2048 bit, default) oppure didattico (veloce, non sicuro)",
    )

    parser.add_argument(
        "--elettori",
        type=int,
        default=10,
        help="elettori simulati per circoscrizione (default 10)",
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
        "--seme",
        type=int,
        default=2026,
        help="seme delle scelte degli elettori simulati",
    )

    parser.add_argument(
        "--porta",
        type=int,
        default=8000,
        help="porta del server locale (default 8000)",
    )

    parser.add_argument(
        "--registro",
        help="file in cui scrivere il registro pubblico alla chiusura",
    )

    return parser.parse_args()


def main() -> None:
    """
    Prepara l'elezione e avvia il server.
    """

    arguments = parse_arguments()

    config = load_election_config(arguments.config)
    params = GROUPS[arguments.gruppo]

    print(f"\n{config.name}")
    print(
        f"Gruppo {arguments.gruppo}: p da {params.p.bit_length()} bit. "
        f"Cerimonia con {arguments.garanti} garanti, quorum {arguments.quorum}."
    )

    election = ElectionSession(
        config=config,
        params=params,
        guardian_count=arguments.garanti,
        quorum=arguments.quorum,
    )

    start = time.perf_counter()

    def progress(done: int, total: int) -> None:
        if done == total or done % 10 == 0:
            print(f"  elettori simulati: {done}/{total}", flush=True)

    if arguments.elettori > 0:
        election.prefill(
            voters_per_district=arguments.elettori,
            seed=arguments.seme,
            progress=progress,
        )

    print(f"Pronto in {time.perf_counter() - start:.1f} s.")
    print(f"Apri http://127.0.0.1:{arguments.porta} nel browser (Ctrl+C per uscire).\n")

    app = create_app(
        election,
        registry_path=Path(arguments.registro) if arguments.registro else None,
    )

    app.run(
        host="127.0.0.1",
        port=arguments.porta,
        debug=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
