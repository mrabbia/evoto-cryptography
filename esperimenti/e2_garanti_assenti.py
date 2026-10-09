"""
Esperimento E2: garanti assenti.

Mostra le due proprietà della decifratura a soglia
(specifica condivisa docs/spec_f1.md, sezioni 23, 24 e 50):

1. con 5 garanti e quorum 3, qualunque gruppo di almeno 3 garanti
   decifra gli stessi totali: voti, seggi ed eletti coincidono con il
   conteggio in chiaro e il verificatore indipendente accetta il
   registro; con 2 soli garanti la decifratura viene rifiutata;
2. meno di quorum share non rivelano nulla sul segreto: nel gruppo
   didattico contiamo, per ogni possibile segreto, quanti polinomi
   sono compatibili con le share note.

Uso:
    uv run python -m esperimenti.e2_garanti_assenti
    uv run python -m esperimenti.e2_garanti_assenti --gruppo demo --elettori 10

La seconda parte usa sempre il gruppo didattico: enumerare i polinomi
è possibile solo con un q piccolo.
"""

import argparse
from collections import Counter
from dataclasses import dataclass, replace
from itertools import combinations, product
from pathlib import Path
import time

from evoto.configurazione import (
    ElectionConfig,
    load_election_config,
)
from evoto.decifratura import lagrange_coefficient
from evoto.garanti import run_key_ceremony
from evoto.gruppo import (
    DEMO_PARAMS,
    TEST_PARAMS,
    GroupParameters,
    mod_pow,
)
from evoto.registro import public_registry_to_json
from evoto.scrutinio import run_scrutiny
from evoto.simulazione import (
    SimulationReport,
    simulate_election,
)
from evoto.urna import (
    DistrictResult,
    decrypt_district_tally,
)
from verifica.verifica import verify_public_registry


DEFAULT_CONFIG = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "elezione_esempio.json"
)

# Stessi pesi di demo.py: la Coalizione Alfa supera la soglia del premio.
EXAMPLE_WEIGHTS = (22, 14, 12, 9, 16, 11, 7, 6)

GROUPS = {
    "didattico": TEST_PARAMS,
    "demo": DEMO_PARAMS,
}


@dataclass(frozen=True)
class SubsetOutcome:
    """
    Esito della decifratura con un gruppo di garanti presenti.

    same_totals: i totali decifrati coincidono con il conteggio in chiaro.
    same_scrutiny: seggi ed eletti coincidono con quelli del conteggio
    in chiaro.
    registry_verified: esito complessivo del verificatore indipendente
    sul registro pubblicato con queste share, oppure None se la
    verifica non è stata richiesta.
    """

    present_guardians: tuple[int, ...]
    same_totals: bool
    same_scrutiny: bool
    registry_verified: bool | None


@dataclass(frozen=True)
class AbsentGuardiansReport:
    """
    Risultato della prima parte dell'esperimento.

    outcomes contiene un esito per ogni gruppo di almeno quorum garanti.
    below_quorum_subsets è il numero di gruppi con quorum - 1 garanti;
    rejected_below_quorum quanti di questi sono stati rifiutati.
    """

    guardian_count: int
    quorum: int
    ballot_count: int
    outcomes: tuple[SubsetOutcome, ...]
    below_quorum_subsets: int
    rejected_below_quorum: int


@dataclass(frozen=True)
class SecrecyRow:
    """
    Riga della seconda parte dell'esperimento.

    known_guardians: garanti di cui si conosce la share.
    compatible_secrets: quanti segreti sono compatibili con quelle share.
    polynomials_per_secret: i valori distinti del numero di polinomi
    compatibili con ciascun segreto. Un solo valore significa che tutti
    i segreti sono ugualmente possibili.
    """

    known_guardians: tuple[int, ...]
    compatible_secrets: int
    polynomials_per_secret: tuple[int, ...]


@dataclass(frozen=True)
class SecrecyReport:
    """
    Risultato della seconda parte dell'esperimento.

    full_matches_key: il segreto interpolato da quorum share soddisfa
    g^s = K.
    forced_matches_key: il segreto interpolato forzando quorum - 1
    share soddisfa g^s' = K (atteso: no).
    """

    guardian_count: int
    quorum: int
    q: int
    rows: tuple[SecrecyRow, ...]
    full_matches_key: bool
    forced_matches_key: bool


def quorum_subsets(
    guardian_count: int,
    quorum: int,
) -> tuple[tuple[int, ...], ...]:
    """
    Elenca tutti i gruppi di garanti che raggiungono il quorum.

    I gruppi sono ordinati per numero di garanti e poi in ordine
    lessicografico. Con 5 garanti e quorum 3 sono
        C(5, 3) + C(5, 4) + C(5, 5) = 10 + 5 + 1 = 16.
    """

    if not 1 <= quorum <= guardian_count:
        raise ValueError(
            "Il quorum deve essere compreso tra 1 e il numero di garanti."
        )

    indices = range(1, guardian_count + 1)

    return tuple(
        subset
        for size in range(quorum, guardian_count + 1)
        for subset in combinations(indices, size)
    )


def decrypt_with_guardians(
    report: SimulationReport,
    present_guardians: tuple[int, ...],
    quorum: int,
    params: GroupParameters,
) -> tuple[DistrictResult, ...]:
    """
    Decifra di nuovo i totali cifrati della simulazione con un altro
    gruppo di garanti presenti.

    I totali cifrati sono gli stessi pubblicati sulla bacheca: cambiano
    soltanto le share di decifratura e i coefficienti di Lagrange.
    """

    return tuple(
        decrypt_district_tally(
            tally=tally,
            secret_shares=report.ceremony.secret_shares,
            present_guardians=present_guardians,
            records=report.ceremony.records,
            quorum=quorum,
            params=params,
            extended_base_hash=report.ceremony.extended_base_hash,
        )
        for tally in report.tallies
    )


def same_totals(
    first: tuple[DistrictResult, ...],
    second: tuple[DistrictResult, ...],
) -> bool:
    """
    Confronta i totali in chiaro di due risultati per circoscrizione.

    Le share di decifratura non vengono confrontate: con garanti
    diversi sono diverse per costruzione.
    """

    if len(first) != len(second):
        return False

    return all(
        (
            a.district_index,
            a.ballot_count,
            a.list_votes,
            a.blank_votes,
            a.preference_votes,
        )
        == (
            b.district_index,
            b.ballot_count,
            b.list_votes,
            b.blank_votes,
            b.preference_votes,
        )
        for a, b in zip(first, second, strict=True)
    )


def run_absent_guardians_experiment(
    config: ElectionConfig,
    voters_per_district: int,
    guardian_count: int,
    quorum: int,
    params: GroupParameters,
    seed: int,
    list_weights: tuple[float, ...] | None = None,
    verify_registry: bool = True,
) -> AbsentGuardiansReport:
    """
    Prima parte dell'esperimento: stesso risultato con garanti assenti.

    Si esegue una sola elezione simulata; poi i suoi totali cifrati
    vengono decifrati con ogni gruppo di almeno quorum garanti e il
    risultato viene confrontato con il conteggio in chiaro.

    Con verify_registry il registro pubblico di ogni gruppo viene
    passato al verificatore indipendente, che ricontrolla le prove
    Chaum-Pedersen delle share e la combinazione di Lagrange (V6, V7)
    e lo scrutinio (V8).

    Infine si prova a decifrare con ogni gruppo di quorum - 1 garanti:
    la decifratura deve essere rifiutata.
    """

    report = simulate_election(
        config=config,
        voters_per_district=voters_per_district,
        guardian_count=guardian_count,
        quorum=quorum,
        present_guardians=tuple(range(1, quorum + 1)),
        params=params,
        seed=seed,
        list_weights=list_weights,
    )

    outcomes = []

    for subset in quorum_subsets(guardian_count, quorum):
        results = decrypt_with_guardians(
            report,
            subset,
            quorum,
            params,
        )

        scrutiny = run_scrutiny(
            config,
            results,
        )

        verified = None

        if verify_registry:
            subset_report = replace(
                report,
                results=results,
                scrutiny=scrutiny,
            )

            verdict = verify_public_registry(
                public_registry_to_json(
                    subset_report,
                    params,
                )
            )

            verified = verdict["overall"]

        outcomes.append(
            SubsetOutcome(
                present_guardians=subset,
                same_totals=same_totals(
                    results,
                    report.plaintext_results,
                ),
                same_scrutiny=scrutiny == report.plaintext_scrutiny,
                registry_verified=verified,
            )
        )

    below_quorum = (
        tuple(combinations(range(1, guardian_count + 1), quorum - 1))
        if quorum > 1
        else ()
    )

    rejected = 0

    for subset in below_quorum:
        try:
            decrypt_with_guardians(
                report,
                subset,
                quorum,
                params,
            )
        except ValueError:
            rejected += 1

    return AbsentGuardiansReport(
        guardian_count=guardian_count,
        quorum=quorum,
        ballot_count=sum(
            result.ballot_count
            for result in report.results
        ),
        outcomes=tuple(outcomes),
        below_quorum_subsets=len(below_quorum),
        rejected_below_quorum=rejected,
    )


def count_compatible_polynomials(
    known_shares: dict[int, int],
    quorum: int,
    q: int,
) -> Counter[int]:
    """
    Conta, per ogni possibile segreto, i polinomi compatibili con le
    share note.

    Il polinomio della cerimonia ha grado quorum - 1:

        S(x) = a_0 + a_1 x + ... + a_(k-1) x^(k-1) mod q

    e il segreto è a_0 = S(0). Per ogni scelta di (a_1, ..., a_(k-1))
    la prima share fissa a_0; il polinomio è compatibile se passa anche
    per tutte le altre share note.

    Il risultato associa a ogni segreto il numero di polinomi
    compatibili. Con m < quorum share note ogni segreto ha esattamente
    q^(k-1-m) polinomi: chi conosce quelle share non ha alcuna
    informazione sul segreto. Con quorum share resta un solo polinomio,
    quindi un solo segreto.

    Si enumerano q^(k-1) polinomi: serve un q piccolo, come quello del
    gruppo didattico (1289^2, circa 1,7 milioni, per quorum 3).
    """

    if not known_shares:
        raise ValueError("Serve almeno una share nota.")

    if quorum < 1:
        raise ValueError("Il quorum deve essere almeno 1.")

    for index in known_shares:
        if not 1 <= index < q:
            raise ValueError(
                "Gli indici dei garanti devono essere compresi tra 1 e q - 1."
            )

    indices = sorted(known_shares)
    first = indices[0]
    others = indices[1:]

    # Potenze l^j mod q per j = 1, ..., k - 1, calcolate una volta sola.
    powers = {
        index: tuple(
            pow(index, exponent, q)
            for exponent in range(1, quorum)
        )
        for index in indices
    }

    counts: Counter[int] = Counter()

    for coefficients in product(range(q), repeat=quorum - 1):
        tail = sum(
            coefficient * power
            for coefficient, power in zip(
                coefficients,
                powers[first],
                strict=True,
            )
        )

        secret = (known_shares[first] - tail) % q

        compatible = all(
            (
                secret
                + sum(
                    coefficient * power
                    for coefficient, power in zip(
                        coefficients,
                        powers[index],
                        strict=True,
                    )
                )
            )
            % q
            == known_shares[index]
            for index in others
        )

        if compatible:
            counts[secret] += 1

    return counts


def interpolate_secret(
    shares: dict[int, int],
    params: GroupParameters,
) -> int:
    """
    Ricostruisce S(0) dalle share indicate con i coefficienti di Lagrange.

        s = Σ λ_l s_l mod q

    È la stessa combinazione che la decifratura esegue all'esponente
    (M = ∏ M_l^(λ_l)), qui fatta in chiaro sulle share. La libreria non
    la usa mai: serve solo all'esperimento per mostrare che con meno di
    quorum share il risultato è un valore sbagliato.
    """

    if not shares:
        raise ValueError("Serve almeno una share.")

    indices = tuple(sorted(shares))

    return sum(
        lagrange_coefficient(index, indices, params) * shares[index]
        for index in indices
    ) % params.q


def run_secrecy_experiment(
    guardian_count: int,
    quorum: int,
    params: GroupParameters,
    election_id: int,
    coefficients: tuple[tuple[int, ...], ...] | None = None,
) -> SecrecyReport:
    """
    Seconda parte dell'esperimento: meno di quorum share non rivelano
    nulla sul segreto.

    Si esegue una cerimonia vera nel gruppo indicato, poi si considerano
    le share aggregate dei garanti 1, poi 1 e 2, fino a 1, ..., quorum,
    e per ciascun insieme si contano i segreti compatibili.

    Si controlla anche che:
    - con quorum share, Lagrange restituisca il segreto della chiave
      pubblica, cioè g^s = K;
    - forzando Lagrange con quorum - 1 share si ottenga un valore s'
      con g^s' diverso da K.

    coefficients permette di fissare i polinomi dei garanti nei test.

    Nota per la tesina: la proprietà è informativa per Shamir puro.
    Con gli impegni di Feldman il segreto è fissato pubblicamente da
    K = g^s, quindi la protezione diventa computazionale: ricavare s
    da K richiede un logaritmo discreto.
    """

    ceremony = run_key_ceremony(
        guardian_count=guardian_count,
        quorum=quorum,
        params=params,
        election_id=election_id,
        coefficients=coefficients,
    )

    shares = ceremony.secret_shares

    rows = []

    for known_count in range(1, quorum + 1):
        known = {
            index: shares[index]
            for index in range(1, known_count + 1)
        }

        counts = count_compatible_polynomials(
            known,
            quorum,
            params.q,
        )

        rows.append(
            SecrecyRow(
                known_guardians=tuple(known),
                compatible_secrets=len(counts),
                polynomials_per_secret=tuple(sorted(set(counts.values()))),
            )
        )

    full_secret = interpolate_secret(
        {
            index: shares[index]
            for index in range(1, quorum + 1)
        },
        params,
    )

    full_matches = (
        mod_pow(params.g, full_secret, params.p)
        == ceremony.joint_public_key
    )

    forced_matches = False

    if quorum > 1:
        forced_secret = interpolate_secret(
            {
                index: shares[index]
                for index in range(1, quorum)
            },
            params,
        )

        forced_matches = (
            mod_pow(params.g, forced_secret, params.p)
            == ceremony.joint_public_key
        )

    return SecrecyReport(
        guardian_count=guardian_count,
        quorum=quorum,
        q=params.q,
        rows=tuple(rows),
        full_matches_key=full_matches,
        forced_matches_key=forced_matches,
    )


def parse_arguments() -> argparse.Namespace:
    """
    Legge le opzioni della riga di comando.
    """

    parser = argparse.ArgumentParser(
        description="Esperimento E2: garanti assenti.",
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
        "--seme",
        type=int,
        default=2026,
        help="seme delle scelte casuali degli elettori",
    )

    parser.add_argument(
        "--gruppo",
        choices=tuple(GROUPS),
        default="didattico",
        help="gruppo della prima parte (default didattico)",
    )

    parser.add_argument(
        "--senza-verificatore",
        action="store_true",
        help="non eseguire il verificatore su ogni registro",
    )

    return parser.parse_args()


def main() -> None:
    """
    Esegue l'esperimento e stampa il resoconto.
    """

    arguments = parse_arguments()

    config = load_election_config(arguments.config)
    params = GROUPS[arguments.gruppo]

    weights = (
        EXAMPLE_WEIGHTS
        if len(config.list_names) == len(EXAMPLE_WEIGHTS)
        else None
    )

    print("\nEsperimento E2: garanti assenti")
    print("===============================")

    start = time.perf_counter()

    absent = run_absent_guardians_experiment(
        config=config,
        voters_per_district=arguments.elettori,
        guardian_count=arguments.garanti,
        quorum=arguments.quorum,
        params=params,
        seed=arguments.seme,
        list_weights=weights,
        verify_registry=not arguments.senza_verificatore,
    )

    elapsed = time.perf_counter() - start

    print(
        f"\n{absent.guardian_count} garanti, quorum {absent.quorum}, "
        f"{absent.ballot_count} schede depositate, "
        f"gruppo {arguments.gruppo} (p da {params.p.bit_length()} bit)."
    )

    print(
        "\n  Garanti presenti   Totali     Seggi ed eletti   Verificatore"
    )

    def outcome(same: bool) -> str:
        return "uguali" if same else "DIVERSI"

    for item in absent.outcomes:
        present = ", ".join(map(str, item.present_guardians))

        if item.registry_verified is None:
            verdict = "-"
        elif item.registry_verified:
            verdict = "ELEZIONE VERIFICATA"
        else:
            verdict = "VERIFICA FALLITA"

        print(
            f"  {present:<18} {outcome(item.same_totals):<10} "
            f"{outcome(item.same_scrutiny):<17} {verdict}"
        )

    agreeing = sum(
        item.same_totals and item.same_scrutiny
        for item in absent.outcomes
    )

    print(
        f"\n{agreeing} gruppi su {len(absent.outcomes)} danno lo stesso "
        "risultato del conteggio in chiaro."
    )

    if absent.below_quorum_subsets:
        below = absent.quorum - 1
        word = "garante" if below == 1 else "garanti"

        print(
            f"Con {below} {word} la decifratura è rifiutata in "
            f"{absent.rejected_below_quorum} casi su "
            f"{absent.below_quorum_subsets}."
        )

    print(f"Tempo: {elapsed:.1f} s")

    secrecy = run_secrecy_experiment(
        guardian_count=arguments.garanti,
        quorum=arguments.quorum,
        params=TEST_PARAMS,
        election_id=config.election_id,
    )

    print(
        "\nMeno di quorum share non rivelano nulla "
        f"(gruppo didattico, q = {secrecy.q})"
    )

    print("\n  Share note        Segreti compatibili   Polinomi per segreto")

    for row in secrecy.rows:
        known = "{" + ", ".join(map(str, row.known_guardians)) + "}"
        per_secret = ", ".join(map(str, row.polynomials_per_secret))

        print(
            f"  {known:<17} {row.compatible_secrets:>5} su {secrecy.q:<11} "
            f"{per_secret}"
        )

    def answer(value: bool) -> str:
        return "sì" if value else "no"

    print(
        f"\nLagrange con {secrecy.quorum} share: g^s = K? "
        f"{answer(secrecy.full_matches_key)}"
    )

    if secrecy.quorum > 1:
        print(
            f"Lagrange forzato con {secrecy.quorum - 1} share: g^s' = K? "
            f"{answer(secrecy.forced_matches_key)}"
        )

    print()


if __name__ == "__main__":
    main()
