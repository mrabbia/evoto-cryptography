"""
Esperimento E5: costi di una scheda politica.

Misura dimensione e tempi per scheda al variare del numero di liste e
di candidati, nelle configurazioni della sezione 2.5 della proposta di
progetto, e li proietta su una circoscrizione
(specifica condivisa docs/spec_f1.md, sezione 50).

Per ogni configurazione si costruisce una scheda vera con prepare_ballot
e la si verifica con verify_ballot. Si misurano:
- numero di cifrati, di prove e di rami delle prove OR;
- dimensione in byte, con gli impegni delle prove (come nel nostro
  registro e in ElectionGuard) e in forma compatta (solo sfide e
  risposte: gli impegni si ricalcolano da sfida e risposta);
- numero di esponenziazioni modulari, per cifrare e per verificare;
- tempi di cifratura e di verifica.

Uso:
    uv run python -m esperimenti.e5_costi
    uv run python -m esperimenti.e5_costi --liste 2,10 --candidati 8 --csv e5.csv
    uv run python -m esperimenti.e5_costi --python-puro

Il gruppo da 4096 bit è quello standard di ElectionGuard (q = 2^256 - 189):
serve soltanto per le misure, la libreria usa DEMO_PARAMS.
"""

import argparse
from contextlib import ExitStack, contextmanager
import csv
from dataclasses import asdict, dataclass
import random
import statistics
import time
from collections.abc import Callable, Iterator
from unittest.mock import patch

import gmpy2

import evoto.decifratura
import evoto.elgamal
import evoto.garanti
import evoto.gruppo
import evoto.prove
from evoto.decifratura import (
    compute_decryption_share,
    decrypt_tally,
    verify_decryption_share,
)
from evoto.elgamal import encrypt
from evoto.garanti import (
    compute_verification_key,
    run_key_ceremony,
)
from evoto.gruppo import (
    DEMO_PARAMS,
    TEST_PARAMS,
    GroupParameters,
    mod_pow,
)
from evoto.scheda import (
    BallotLayout,
    BallotProofs,
    EncryptedBallot,
    PreferenceMetadata,
    verify_ballot,
)
from evoto.urna import aggregate_ciphertexts
from evoto.voto import (
    VoterChoice,
    prepare_ballot,
)


# Gruppo standard di ElectionGuard: p da 4096 bit, q = 2^256 - 189,
# g = 2^((p - 1) / q) mod p. Usato solo per confrontare i costi.
EG_4096_PARAMS = GroupParameters(
    p=int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "93C467E37DB0C7A4D1BE3F810152CB56"
        "A1CECC3AF65CC0190C03DF34709AFFBD"
        "8E4B59FA03A9F0EED0649CCB621057D1"
        "1056AE9132135A08E43B4673D74BAFEA"
        "58DEB878CC86D733DBE7BF38154B36CF"
        "8A96D1567899AAAE0C09D4C8B6B7B86F"
        "D2A1EA1DE62FF8643EC7C27182797722"
        "5E6AC2F0BD61C746961542A3CE3BEA5D"
        "B54FE70E63E6D09F8FC28658E80567A4"
        "7CFDE60EE741E5D85A7BD46931CED822"
        "0365594964B839896FCAABCCC9B31959"
        "C083F22AD3EE591C32FAB2C7448F2A05"
        "7DB2DB49EE52E0182741E53865F004CC"
        "8E704B7C5C40BF304C4D8C4F13EDF604"
        "7C555302D2238D8CE11DF2424F1B66C2"
        "C5D238D0744DB679AF2890487031F9C0"
        "AEA1C4BB6FE9554EE528FDF1B05E5B25"
        "6223B2F09215F3719F9C7CCC69DDF172"
        "D0D6234217FCC0037F18B93EF5389130"
        "B7A661E5C26E54214068BBCAFEA32A67"
        "818BD3075AD1F5C7E9CC3D1737FB2817"
        "1BAF84DBB6612B7881C1A48E439CD03A"
        "92BF52225A2B38E6542E9F722BCE15A3"
        "81B5753EA842763381CCAE83512B3051"
        "1B32E5E8D80362149AD030AABA5F3A57"
        "98BB22AA7EC1B6D0F17903F4E22D8407"
        "34AA85973F79A93FFB82A75C47C03D43"
        "D2F9CA02D03199BACEDDD4533A52566A"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    ),
    q=2**256 - 189,
    g=int(
        "1D41E49C477E15EAEEF0C5E4AC08D4A4"
        "6C268CD3424FC01D13769BDB43673218"
        "587BC86C4C1448D006A03699F3ABAE5F"
        "EB19E296F5D143CC5E4A3FC89088C9F4"
        "523D166EE3AE9D5FB03C0BDD77ADD5C0"
        "17F6C55E2EC92C226FEF5C6C1DF2E7C3"
        "6D90E7EAADE098241D3409983BCCD2B5"
        "379E9391FBC62F9F8D939D1208B16036"
        "7C134264122189595EC85C8CDBE5F9D3"
        "07F46912C04932F8C16815A76B4682BD"
        "6BDC0ED52B00D8D30F59C731D5A7FFAE"
        "8165D53CF96649AAC2B743DA56F14F19"
        "DACC5236F29B1AB9F9BEFC69697293D5"
        "DEAD8B5BF5DE9BAB6DE67C45719E5634"
        "4A3CBDF3609824B1B578E34EAEB6DD31"
        "90AB3571D6D671C512282C1DA7BD36B4"
        "251D2584FADEA80B9E141423074DD9B5"
        "FB83ACBDEAD4C87A58FFF517F977A830"
        "80370A3B0CF98A1BC2978C47AAC29611"
        "FD6C40E2F9875C35D50443A9AA3F4961"
        "1DCD3A0D6FF3CB3FACF31471BDB61860"
        "B92C594D4E46569BB39FEEADFF1FD64C"
        "836A6D6DB85C6BA7241766B7AB56BF73"
        "9633B054147F7170921412E948D9E474"
        "02D15BB1C257318612C121C36B80EB84"
        "33C08E7D0B7149E3AB0A8735A92EDCE8"
        "FF943E28A2DCEACFCC69EC318909CB04"
        "7BE1C5858844B5AD44F22EEB289E4CC5"
        "54F7A5E2F3DEA026877FF92851816071"
        "CE028EB868D965CCB2D2295A8C55BD1C"
        "070B39B09AE06B37D29343B9D8997DC2"
        "44C468B980970731736EE018BBADB987",
        16,
    ),
)

GROUPS = {
    "didattico": TEST_PARAMS,
    "demo": DEMO_PARAMS,
    "4096": EG_4096_PARAMS,
}

# Moduli che importano mod_pow: per contare le esponenziazioni, o per
# sostituire gmpy2 con pow() di Python, la si sostituisce in ognuno.
MOD_POW_MODULES = (
    evoto.gruppo,
    evoto.elgamal,
    evoto.prove,
    evoto.garanti,
    evoto.decifratura,
)

# Configurazione di riferimento della sezione 2.5 della proposta:
# 10 liste, ciascuna con capolista più 8 candidati.
REFERENCE_LISTS = 10
REFERENCE_CANDIDATES = 8


@dataclass
class ExponentiationCounter:
    """
    Contatore delle esponenziazioni modulari.

    membership_checks conta, tra queste, i controlli di appartenenza
    al sottogruppo, cioè le esponenziazioni con esponente q.
    """

    count: int = 0
    membership_checks: int = 0


@dataclass(frozen=True)
class BallotDimensions:
    """
    Struttura di una scheda cifrata con le sue prove.

    ciphertexts: m = liste + 1 (bianca) + caselle di preferenza.
    proofs: prove R1-R5, cioè m + 1 + preferenze + 1 + generi.
    branches: rami delle prove OR; ogni ramo ha due impegni,
    una sfida e una risposta.
    """

    ciphertexts: int
    r1_proofs: int
    r3_proofs: int
    r5_proofs: int
    proofs: int
    branches: int


@dataclass(frozen=True)
class BallotMeasure:
    """
    Misure di una scheda in una configurazione e in un gruppo.

    implementation è gmpy2 oppure python (pow() di Python).
    Le dimensioni sono in byte, i tempi in secondi (mediana delle
    ripetizioni).
    """

    group: str
    implementation: str
    p_bits: int
    q_bits: int
    list_count: int
    candidates_per_list: int
    ciphertexts: int
    proofs: int
    branches: int
    full_size: int
    compact_size: int
    encrypt_exponentiations: int
    verify_exponentiations: int
    verify_membership_checks: int
    encrypt_seconds: float
    verify_seconds: float


@dataclass(frozen=True)
class ExponentiationCost:
    """
    Costo di una esponenziazione modulare con esponente minore di q.
    """

    group: str
    p_bits: int
    gmpy2_seconds: float
    python_seconds: float


@dataclass(frozen=True)
class DistrictProjection:
    """
    Proiezione dei costi su una circoscrizione.

    board_bytes: dimensione delle schede sulla bacheca, in forma
    compatta e con gli impegni.
    verify_seconds: verifica di tutte le schede su un solo core.
    tally_seconds: conteggio omomorfico di tutte le caselle.
    decryption_seconds: decifratura a soglia di tutti i totali,
    compresi prove, verifica delle share e logaritmo discreto.
    """

    voters: int
    group: str
    compact_board_bytes: int
    full_board_bytes: int
    verify_seconds: float
    tally_seconds: float
    decryption_seconds: float


def synthetic_layout(
    list_count: int,
    candidates_per_list: int,
    max_preferences: int = 3,
    max_preferences_per_gender: int = 2,
) -> BallotLayout:
    """
    Costruisce la scheda di una circoscrizione con liste tutte uguali.

    Ogni lista ha il capolista, che non ha casella, più
    candidates_per_list candidati con una casella ciascuno, di genere
    alternato M, F, M, F, ...
    """

    if list_count < 1:
        raise ValueError("Serve almeno una lista.")

    if candidates_per_list < 0:
        raise ValueError("Il numero di candidati non può essere negativo.")

    metadata = tuple(
        PreferenceMetadata(
            list_index=list_index,
            gender="M" if position % 2 == 0 else "F",
        )
        for list_index in range(list_count)
        for position in range(candidates_per_list)
    )

    return BallotLayout(
        list_count=list_count,
        preference_metadata=metadata,
        max_preferences=max_preferences,
        max_preferences_per_gender=max_preferences_per_gender,
    )


def sample_choice(
    layout: BallotLayout,
) -> VoterChoice:
    """
    Voto alla prima lista con il massimo di preferenze consentito.

    Le prime caselle della lista hanno genere alternato, quindi con al
    massimo tre preferenze il vincolo di genere è sempre rispettato.
    """

    candidates = sum(
        metadata.list_index == 0
        for metadata in layout.preference_metadata
    )

    count = min(
        candidates,
        layout.max_preferences,
        2 * layout.max_preferences_per_gender,
    )

    return VoterChoice(
        list_index=0,
        preferences=tuple(range(count)),
    )


def ballot_dimensions(
    ballot: EncryptedBallot,
    proofs: BallotProofs,
) -> BallotDimensions:
    """
    Conta cifrati, prove e rami di una scheda vera.
    """

    all_proofs = (
        proofs.r1_proofs
        + (proofs.r2_proof,)
        + proofs.r3_proofs
        + (proofs.r4_proof,)
        + proofs.r5_proofs
    )

    ciphertexts = (
        len(ballot.list_ciphertexts)
        + 1
        + len(ballot.preference_ciphertexts)
    )

    return BallotDimensions(
        ciphertexts=ciphertexts,
        r1_proofs=len(proofs.r1_proofs),
        r3_proofs=len(proofs.r3_proofs),
        r5_proofs=len(proofs.r5_proofs),
        proofs=len(all_proofs),
        branches=sum(
            len(proof.branches)
            for proof in all_proofs
        ),
    )


def ballot_size(
    dimensions: BallotDimensions,
    params: GroupParameters,
    compact: bool,
) -> int:
    """
    Dimensione in byte di una scheda con le sue prove, in binario.

    Un elemento del gruppo occupa i byte di p, una sfida o una risposta
    quelli di q. Ogni cifrato ha due elementi (alpha, beta); ogni ramo
    ha due impegni (elementi), una sfida e una risposta (scalari).

    In forma compatta gli impegni non si trasmettono: il verificatore
    li ricalcola da sfida e risposta. È una stima: il nostro registro
    pubblica gli impegni.
    """

    element_bytes = (params.p.bit_length() + 7) // 8
    scalar_bytes = (params.q.bit_length() + 7) // 8

    elements = 2 * dimensions.ciphertexts

    if not compact:
        elements += 2 * dimensions.branches

    scalars = 2 * dimensions.branches

    return elements * element_bytes + scalars * scalar_bytes


@contextmanager
def count_exponentiations(
    implementation: Callable[[int, int, int], int] | None = None,
    subgroup_order: int | None = None,
) -> Iterator[ExponentiationCounter]:
    """
    Conta le esponenziazioni modulari eseguite dalla libreria.

    Sostituisce temporaneamente mod_pow nei moduli che la importano con
    una funzione che incrementa un contatore. implementation permette
    di usare pow() di Python al posto di gmpy2, per misurare il costo
    in Python puro con lo stesso codice.

    Se subgroup_order è indicato, le esponenziazioni con quell'esponente
    vengono contate anche come controlli di appartenenza al sottogruppo
    (value^q = 1 mod p).

    Alla fine del blocco with i moduli tornano come prima.
    """

    counter = ExponentiationCounter()
    base_implementation = implementation or mod_pow

    def counting_mod_pow(base: int, exponent: int, modulus: int) -> int:
        counter.count += 1

        if exponent == subgroup_order:
            counter.membership_checks += 1

        return base_implementation(base, exponent, modulus)

    with ExitStack() as stack:
        for module in MOD_POW_MODULES:
            stack.enter_context(
                patch.object(module, "mod_pow", counting_mod_pow)
            )

        yield counter


def python_pow(base: int, exponent: int, modulus: int) -> int:
    """
    Esponenziazione modulare con il solo pow() di Python.
    """

    return pow(base, exponent, modulus)


def measure_ballot(
    layout: BallotLayout,
    params: GroupParameters,
    group: str,
    public_key: int,
    context: int,
    repetitions: int,
    implementation: Callable[[int, int, int], int] | None = None,
) -> BallotMeasure:
    """
    Cifra e verifica repetitions schede e ne restituisce le misure.

    Il numero di esponenziazioni non dipende dalla scelta dell'elettore
    né dai numeri casuali: si conta sulla prima ripetizione. Comprende
    anche le g^v con v piccolo delle prove OR, di costo trascurabile:
    per questo la stima in Python puro di main è un poco per eccesso.
    """

    if repetitions < 1:
        raise ValueError("Serve almeno una ripetizione.")

    choice = sample_choice(layout)

    encrypt_times = []
    verify_times = []
    encrypt_count = 0
    verify_count = 0
    membership_checks = 0
    prepared = None

    for repetition in range(repetitions):
        with count_exponentiations(implementation, params.q) as counter:
            start = time.perf_counter()

            prepared = prepare_ballot(
                layout,
                0,
                choice,
                public_key,
                params,
                context,
            )

            encrypt_times.append(time.perf_counter() - start)

        if repetition == 0:
            encrypt_count = counter.count

        with count_exponentiations(implementation, params.q) as counter:
            start = time.perf_counter()

            valid = verify_ballot(
                layout,
                prepared.ballot,
                prepared.proofs,
                public_key,
                params,
                context,
            )

            verify_times.append(time.perf_counter() - start)

        if repetition == 0:
            verify_count = counter.count
            membership_checks = counter.membership_checks

        if not valid:
            raise ValueError("La scheda appena cifrata non è valida.")

    dimensions = ballot_dimensions(
        prepared.ballot,
        prepared.proofs,
    )

    candidates_per_list = (
        len(layout.preference_metadata) // layout.list_count
    )

    return BallotMeasure(
        group=group,
        implementation="gmpy2" if implementation is None else "python",
        p_bits=params.p.bit_length(),
        q_bits=params.q.bit_length(),
        list_count=layout.list_count,
        candidates_per_list=candidates_per_list,
        ciphertexts=dimensions.ciphertexts,
        proofs=dimensions.proofs,
        branches=dimensions.branches,
        full_size=ballot_size(dimensions, params, compact=False),
        compact_size=ballot_size(dimensions, params, compact=True),
        encrypt_exponentiations=encrypt_count,
        verify_exponentiations=verify_count,
        verify_membership_checks=membership_checks,
        encrypt_seconds=statistics.median(encrypt_times),
        verify_seconds=statistics.median(verify_times),
    )


def measure_exponentiation(
    params: GroupParameters,
    group: str,
    samples: int = 200,
    seed: int = 5,
) -> ExponentiationCost:
    """
    Misura il costo medio di una esponenziazione modulare.

    Basi casuali del sottogruppo ed esponenti casuali minori di q, come
    nelle operazioni del protocollo. Si confrontano gmpy2.powmod e pow()
    di Python sugli stessi valori.
    """

    if samples < 1:
        raise ValueError("Serve almeno un campione.")

    rng = random.Random(seed)

    bases = [
        mod_pow(params.g, rng.randrange(1, params.q), params.p)
        for _ in range(samples)
    ]

    exponents = [
        rng.randrange(1, params.q)
        for _ in range(samples)
    ]

    start = time.perf_counter()

    for base, exponent in zip(bases, exponents, strict=True):
        gmpy2.powmod(base, exponent, params.p)

    gmpy2_seconds = (time.perf_counter() - start) / samples

    start = time.perf_counter()

    for base, exponent in zip(bases, exponents, strict=True):
        pow(base, exponent, params.p)

    python_seconds = (time.perf_counter() - start) / samples

    return ExponentiationCost(
        group=group,
        p_bits=params.p.bit_length(),
        gmpy2_seconds=gmpy2_seconds,
        python_seconds=python_seconds,
    )


def project_district(
    measure: BallotMeasure,
    params: GroupParameters,
    voters: int,
    guardian_count: int = 5,
    quorum: int = 3,
    samples: int = 200,
) -> DistrictProjection:
    """
    Proietta i costi di una scheda su una circoscrizione di voters
    elettori.

    Bacheca e verifica crescono linearmente con il numero di schede.
    Il conteggio omomorfico costa una moltiplicazione di cifrati per
    casella e per scheda: si misura su samples cifrati e si scala.
    La decifratura non dipende dal numero di schede, salvo il logaritmo
    discreto, che con baby-step giant-step costa circa 2·sqrt(voters)
    passi: si misura davvero su un totale vicino a voters / 2.
    """

    if voters < 1:
        raise ValueError("Serve almeno un elettore.")

    ceremony = run_key_ceremony(
        guardian_count=guardian_count,
        quorum=quorum,
        params=params,
        election_id=1,
    )

    public_key = ceremony.joint_public_key
    context = ceremony.extended_base_hash

    sample = tuple(
        encrypt(
            1,
            public_key,
            params,
        )
        for _ in range(samples)
    )

    # Si ripete il campione per avere una misura meno rumorosa.
    repeated = sample * 10

    start = time.perf_counter()

    aggregate_ciphertexts(
        repeated,
        params,
    )

    per_ciphertext = (time.perf_counter() - start) / len(repeated)

    tally_seconds = (
        per_ciphertext
        * voters
        * measure.ciphertexts
    )

    # Un totale cifrato realistico: circa metà degli elettori.
    tally = encrypt(
        voters // 2,
        public_key,
        params,
    )

    present = tuple(range(1, quorum + 1))

    verification_keys = {
        index: compute_verification_key(index, ceremony.records, params)
        for index in present
    }

    start = time.perf_counter()

    shares = tuple(
        compute_decryption_share(
            guardian_index=index,
            secret_share=ceremony.secret_shares[index],
            tally=tally,
            params=params,
            extended_base_hash=context,
        )
        for index in present
    )

    for share in shares:
        if not verify_decryption_share(
            share=share,
            verification_key=verification_keys[share.guardian_index],
            tally=tally,
            params=params,
            extended_base_hash=context,
        ):
            raise ValueError("Share di decifratura non valida.")

    total = decrypt_tally(
        tally=tally,
        shares=shares,
        quorum=quorum,
        params=params,
        max_total=voters,
    )

    per_total = time.perf_counter() - start

    if total != voters // 2:
        raise ValueError("Il totale decifrato non è corretto.")

    return DistrictProjection(
        voters=voters,
        group=measure.group,
        compact_board_bytes=voters * measure.compact_size,
        full_board_bytes=voters * measure.full_size,
        verify_seconds=voters * measure.verify_seconds,
        tally_seconds=tally_seconds,
        decryption_seconds=per_total * measure.ciphertexts,
    )


def parse_int_list(value: str) -> tuple[int, ...]:
    """
    Legge un elenco di interi separati da virgole, come "2,4,8".
    """

    numbers = tuple(
        int(item)
        for item in value.split(",")
        if item.strip()
    )

    if not numbers:
        raise argparse.ArgumentTypeError("Serve almeno un numero.")

    return numbers


def parse_arguments() -> argparse.Namespace:
    """
    Legge le opzioni della riga di comando.
    """

    parser = argparse.ArgumentParser(
        description="Esperimento E5: costi di una scheda politica.",
    )

    parser.add_argument(
        "--gruppo",
        choices=tuple(GROUPS),
        default="demo",
        help="gruppo della tabella al variare di liste e candidati",
    )

    parser.add_argument(
        "--liste",
        type=parse_int_list,
        default=(2, 4, 6, 8, 10),
        help="numeri di liste, separati da virgole (default 2,4,6,8,10)",
    )

    parser.add_argument(
        "--candidati",
        type=parse_int_list,
        default=(2, 4, 8),
        help="candidati per lista oltre al capolista (default 2,4,8)",
    )

    parser.add_argument(
        "--ripetizioni",
        type=int,
        default=3,
        help="ripetizioni di ogni misura, si usa la mediana (default 3)",
    )

    parser.add_argument(
        "--elettori-circoscrizione",
        type=int,
        default=1_000_000,
        help="elettori della circoscrizione della proiezione",
    )

    parser.add_argument(
        "--python-puro",
        action="store_true",
        help="misura anche la scheda di riferimento senza gmpy2 (lento)",
    )

    parser.add_argument(
        "--csv",
        help="file CSV in cui salvare tutte le misure delle schede",
    )

    return parser.parse_args()


def format_bytes(size: float) -> str:
    """
    Dimensione leggibile: byte, KB, MB, GB o TB (potenze di 1000).
    """

    for unit in ("B", "KB", "MB", "GB"):
        if size < 1000:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"

        size /= 1000

    return f"{size:.2f} TB"


def format_seconds(seconds: float) -> str:
    """
    Durata leggibile: millisecondi, secondi, minuti od ore.
    """

    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"

    if seconds < 120:
        return f"{seconds:.2f} s"

    if seconds < 7200:
        return f"{seconds / 60:.1f} min"

    return f"{seconds / 3600:.1f} h"


def main() -> None:
    """
    Esegue l'esperimento e stampa le tabelle.
    """

    arguments = parse_arguments()

    print("\nEsperimento E5: costi di una scheda politica")
    print("============================================")

    # 1. Costo di una esponenziazione modulare
    costs = {
        name: measure_exponentiation(params, name)
        for name, params in GROUPS.items()
        if name != "didattico"
    }

    print("\nEsponenziazione modulare (esponente minore di q)")
    print("\n  Gruppo    p      gmpy2       Python puro   rapporto")

    for cost in costs.values():
        ratio = cost.python_seconds / cost.gmpy2_seconds

        print(
            f"  {cost.group:<9} {cost.p_bits:<6} "
            f"{format_seconds(cost.gmpy2_seconds):<11} "
            f"{format_seconds(cost.python_seconds):<13} {ratio:.1f}x"
        )

    # 2. Scheda di riferimento nei gruppi della sezione 2.5
    layout = synthetic_layout(REFERENCE_LISTS, REFERENCE_CANDIDATES)
    keys = {}
    reference = {}

    for name in ("demo", "4096"):
        params = GROUPS[name]

        ceremony = run_key_ceremony(
            guardian_count=5,
            quorum=3,
            params=params,
            election_id=1,
        )

        keys[name] = (
            ceremony.joint_public_key,
            ceremony.extended_base_hash,
        )

        reference[name] = measure_ballot(
            layout=layout,
            params=params,
            group=name,
            public_key=ceremony.joint_public_key,
            context=ceremony.extended_base_hash,
            repetitions=arguments.ripetizioni,
        )

    measure = reference["4096"]

    print(
        f"\nScheda di riferimento: {REFERENCE_LISTS} liste con capolista "
        f"più {REFERENCE_CANDIDATES} candidati"
    )

    print(
        f"{measure.ciphertexts} cifrati, {measure.proofs} prove, "
        f"{measure.branches} rami."
    )

    print(
        f"Esponenziazioni: {measure.encrypt_exponentiations} per cifrare, "
        f"{measure.verify_exponentiations} per verificare, di cui "
        f"{measure.verify_membership_checks} controlli di appartenenza "
        "al sottogruppo."
    )

    python_measure = None

    if arguments.python_puro:
        public_key, context = keys["4096"]

        python_measure = measure_ballot(
            layout=layout,
            params=EG_4096_PARAMS,
            group="4096",
            public_key=public_key,
            context=context,
            repetitions=1,
            implementation=python_pow,
        )

    estimated_verify = (
        measure.verify_exponentiations
        * costs["4096"].python_seconds
    )

    estimated_encrypt = (
        measure.encrypt_exponentiations
        * costs["4096"].python_seconds
    )

    print(
        "\n  Configurazione                          Dimensione   "
        "Cifratura    Verifica"
    )

    if python_measure is None:
        python_row = (
            f"~{format_seconds(estimated_encrypt):<11} "
            f"~{format_seconds(estimated_verify)} (stima)"
        )
    else:
        python_row = (
            f"{format_seconds(python_measure.encrypt_seconds):<12} "
            f"{format_seconds(python_measure.verify_seconds)}"
        )

    print(
        f"  4096 bit, con impegni, Python puro      "
        f"{format_bytes(measure.full_size):<12} {python_row}"
    )

    for name, label in (
        ("4096", "4096 bit, forma compatta, gmpy2       "),
        ("demo", "2048/256 bit, forma compatta, gmpy2   "),
        ("demo", "2048/256 bit, con impegni, gmpy2      "),
    ):
        item = reference[name]
        compact = "compatta" in label
        size = item.compact_size if compact else item.full_size

        print(
            f"  {label}  {format_bytes(size):<12} "
            f"{format_seconds(item.encrypt_seconds):<12} "
            f"{format_seconds(item.verify_seconds)}"
        )

    # 3. Al variare di liste e candidati
    params = GROUPS[arguments.gruppo]
    public_key, context = keys.get(arguments.gruppo, (None, None))

    if public_key is None:
        ceremony = run_key_ceremony(
            guardian_count=5,
            quorum=3,
            params=params,
            election_id=1,
        )

        public_key = ceremony.joint_public_key
        context = ceremony.extended_base_hash

    grid = []

    for list_count in arguments.liste:
        for candidates in arguments.candidati:
            grid.append(
                measure_ballot(
                    layout=synthetic_layout(list_count, candidates),
                    params=params,
                    group=arguments.gruppo,
                    public_key=public_key,
                    context=context,
                    repetitions=arguments.ripetizioni,
                )
            )

    print(
        f"\nAl variare di liste e candidati (gruppo {arguments.gruppo}, "
        f"p da {params.p.bit_length()} bit)"
    )

    print(
        "\n  Liste  Cand.  Cifrati  Prove  Compatta    Con impegni  "
        "Cifratura    Verifica"
    )

    for item in grid:
        print(
            f"  {item.list_count:>5}  {item.candidates_per_list:>5}  "
            f"{item.ciphertexts:>7}  {item.proofs:>5}  "
            f"{format_bytes(item.compact_size):<11} "
            f"{format_bytes(item.full_size):<12} "
            f"{format_seconds(item.encrypt_seconds):<12} "
            f"{format_seconds(item.verify_seconds)}"
        )

    # 4. Proiezione su una circoscrizione
    projection = project_district(
        measure=reference["demo"],
        params=DEMO_PARAMS,
        voters=arguments.elettori_circoscrizione,
    )

    voters = f"{projection.voters:,}".replace(",", ".")

    print(
        f"\nProiezione su una circoscrizione di {voters} elettori "
        "(scheda di riferimento, gruppo demo)"
    )

    print(
        f"\n  Bacheca, forma compatta     "
        f"{format_bytes(projection.compact_board_bytes)}"
    )

    print(
        f"  Bacheca, con impegni        "
        f"{format_bytes(projection.full_board_bytes)}"
    )

    print(
        f"  Verifica di tutte le schede "
        f"{format_seconds(projection.verify_seconds)} su un core, "
        f"{format_seconds(projection.verify_seconds / 8)} su 8 core"
    )

    print(
        f"  Conteggio omomorfico        "
        f"{format_seconds(projection.tally_seconds)}"
    )

    print(
        f"  Decifratura dei totali      "
        f"{format_seconds(projection.decryption_seconds)} "
        "(3 garanti, con prove e logaritmo discreto)"
    )

    if arguments.csv:
        rows = list(reference.values()) + grid

        if python_measure is not None:
            rows.append(python_measure)

        with open(arguments.csv, "w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(
                output,
                fieldnames=list(asdict(rows[0])),
            )

            writer.writeheader()

            for row in rows:
                writer.writerow(asdict(row))

        print(f"\nMisure salvate in {arguments.csv}")

    print()


if __name__ == "__main__":
    main()
