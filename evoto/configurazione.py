"""
Configurazione dell'elezione del progetto evoto.

Questo modulo contiene:
- il modello della configurazione: liste, coalizioni, circoscrizioni,
  candidati e regole elettorali;
- la lettura e la validazione del file JSON di configurazione;
- la costruzione del BallotLayout di ogni circoscrizione;
- la corrispondenza tra caselle di preferenza e candidati.

Cambiare legge elettorale significa cambiare il file di configurazione,
non il codice. Il formato del file è descritto nella specifica condivisa
docs/spec_f1.md, sezione 42.
"""

from dataclasses import dataclass
from fractions import Fraction
import json
from pathlib import Path

from evoto.scheda import (
    BallotLayout,
    PreferenceMetadata,
)


@dataclass(frozen=True)
class Candidate:
    """
    Candidato di una lista in una circoscrizione.

    gender è il genere usato dal vincolo R5.
    """

    name: str
    gender: str


@dataclass(frozen=True)
class Coalition:
    """
    Coalizione di liste collegate.

    list_indices contiene gli indici delle liste che ne fanno parte.
    """

    name: str
    list_indices: tuple[int, ...]


@dataclass(frozen=True)
class District:
    """
    Circoscrizione elettorale.

    candidates[p] contiene i candidati della lista p in questa
    circoscrizione: il primo è il capolista bloccato, che non ha una
    casella di preferenza; gli altri hanno una casella ciascuno.
    """

    name: str
    candidates: tuple[tuple[Candidate, ...], ...]


@dataclass(frozen=True)
class ElectoralRules:
    """
    Parametri della legge elettorale.

    Le soglie sono frazioni dei voti validi nazionali:
    per esempio Fraction(3, 100) significa 3%.
    """

    max_preferences: int
    max_preferences_per_gender: int
    list_threshold: Fraction
    coalition_threshold: Fraction
    bonus_threshold: Fraction
    bonus_seat_share: Fraction


@dataclass(frozen=True)
class ElectionConfig:
    """
    Configurazione completa di un'elezione.

    election_id è l'identificativo e usato nel contesto Q
    della cerimonia delle chiavi.
    """

    name: str
    election_id: int
    seats: int
    rules: ElectoralRules
    list_names: tuple[str, ...]
    coalitions: tuple[Coalition, ...]
    districts: tuple[District, ...]


def _percent(value: object, field: str) -> Fraction:
    """
    Converte una percentuale del file JSON in una frazione esatta.

    Passiamo da str() per evitare gli errori di arrotondamento
    dei numeri in virgola mobile: 2.5 diventa esattamente 1/40.
    """

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Il campo {field} deve essere un numero.")

    fraction = Fraction(str(value)) / 100

    if not 0 <= fraction <= 1:
        raise ValueError(f"Il campo {field} deve essere compreso tra 0 e 100.")

    return fraction


def _positive_int(value: object, field: str) -> int:
    """
    Controlla che un campo del file JSON sia un intero positivo.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"Il campo {field} deve essere un intero positivo.")

    return value


def _parse_rules(data: dict) -> ElectoralRules:
    """
    Legge la sezione rules del file di configurazione.
    """

    max_preferences = data["max_preferences"]
    max_per_gender = data["max_preferences_per_gender"]

    for value, field in (
        (max_preferences, "max_preferences"),
        (max_per_gender, "max_preferences_per_gender"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(
                f"Il campo {field} deve essere un intero non negativo."
            )

    bonus_seat_share = _percent(
        data["bonus_seats_percent"],
        "bonus_seats_percent",
    )

    if bonus_seat_share == 0:
        raise ValueError("Il campo bonus_seats_percent deve essere positivo.")

    return ElectoralRules(
        max_preferences=max_preferences,
        max_preferences_per_gender=max_per_gender,
        list_threshold=_percent(
            data["list_threshold_percent"],
            "list_threshold_percent",
        ),
        coalition_threshold=_percent(
            data["coalition_threshold_percent"],
            "coalition_threshold_percent",
        ),
        bonus_threshold=_percent(
            data["bonus_threshold_percent"],
            "bonus_threshold_percent",
        ),
        bonus_seat_share=bonus_seat_share,
    )


def _parse_candidate(data: dict) -> Candidate:
    """
    Legge un candidato e controlla nome e genere.
    """

    name = data["name"]
    gender = data["gender"]

    if not isinstance(name, str) or not name.strip():
        raise ValueError("Ogni candidato deve avere un nome.")

    if not isinstance(gender, str) or not gender.strip():
        raise ValueError(f"Il candidato {name} deve avere un genere.")

    return Candidate(
        name=name,
        gender=gender,
    )


def parse_election_config(data: dict) -> ElectionConfig:
    """
    Costruisce e valida la configurazione a partire dal JSON già letto.

    Controlliamo, tra l'altro, che:
    - i nomi delle liste siano distinti;
    - ogni circoscrizione abbia candidati per tutte e sole le liste;
    - ogni lista abbia almeno il capolista in ogni circoscrizione.

    Le coalizioni sono ricavate dal campo coalition di ogni lista,
    nell'ordine in cui compaiono per la prima volta.

    Un campo mancante produce un ValueError che lo nomina.
    """

    try:
        return _parse_election_config(data)
    except KeyError as exc:
        raise ValueError(f"Manca il campo obbligatorio {exc}.") from exc


def _parse_election_config(data: dict) -> ElectionConfig:
    """
    Corpo di parse_election_config: può sollevare KeyError
    se manca un campo, che viene tradotto dal chiamante.
    """

    name = data["name"]
    election_id = data["election_id"]
    seats = _positive_int(data["seats"], "seats")
    rules = _parse_rules(data["rules"])
    lists_data = data["lists"]
    districts_data = data["districts"]

    if isinstance(election_id, bool) or not isinstance(election_id, int):
        raise ValueError("Il campo election_id deve essere un intero.")

    if election_id < 0:
        raise ValueError("Il campo election_id deve essere non negativo.")

    if not lists_data:
        raise ValueError("L'elezione deve avere almeno una lista.")

    list_names = tuple(entry["name"] for entry in lists_data)

    if len(set(list_names)) != len(list_names):
        raise ValueError("I nomi delle liste devono essere distinti.")

    # Le coalizioni sono ricavate dalle liste che le dichiarano.
    coalition_members: dict[str, list[int]] = {}

    for index, entry in enumerate(lists_data):
        coalition = entry.get("coalition")

        if coalition is None:
            continue

        if not isinstance(coalition, str) or not coalition.strip():
            raise ValueError("Il nome della coalizione non è valido.")

        coalition_members.setdefault(coalition, []).append(index)

    coalitions = tuple(
        Coalition(
            name=coalition,
            list_indices=tuple(indices),
        )
        for coalition, indices in coalition_members.items()
    )

    if not districts_data:
        raise ValueError("L'elezione deve avere almeno una circoscrizione.")

    districts = []

    for district_data in districts_data:
        district_name = district_data["name"]
        candidates_data = district_data["candidates"]

        if set(candidates_data) != set(list_names):
            raise ValueError(
                f"La circoscrizione {district_name} deve avere candidati "
                "per tutte e sole le liste dell'elezione."
            )

        candidates = []

        for list_name in list_names:
            list_candidates = tuple(
                _parse_candidate(candidate)
                for candidate in candidates_data[list_name]
            )

            if not list_candidates:
                raise ValueError(
                    f"La {list_name} nella circoscrizione {district_name} "
                    "deve avere almeno il capolista."
                )

            candidates.append(list_candidates)

        districts.append(
            District(
                name=district_name,
                candidates=tuple(candidates),
            )
        )

    return ElectionConfig(
        name=name,
        election_id=election_id,
        seats=seats,
        rules=rules,
        list_names=list_names,
        coalitions=coalitions,
        districts=tuple(districts),
    )


def load_election_config(path: str | Path) -> ElectionConfig:
    """
    Legge e valida un file JSON di configurazione.
    """

    with open(path, encoding="utf-8") as config_file:
        data = json.load(config_file)

    return parse_election_config(data)


def coalition_of(
    config: ElectionConfig,
    list_index: int,
) -> int | None:
    """
    Restituisce l'indice della coalizione della lista, oppure None
    se la lista non è coalizzata.
    """

    for coalition_index, coalition in enumerate(config.coalitions):
        if list_index in coalition.list_indices:
            return coalition_index

    return None


def preference_candidates(
    config: ElectionConfig,
    district_index: int,
) -> tuple[tuple[int, int], ...]:
    """
    Associa ogni casella di preferenza al suo candidato.

    L'elemento k è la coppia (indice della lista, posizione del
    candidato nella lista) della k-esima casella di preferenza.
    Le posizioni partono da 1 perché la posizione 0 è il capolista,
    che non ha casella.

    L'ordine delle caselle è: lista dopo lista, nell'ordine della
    configurazione, e dentro ogni lista nell'ordine dei candidati.
    """

    district = config.districts[district_index]

    return tuple(
        (list_index, position)
        for list_index, candidates in enumerate(district.candidates)
        for position in range(1, len(candidates))
    )


def build_ballot_layout(
    config: ElectionConfig,
    district_index: int,
) -> BallotLayout:
    """
    Costruisce la struttura pubblica della scheda di una circoscrizione.

    I metadati delle preferenze (lista e genere) vengono dalla
    configurazione ufficiale e non dal votante.
    """

    if not 0 <= district_index < len(config.districts):
        raise ValueError("L'indice della circoscrizione non è valido.")

    district = config.districts[district_index]

    metadata = tuple(
        PreferenceMetadata(
            list_index=list_index,
            gender=district.candidates[list_index][position].gender,
        )
        for list_index, position in preference_candidates(
            config,
            district_index,
        )
    )

    return BallotLayout(
        list_count=len(config.list_names),
        preference_metadata=metadata,
        max_preferences=config.rules.max_preferences,
        max_preferences_per_gender=(
            config.rules.max_preferences_per_gender
    ),
)
