"""
Registro pubblico del progetto evoto.

Questo modulo converte i dati pubblici dell'elezione
in strutture semplici serializzabili in JSON.

La serializzazione è esplicita per evitare che dati
privati vengano inclusi accidentalmente nel registro.
"""

import json
from evoto.elgamal import Ciphertext
from evoto.decifratura import DecryptionShare
from evoto.garanti import GuardianRecord
from evoto.prove import (
    ChaumPedersenProof,
    SchnorrProof,
    ValueSetBranchProof,
    ValueSetProof,
)
from evoto.scheda import (
    BallotProofs,
    BallotWitness,
    EncryptedBallot,
)
from evoto.urna import (
    CAST,
    SPOILED,
    BoardEntry,
    BulletinBoard,
    DistrictResult,
    DistrictTally,
)
from fractions import Fraction

from evoto.configurazione import (
    Candidate,
    ElectionConfig,
)
from evoto.scrutinio import (
    Competitor,
    ElectedCandidate,
    ScrutinyResult,
)
from evoto.gruppo import GroupParameters
from evoto.simulazione import SimulationReport


def _ciphertext_to_data(
    ciphertext: Ciphertext,
) -> dict[str, int]:
    """
    Converte un ciphertext nella sua rappresentazione pubblica.
    """

    return {
        "alpha": ciphertext.alpha,
        "beta": ciphertext.beta,
    }


def _schnorr_proof_to_data(
    proof: SchnorrProof,
) -> dict[str, int]:
    """
    Converte una prova di Schnorr nei suoi dati pubblici.
    """

    return {
        "commitment": proof.commitment,
        "challenge": proof.challenge,
        "response": proof.response,
    }


def _chaum_pedersen_proof_to_data(
    proof: ChaumPedersenProof,
) -> dict[str, int]:
    """
    Converte una prova Chaum-Pedersen nei suoi dati pubblici.
    """

    return {
        "commitment_1": proof.commitment_1,
        "commitment_2": proof.commitment_2,
        "challenge": proof.challenge,
        "response": proof.response,
    }


def _value_set_branch_to_data(
    branch: ValueSetBranchProof,
) -> dict[str, int]:
    """
    Converte un ramo di una prova OR nei suoi dati pubblici.
    """

    return {
        "commitment_1": branch.commitment_1,
        "commitment_2": branch.commitment_2,
        "challenge": branch.challenge,
        "response": branch.response,
    }


def _value_set_proof_to_data(
    proof: ValueSetProof,
) -> dict[str, object]:
    """
    Converte una prova OR completa nella rappresentazione pubblica.
    """

    return {
        "branches": [
            _value_set_branch_to_data(branch)
            for branch in proof.branches
        ],
    }


def _guardian_record_to_data(
    record: GuardianRecord,
) -> dict[str, object]:
    """
    Converte i dati pubblici di un garante.
    """

    return {
        "index": record.index,
        "commitments": list(record.commitments),
        "proofs": [
            _schnorr_proof_to_data(proof)
            for proof in record.proofs
        ],
    }


def _decryption_share_to_data(
    share: DecryptionShare,
) -> dict[str, object]:
    """
    Converte una share pubblica di decifratura.
    """

    return {
        "guardian_index": share.guardian_index,
        "partial_decryption": share.partial_decryption,
        "proof": _chaum_pedersen_proof_to_data(
            share.proof
        ),
    }


def _encrypted_ballot_to_data(
    ballot: EncryptedBallot,
) -> dict[str, object]:
    """
    Converte una scheda cifrata nei suoi dati pubblici.
    """

    return {
        "list_ciphertexts": [
            _ciphertext_to_data(ciphertext)
            for ciphertext in ballot.list_ciphertexts
        ],
        "blank_ciphertext": _ciphertext_to_data(
            ballot.blank_ciphertext
        ),
        "preference_ciphertexts": [
            _ciphertext_to_data(ciphertext)
            for ciphertext in ballot.preference_ciphertexts
        ],
    }


def _ballot_proofs_to_data(
    proofs: BallotProofs,
) -> dict[str, object]:
    """
    Converte tutte le prove pubbliche R1-R5 di una scheda.
    """

    return {
        "r1_proofs": [
            _value_set_proof_to_data(proof)
            for proof in proofs.r1_proofs
        ],
        "r2_proof": _value_set_proof_to_data(
            proofs.r2_proof
        ),
        "r3_proofs": [
            _value_set_proof_to_data(proof)
            for proof in proofs.r3_proofs
        ],
        "r4_proof": _value_set_proof_to_data(
            proofs.r4_proof
        ),
        "r5_proofs": [
            _value_set_proof_to_data(proof)
            for proof in proofs.r5_proofs
        ],
    }


def _ballot_witness_to_data(
    witness: BallotWitness,
) -> dict[str, object]:
    """
    Converte il witness rivelato di una scheda SPOILED.
    """

    return {
        "list_plaintexts": list(witness.list_plaintexts),
        "blank_plaintext": witness.blank_plaintext,
        "preference_plaintexts": list(
            witness.preference_plaintexts
        ),
        "list_nonces": list(witness.list_nonces),
        "blank_nonce": witness.blank_nonce,
        "preference_nonces": list(
            witness.preference_nonces
        ),
    }


def _board_entry_to_data(
    entry: BoardEntry,
) -> dict[str, object]:
    """
    Converte una riga della bacheca nei dati pubblici.
    """

    data: dict[str, object] = {
        "sequence": entry.sequence,
        "district_index": entry.district_index,
        "state": entry.state,
        "ballot": _encrypted_ballot_to_data(
            entry.ballot
        ),
        "proofs": _ballot_proofs_to_data(
            entry.proofs
        ),
        "ballot_hash": entry.ballot_hash,
        "tracking_code": entry.tracking_code,
    }

    if entry.state == CAST:
        if entry.revealed_witness is not None:
            raise ValueError(
                "Una scheda CAST non può pubblicare il witness."
            )

        return data

    if entry.state == SPOILED:
        if entry.revealed_witness is None:
            raise ValueError(
                "Una scheda SPOILED deve pubblicare il witness."
            )

        data["revealed_witness"] = _ballot_witness_to_data(
            entry.revealed_witness
        )

        return data

    raise ValueError(
        "Lo stato della scheda deve essere CAST o SPOILED."
    )


def _bulletin_board_to_data(
    board: BulletinBoard,
) -> dict[str, object]:
    """
    Converte la bacheca pubblica completa.
    """

    return {
        "extended_base_hash": board.extended_base_hash,
        "genesis_code": board.genesis_code,
        "entries": [
            _board_entry_to_data(entry)
            for entry in board.entries
        ],
    }


def _district_tally_to_data(
    tally: DistrictTally,
) -> dict[str, object]:
    """
    Converte i totali cifrati pubblici di una circoscrizione.
    """

    return {
        "district_index": tally.district_index,
        "ballot_count": tally.ballot_count,
        "list_tallies": [
            _ciphertext_to_data(ciphertext)
            for ciphertext in tally.list_tallies
        ],
        "blank_tally": _ciphertext_to_data(
            tally.blank_tally
        ),
        "preference_tallies": [
            _ciphertext_to_data(ciphertext)
            for ciphertext in tally.preference_tallies
        ],
    }


def _district_result_to_data(
    result: DistrictResult,
) -> dict[str, object]:
    """
    Converte il risultato pubblico di una circoscrizione.
    """

    return {
        "district_index": result.district_index,
        "ballot_count": result.ballot_count,
        "list_votes": list(result.list_votes),
        "blank_votes": result.blank_votes,
        "preference_votes": list(
            result.preference_votes
        ),
        "decryption_shares": [
            [
                _decryption_share_to_data(share)
                for share in shares
            ]
            for shares in result.decryption_shares
        ],
    }


def _fraction_to_percent(
    value: Fraction,
) -> int | float:
    """
    Riporta una frazione alla percentuale del file di configurazione.
    """

    percent = value * 100

    if percent.denominator == 1:
        return percent.numerator

    return float(percent)


def _candidate_to_data(
    candidate: Candidate,
) -> dict[str, str]:
    """
    Converte un candidato nella forma della configurazione pubblica.
    """

    return {
        "name": candidate.name,
        "gender": candidate.gender,
    }


def _election_config_to_data(
    config: ElectionConfig,
) -> dict[str, object]:
    """
    Ricostruisce la configurazione pubblica nel formato JSON ufficiale.
    """

    coalition_by_list: dict[int, str] = {}

    for coalition in config.coalitions:
        for list_index in coalition.list_indices:
            coalition_by_list[list_index] = coalition.name

    lists = [
        {
            "name": list_name,
            "coalition": coalition_by_list.get(list_index),
        }
        for list_index, list_name in enumerate(config.list_names)
    ]

    districts = []

    for district in config.districts:
        candidates = {
            config.list_names[list_index]: [
                _candidate_to_data(candidate)
                for candidate in list_candidates
            ]
            for list_index, list_candidates in enumerate(
                district.candidates
            )
        }

        districts.append(
            {
                "name": district.name,
                "candidates": candidates,
            }
        )

    return {
        "name": config.name,
        "election_id": config.election_id,
        "seats": config.seats,
        "rules": {
            "max_preferences": config.rules.max_preferences,
            "max_preferences_per_gender":
                config.rules.max_preferences_per_gender,
            "list_threshold_percent": _fraction_to_percent(
                config.rules.list_threshold
            ),
            "coalition_threshold_percent": _fraction_to_percent(
                config.rules.coalition_threshold
            ),
            "bonus_threshold_percent": _fraction_to_percent(
                config.rules.bonus_threshold
            ),
            "bonus_seats_percent": _fraction_to_percent(
                config.rules.bonus_seat_share
            ),
        },
        "lists": lists,
        "districts": districts,
    }


def _competitor_to_data(
    competitor: Competitor,
) -> dict[str, object]:
    """
    Converte un competitore dello scrutinio.
    """

    return {
        "name": competitor.name,
        "list_indices": list(competitor.list_indices),
        "votes": competitor.votes,
        "is_coalition": competitor.is_coalition,
    }


def _elected_candidate_to_data(
    candidate: ElectedCandidate,
) -> dict[str, object]:
    """
    Converte un candidato eletto.
    """

    return {
        "district_index": candidate.district_index,
        "list_index": candidate.list_index,
        "name": candidate.name,
        "position": candidate.position,
        "preferences": candidate.preferences,
    }


def _scrutiny_result_to_data(
    result: ScrutinyResult,
) -> dict[str, object]:
    """
    Converte il risultato pubblico completo dello scrutinio.
    """

    return {
        "valid_votes": result.valid_votes,
        "blank_votes": result.blank_votes,
        "list_votes": list(result.list_votes),
        "coalition_votes": list(result.coalition_votes),
        "competitors": [
            _competitor_to_data(competitor)
            for competitor in result.competitors
        ],
        "competitor_seats": list(
            result.competitor_seats
        ),
        "bonus_competitor": result.bonus_competitor,
        "list_seats": list(result.list_seats),
        "district_list_seats": [
            list(seats)
            for seats in result.district_list_seats
        ],
        "elected": [
            _elected_candidate_to_data(candidate)
            for candidate in result.elected
        ],
    }


def build_public_registry(
    report: SimulationReport,
    params: GroupParameters,
) -> dict[str, object]:
    """
    Costruisce il registro pubblico completo dell'elezione.

    Pubblica soltanto i dati necessari alla verifica indipendente.
    """

    records = report.ceremony.records

    if not records:
        raise ValueError(
            "La cerimonia deve contenere almeno un garante."
        )

    quorum = len(records[0].commitments)

    if quorum < 1:
        raise ValueError(
            "Il quorum deve essere almeno 1."
        )

    for record in records:
        if len(record.commitments) != quorum:
            raise ValueError(
                "I garanti devono avere lo stesso numero di impegni."
            )

        if len(record.proofs) != quorum:
            raise ValueError(
                "Ogni impegno deve avere una prova di Schnorr."
            )

    guardian_count = len(records)

    if quorum > guardian_count:
        raise ValueError(
            "Il quorum non può superare il numero di garanti."
        )

    if report.board.extended_base_hash != (
        report.ceremony.extended_base_hash
    ):
        raise ValueError(
            "La bacheca usa un contesto Q_bar diverso dalla cerimonia."
        )

    return {
        "configuration": _election_config_to_data(
            report.config
        ),
        "group": {
            "p": params.p,
            "q": params.q,
            "g": params.g,
        },
        "election_context": {
            "n": guardian_count,
            "quorum": quorum,
            "e": report.config.election_id,
            "Q": report.ceremony.base_hash,
            "Q_bar": report.ceremony.extended_base_hash,
        },
        "guardians": [
            _guardian_record_to_data(record)
            for record in records
        ],
        "K": report.ceremony.joint_public_key,
        "bulletin_board": _bulletin_board_to_data(
            report.board
        ),
        "district_tallies": [
            _district_tally_to_data(tally)
            for tally in report.tallies
        ],
        "district_results": [
            _district_result_to_data(result)
            for result in report.results
        ],
        "scrutiny": _scrutiny_result_to_data(
            report.scrutiny
        ),
    }


def public_registry_to_json(
    report: SimulationReport,
    params: GroupParameters,
) -> str:
    """
    Serializza il registro pubblico completo in JSON.
    """

    registry = build_public_registry(
        report,
        params,
    )

    return json.dumps(
        registry,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )