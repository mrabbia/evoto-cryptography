"""
Test della serializzazione del registro pubblico.
"""

from evoto.elgamal import Ciphertext
from evoto.decifratura import DecryptionShare
from evoto.garanti import GuardianRecord
from evoto.prove import (
    ChaumPedersenProof,
    SchnorrProof,
    ValueSetBranchProof,
    ValueSetProof,
)
from evoto.registro import (
    _chaum_pedersen_proof_to_data,
    _ciphertext_to_data,
    _schnorr_proof_to_data,
    _value_set_proof_to_data,
    _decryption_share_to_data,
    _guardian_record_to_data,
    _ballot_proofs_to_data,
    _encrypted_ballot_to_data,
    _ballot_witness_to_data,
    _board_entry_to_data,
    _bulletin_board_to_data,
    _district_result_to_data,
    _district_tally_to_data,
    _election_config_to_data,
    _scrutiny_result_to_data,
)
from evoto.scheda import (
    BallotProofs,
    EncryptedBallot,
    BallotWitness,
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
    Coalition,
    District,
    ElectionConfig,
    ElectoralRules,
)
from evoto.scrutinio import (
    Competitor,
    ElectedCandidate,
    ScrutinyResult,
)


def test_serializes_ciphertext():
    """
    Un ciphertext conserva alpha e beta.
    """

    ciphertext = Ciphertext(
        alpha=11,
        beta=22,
    )

    assert _ciphertext_to_data(ciphertext) == {
        "alpha": 11,
        "beta": 22,
    }


def test_serializes_schnorr_proof():
    """
    Una prova Schnorr conserva tutti i dati pubblici.
    """

    proof = SchnorrProof(
        commitment=10,
        challenge=20,
        response=30,
    )

    assert _schnorr_proof_to_data(proof) == {
        "commitment": 10,
        "challenge": 20,
        "response": 30,
    }


def test_serializes_chaum_pedersen_proof():
    """
    Una prova Chaum-Pedersen conserva tutti i dati pubblici.
    """

    proof = ChaumPedersenProof(
        commitment_1=10,
        commitment_2=20,
        challenge=30,
        response=40,
    )

    assert _chaum_pedersen_proof_to_data(proof) == {
        "commitment_1": 10,
        "commitment_2": 20,
        "challenge": 30,
        "response": 40,
    }


def test_serializes_value_set_proof():
    """
    Una prova OR conserva tutti i suoi rami nell'ordine originale.
    """

    proof = ValueSetProof(
        branches=(
            ValueSetBranchProof(
                commitment_1=10,
                commitment_2=20,
                challenge=30,
                response=40,
            ),
            ValueSetBranchProof(
                commitment_1=50,
                commitment_2=60,
                challenge=70,
                response=80,
            ),
        )
    )

    assert _value_set_proof_to_data(proof) == {
        "branches": [
            {
                "commitment_1": 10,
                "commitment_2": 20,
                "challenge": 30,
                "response": 40,
            },
            {
                "commitment_1": 50,
                "commitment_2": 60,
                "challenge": 70,
                "response": 80,
            },
        ],
    }


def test_serializes_guardian_record():
    """
    Un GuardianRecord conserva solo i dati pubblici del garante.
    """

    record = GuardianRecord(
        index=2,
        commitments=(100, 200),
        proofs=(
            SchnorrProof(
                commitment=10,
                challenge=20,
                response=30,
            ),
            SchnorrProof(
                commitment=40,
                challenge=50,
                response=60,
            ),
        ),
    )

    assert _guardian_record_to_data(record) == {
        "index": 2,
        "commitments": [100, 200],
        "proofs": [
            {
                "commitment": 10,
                "challenge": 20,
                "response": 30,
            },
            {
                "commitment": 40,
                "challenge": 50,
                "response": 60,
            },
        ],
    }


def test_serializes_decryption_share():
    """
    Una share conserva il contributo e la prova pubblica.
    """

    share = DecryptionShare(
        guardian_index=3,
        partial_decryption=1234,
        proof=ChaumPedersenProof(
            commitment_1=10,
            commitment_2=20,
            challenge=30,
            response=40,
        ),
    )

    assert _decryption_share_to_data(share) == {
        "guardian_index": 3,
        "partial_decryption": 1234,
        "proof": {
            "commitment_1": 10,
            "commitment_2": 20,
            "challenge": 30,
            "response": 40,
        },
    }


def _test_value_set_proof(
    value: int,
) -> ValueSetProof:
    """
    Crea una prova OR semplice per i test del registro.
    """

    return ValueSetProof(
        branches=(
            ValueSetBranchProof(
                commitment_1=value,
                commitment_2=value + 1,
                challenge=value + 2,
                response=value + 3,
            ),
        )
    )


def test_serializes_encrypted_ballot():
    """
    Una scheda cifrata conserva liste, bianca e preferenze.
    """

    ballot = EncryptedBallot(
        list_ciphertexts=(
            Ciphertext(alpha=10, beta=20),
            Ciphertext(alpha=30, beta=40),
        ),
        blank_ciphertext=Ciphertext(
            alpha=50,
            beta=60,
        ),
        preference_ciphertexts=(
            Ciphertext(alpha=70, beta=80),
        ),
    )

    assert _encrypted_ballot_to_data(ballot) == {
        "list_ciphertexts": [
            {
                "alpha": 10,
                "beta": 20,
            },
            {
                "alpha": 30,
                "beta": 40,
            },
        ],
        "blank_ciphertext": {
            "alpha": 50,
            "beta": 60,
        },
        "preference_ciphertexts": [
            {
                "alpha": 70,
                "beta": 80,
            },
        ],
    }


def test_serializes_ballot_proofs():
    """
    Le prove R1-R5 vengono conservate nella struttura corretta.
    """

    proofs = BallotProofs(
        r1_proofs=(
            _test_value_set_proof(10),
            _test_value_set_proof(20),
        ),
        r2_proof=_test_value_set_proof(30),
        r3_proofs=(
            _test_value_set_proof(40),
        ),
        r4_proof=_test_value_set_proof(50),
        r5_proofs=(
            _test_value_set_proof(60),
        ),
    )

    data = _ballot_proofs_to_data(proofs)

    assert len(data["r1_proofs"]) == 2
    assert data["r1_proofs"][0]["branches"][0] == {
        "commitment_1": 10,
        "commitment_2": 11,
        "challenge": 12,
        "response": 13,
    }

    assert data["r2_proof"]["branches"][0][
        "commitment_1"
    ] == 30

    assert data["r3_proofs"][0]["branches"][0][
        "commitment_1"
    ] == 40

    assert data["r4_proof"]["branches"][0][
        "commitment_1"
    ] == 50

    assert data["r5_proofs"][0]["branches"][0][
        "commitment_1"
    ] == 60


def _test_ballot() -> EncryptedBallot:
    """
    Crea una scheda cifrata semplice per i test del registro.
    """

    return EncryptedBallot(
        list_ciphertexts=(
            Ciphertext(alpha=10, beta=20),
        ),
        blank_ciphertext=Ciphertext(
            alpha=30,
            beta=40,
        ),
        preference_ciphertexts=(
            Ciphertext(alpha=50, beta=60),
        ),
    )


def _test_ballot_proofs() -> BallotProofs:
    """
    Crea un insieme semplice di prove R1-R5.
    """

    return BallotProofs(
        r1_proofs=(
            _test_value_set_proof(10),
            _test_value_set_proof(20),
            _test_value_set_proof(30),
        ),
        r2_proof=_test_value_set_proof(40),
        r3_proofs=(
            _test_value_set_proof(50),
        ),
        r4_proof=_test_value_set_proof(60),
        r5_proofs=(
            _test_value_set_proof(70),
        ),
    )


def _test_witness() -> BallotWitness:
    """
    Crea un witness semplice per una scheda SPOILED.
    """

    return BallotWitness(
        list_plaintexts=(1,),
        blank_plaintext=0,
        preference_plaintexts=(1,),
        list_nonces=(101,),
        blank_nonce=102,
        preference_nonces=(103,),
    )


def test_serializes_ballot_witness():
    """
    Il witness conserva plaintext e nonce rivelati.
    """

    witness = _test_witness()

    assert _ballot_witness_to_data(witness) == {
        "list_plaintexts": [1],
        "blank_plaintext": 0,
        "preference_plaintexts": [1],
        "list_nonces": [101],
        "blank_nonce": 102,
        "preference_nonces": [103],
    }


def test_cast_entry_does_not_publish_witness():
    """
    Una scheda CAST non contiene il witness nel registro.
    """

    entry = BoardEntry(
        sequence=1,
        district_index=0,
        state=CAST,
        ballot=_test_ballot(),
        proofs=_test_ballot_proofs(),
        ballot_hash=111,
        tracking_code=222,
        revealed_witness=None,
    )

    data = _board_entry_to_data(entry)

    assert data["sequence"] == 1
    assert data["district_index"] == 0
    assert data["state"] == CAST
    assert data["ballot_hash"] == 111
    assert data["tracking_code"] == 222
    assert "ballot" in data
    assert "proofs" in data
    assert "revealed_witness" not in data


def test_spoiled_entry_publishes_witness():
    """
    Una scheda SPOILED pubblica il witness necessario al controllo.
    """

    entry = BoardEntry(
        sequence=2,
        district_index=0,
        state=SPOILED,
        ballot=_test_ballot(),
        proofs=_test_ballot_proofs(),
        ballot_hash=333,
        tracking_code=444,
        revealed_witness=_test_witness(),
    )

    data = _board_entry_to_data(entry)

    assert data["state"] == SPOILED
    assert data["revealed_witness"] == {
        "list_plaintexts": [1],
        "blank_plaintext": 0,
        "preference_plaintexts": [1],
        "list_nonces": [101],
        "blank_nonce": 102,
        "preference_nonces": [103],
    }


def test_serializes_bulletin_board():
    """
    La bacheca conserva contesto, genesis e righe in ordine.
    """

    cast_entry = BoardEntry(
        sequence=1,
        district_index=0,
        state=CAST,
        ballot=_test_ballot(),
        proofs=_test_ballot_proofs(),
        ballot_hash=111,
        tracking_code=222,
        revealed_witness=None,
    )

    spoiled_entry = BoardEntry(
        sequence=2,
        district_index=0,
        state=SPOILED,
        ballot=_test_ballot(),
        proofs=_test_ballot_proofs(),
        ballot_hash=333,
        tracking_code=444,
        revealed_witness=_test_witness(),
    )

    board = BulletinBoard(
        extended_base_hash=999,
        genesis_code=888,
        entries=(
            cast_entry,
            spoiled_entry,
        ),
    )

    data = _bulletin_board_to_data(board)

    assert data["extended_base_hash"] == 999
    assert data["genesis_code"] == 888
    assert len(data["entries"]) == 2

    assert data["entries"][0]["sequence"] == 1
    assert data["entries"][0]["state"] == CAST
    assert "revealed_witness" not in data["entries"][0]

    assert data["entries"][1]["sequence"] == 2
    assert data["entries"][1]["state"] == SPOILED
    assert "revealed_witness" in data["entries"][1]


def test_serializes_district_tally():
    """
    Un tally conserva tutti i totali cifrati pubblici.
    """

    tally = DistrictTally(
        district_index=2,
        ballot_count=5,
        list_tallies=(
            Ciphertext(alpha=10, beta=20),
            Ciphertext(alpha=30, beta=40),
        ),
        blank_tally=Ciphertext(
            alpha=50,
            beta=60,
        ),
        preference_tallies=(
            Ciphertext(alpha=70, beta=80),
            Ciphertext(alpha=90, beta=100),
        ),
    )

    assert _district_tally_to_data(tally) == {
        "district_index": 2,
        "ballot_count": 5,
        "list_tallies": [
            {
                "alpha": 10,
                "beta": 20,
            },
            {
                "alpha": 30,
                "beta": 40,
            },
        ],
        "blank_tally": {
            "alpha": 50,
            "beta": 60,
        },
        "preference_tallies": [
            {
                "alpha": 70,
                "beta": 80,
            },
            {
                "alpha": 90,
                "beta": 100,
            },
        ],
    }


def test_serializes_district_result():
    """
    Un risultato conserva voti e share nell'ordine canonico.
    """

    first_share = DecryptionShare(
        guardian_index=1,
        partial_decryption=100,
        proof=ChaumPedersenProof(
            commitment_1=10,
            commitment_2=20,
            challenge=30,
            response=40,
        ),
    )

    second_share = DecryptionShare(
        guardian_index=2,
        partial_decryption=200,
        proof=ChaumPedersenProof(
            commitment_1=50,
            commitment_2=60,
            challenge=70,
            response=80,
        ),
    )

    result = DistrictResult(
        district_index=2,
        ballot_count=5,
        list_votes=(3, 1),
        blank_votes=1,
        preference_votes=(2, 1),
        decryption_shares=(
            (first_share, second_share),
            (first_share, second_share),
            (first_share, second_share),
            (first_share, second_share),
            (first_share, second_share),
        ),
    )

    data = _district_result_to_data(result)

    assert data["district_index"] == 2
    assert data["ballot_count"] == 5
    assert data["list_votes"] == [3, 1]
    assert data["blank_votes"] == 1
    assert data["preference_votes"] == [2, 1]

    assert len(data["decryption_shares"]) == 5

    assert data["decryption_shares"][0][0] == {
        "guardian_index": 1,
        "partial_decryption": 100,
        "proof": {
            "commitment_1": 10,
            "commitment_2": 20,
            "challenge": 30,
            "response": 40,
        },
    }

    assert data["decryption_shares"][0][1] == {
        "guardian_index": 2,
        "partial_decryption": 200,
        "proof": {
            "commitment_1": 50,
            "commitment_2": 60,
            "challenge": 70,
            "response": 80,
        },
    }


def test_serializes_election_config():
    """
    La configurazione torna nel formato pubblico ufficiale.
    """

    config = ElectionConfig(
        name="Elezione test",
        election_id=7,
        seats=10,
        rules=ElectoralRules(
            max_preferences=3,
            max_preferences_per_gender=2,
            list_threshold=Fraction(3, 100),
            coalition_threshold=Fraction(1, 10),
            bonus_threshold=Fraction(21, 50),
            bonus_seat_share=Fraction(11, 20),
        ),
        list_names=(
            "Lista A",
            "Lista B",
        ),
        coalitions=(
            Coalition(
                name="Coalizione X",
                list_indices=(0,),
            ),
        ),
        districts=(
            District(
                name="Nord",
                candidates=(
                    (
                        Candidate(
                            name="Rossi",
                            gender="M",
                        ),
                        Candidate(
                            name="Bianchi",
                            gender="F",
                        ),
                    ),
                    (
                        Candidate(
                            name="Verdi",
                            gender="F",
                        ),
                    ),
                ),
            ),
        ),
    )

    assert _election_config_to_data(config) == {
        "name": "Elezione test",
        "election_id": 7,
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
            {
                "name": "Lista A",
                "coalition": "Coalizione X",
            },
            {
                "name": "Lista B",
                "coalition": None,
            },
        ],
        "districts": [
            {
                "name": "Nord",
                "candidates": {
                    "Lista A": [
                        {
                            "name": "Rossi",
                            "gender": "M",
                        },
                        {
                            "name": "Bianchi",
                            "gender": "F",
                        },
                    ],
                    "Lista B": [
                        {
                            "name": "Verdi",
                            "gender": "F",
                        },
                    ],
                },
            },
        ],
    }


def test_serializes_scrutiny_result():
    """
    Lo scrutinio conserva seggi, competitori ed eletti.
    """

    result = ScrutinyResult(
        valid_votes=90,
        blank_votes=10,
        list_votes=(50, 40),
        coalition_votes=(50,),
        competitors=(
            Competitor(
                name="Coalizione X",
                list_indices=(0,),
                votes=50,
                is_coalition=True,
            ),
            Competitor(
                name="Lista B",
                list_indices=(1,),
                votes=40,
                is_coalition=False,
            ),
        ),
        competitor_seats=(6, 4),
        bonus_competitor=0,
        list_seats=(6, 4),
        district_list_seats=(
            (3, 2),
            (3, 2),
        ),
        elected=(
            ElectedCandidate(
                district_index=0,
                list_index=0,
                name="Rossi",
                position=0,
                preferences=0,
            ),
        ),
    )

    assert _scrutiny_result_to_data(result) == {
        "valid_votes": 90,
        "blank_votes": 10,
        "list_votes": [50, 40],
        "coalition_votes": [50],
        "competitors": [
            {
                "name": "Coalizione X",
                "list_indices": [0],
                "votes": 50,
                "is_coalition": True,
            },
            {
                "name": "Lista B",
                "list_indices": [1],
                "votes": 40,
                "is_coalition": False,
            },
        ],
        "competitor_seats": [6, 4],
        "bonus_competitor": 0,
        "list_seats": [6, 4],
        "district_list_seats": [
            [3, 2],
            [3, 2],
        ],
        "elected": [
            {
                "district_index": 0,
                "list_index": 0,
                "name": "Rossi",
                "position": 0,
                "preferences": 0,
            },
        ],
    }