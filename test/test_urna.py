"""
Test unitari per evoto.urna.

L'aggregazione usa i tre cifrati dell'esempio numerico della specifica,
sezione 38, che aggregati danno il tally (1196, 154).

La bacheca usa la cerimonia della stessa sezione: tre garanti con
quorum 2, chiave pubblica 530 e contesto Q_bar = 744.
"""

from dataclasses import replace

import pytest

from evoto.elgamal import Ciphertext, encrypt
from evoto.garanti import run_key_ceremony
from evoto.gruppo import H, TEST_PARAMS
from evoto.scheda import BallotLayout, PreferenceMetadata
from evoto.urna import (
    CAST,
    SPOILED,
    aggregate_ciphertexts,
    cast_ballot,
    cast_voter_ballot,
    compute_ballot_hash,
    compute_genesis_code,
    compute_tracking_code,
    create_bulletin_board,
    create_voter_roll,
    decrypt_district_tally,
    find_entry,
    spoil_ballot,
    submit_ballot,
    tally_district,
    verify_board_chain,
    verify_spoiled_ballot,
)
from evoto.voto import VoterChoice, prepare_ballot


REFERENCE_CIPHERTEXTS = (
    Ciphertext(alpha=850, beta=2375),
    Ciphertext(alpha=380, beta=22),
    Ciphertext(alpha=625, beta=670),
)

CEREMONY = run_key_ceremony(
    guardian_count=3,
    quorum=2,
    params=TEST_PARAMS,
    election_id=1,
    coefficients=((300, 40), (400, 50), (65, 10)),
)

PUBLIC_KEY = CEREMONY.joint_public_key
CONTEXT = CEREMONY.extended_base_hash

LAYOUT = BallotLayout(
    list_count=2,
    max_preferences=3,
    max_preferences_per_gender=2,
    preference_metadata=(
        PreferenceMetadata(list_index=0, gender="F"),
        PreferenceMetadata(list_index=0, gender="M"),
        PreferenceMetadata(list_index=1, gender="F"),
        PreferenceMetadata(list_index=1, gender="M"),
    ),
)


def prepare(choice: VoterChoice, district_index: int = 0):
    """
    Prepara una scheda per la bacheca di prova.
    """

    return prepare_ballot(
        layout=LAYOUT,
        district_index=district_index,
        choice=choice,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        extended_base_hash=CONTEXT,
    )


def cast(board, prepared):
    """
    Deposita una scheda preparata.
    """

    return cast_ballot(
        board=board,
        district_index=prepared.district_index,
        layout=LAYOUT,
        ballot=prepared.ballot,
        proofs=prepared.proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
    )


def spoil(board, prepared, witness=None):
    """
    Pubblica una scheda sprecata con i dati che la aprono.
    """

    return spoil_ballot(
        board=board,
        district_index=prepared.district_index,
        layout=LAYOUT,
        ballot=prepared.ballot,
        proofs=prepared.proofs,
        witness=prepared.witness if witness is None else witness,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
    )


def empty_board():
    """
    Bacheca vuota per l'elezione di prova.
    """

    return create_bulletin_board(CONTEXT, TEST_PARAMS)


def test_aggregate_reference_vector():
    """
    Il prodotto dei cifrati dei voti 1, 0, 1 è il tally dell'esempio.
    """

    tally = aggregate_ciphertexts(
        REFERENCE_CIPHERTEXTS,
        TEST_PARAMS,
    )

    assert tally == Ciphertext(alpha=1196, beta=154)


def test_aggregate_without_ciphertexts():
    """
    Senza schede il tally è Enc(0), cioè l'elemento neutro (1, 1).
    """

    tally = aggregate_ciphertexts((), TEST_PARAMS)

    assert tally == Ciphertext(alpha=1, beta=1)


def test_aggregate_of_a_single_ciphertext():
    """
    Con una sola scheda il tally coincide con la scheda stessa.
    """

    ciphertext = encrypt(
        message=1,
        public_key=530,
        params=TEST_PARAMS,
        nonce=11,
    )

    tally = aggregate_ciphertexts(
        (ciphertext,),
        TEST_PARAMS,
    )

    assert tally == ciphertext


def test_genesis_code_is_the_hash_of_the_context():
    """
    Il primo anello della catena è H(Q_bar).
    """

    board = empty_board()

    assert board.genesis_code == H(CONTEXT, params=TEST_PARAMS)
    assert board.genesis_code == compute_genesis_code(CONTEXT, TEST_PARAMS)
    assert board.last_tracking_code() == board.genesis_code


def test_ballot_hash_formula():
    """
    L'impronta è H(Q_bar, d, alpha_1, beta_1, ..., alpha_m, beta_m).
    """

    prepared = prepare(VoterChoice(list_index=0))

    values = [CONTEXT, 0]

    for ciphertext in prepared.ballot.all_ciphertexts():
        values.extend([ciphertext.alpha, ciphertext.beta])

    assert compute_ballot_hash(
        prepared.ballot,
        0,
        CONTEXT,
        TEST_PARAMS,
    ) == H(*values, params=TEST_PARAMS)


def test_tracking_code_formula():
    """
    Il codice è H(codice precedente, posizione, stato, impronta),
    con lo stato codificato come 1 per CAST e 2 per SPOILED.
    """

    assert compute_tracking_code(
        100,
        3,
        SPOILED,
        200,
        TEST_PARAMS,
    ) == H(100, 3, 2, 200, params=TEST_PARAMS)


def test_cast_ballot_is_appended_to_the_chain():
    """
    La prima scheda ha posizione 1 e si concatena al codice iniziale.
    """

    prepared = prepare(VoterChoice(list_index=1, preferences=(2,)))

    board = cast(empty_board(), prepared)

    entry = board.entries[0]

    assert entry.sequence == 1
    assert entry.state == CAST
    assert entry.revealed_witness is None
    assert entry.ballot_hash == prepared.ballot_hash
    assert entry.tracking_code == compute_tracking_code(
        board.genesis_code,
        1,
        CAST,
        prepared.ballot_hash,
        TEST_PARAMS,
    )
    assert board.last_tracking_code() == entry.tracking_code


def test_board_is_append_only():
    """
    Depositare una scheda non modifica la bacheca precedente.
    """

    board = empty_board()

    new_board = cast(board, prepare(VoterChoice(list_index=0)))

    assert board.entries == ()
    assert len(new_board.entries) == 1


def test_spoiled_ballot_reveals_its_content():
    """
    Una scheda sprecata viene pubblicata con voti e nonce,
    e chiunque può ricifrarla.
    """

    prepared = prepare(VoterChoice(list_index=0, preferences=(1,)))

    board = spoil(empty_board(), prepared)

    entry = board.entries[0]

    assert entry.state == SPOILED
    assert entry.revealed_witness == prepared.witness
    assert verify_spoiled_ballot(
        entry.ballot,
        entry.revealed_witness,
        PUBLIC_KEY,
        TEST_PARAMS,
    )


def test_spoiled_ballot_with_wrong_witness_is_rejected():
    """
    Se il dispositivo avesse cifrato un voto diverso da quello dichiarato,
    la ricifratura non corrisponderebbe e la bacheca lo rifiuta.
    """

    prepared = prepare(VoterChoice(list_index=0))
    other = prepare(VoterChoice(list_index=1))

    with pytest.raises(ValueError):
        spoil(empty_board(), prepared, witness=other.witness)


def test_cast_ballot_cannot_reveal_its_content():
    """
    Una scheda depositata non deve portare con sé il voto.
    """

    prepared = prepare(VoterChoice(list_index=0))

    with pytest.raises(ValueError):
        submit_ballot(
            board=empty_board(),
            district_index=0,
            layout=LAYOUT,
            ballot=prepared.ballot,
            proofs=prepared.proofs,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            state=CAST,
            revealed_witness=prepared.witness,
        )


def test_ballot_with_invalid_proofs_is_rejected():
    """
    La bacheca accetta solo schede con prove R1-R5 valide.
    """

    first = prepare(VoterChoice(list_index=0))
    second = prepare(VoterChoice(list_index=1))

    with pytest.raises(ValueError):
        cast_ballot(
            board=empty_board(),
            district_index=0,
            layout=LAYOUT,
            ballot=first.ballot,
            proofs=second.proofs,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
        )


def test_copied_ballot_is_rejected():
    """
    Una scheda identica a una già presente viene rifiutata.

    Senza questo controllo un elettore potrebbe ricopiare la scheda
    di un altro e votare come lui (Cortier e Smyth, 2011).
    """

    prepared = prepare(VoterChoice(list_index=0))

    board = cast(empty_board(), prepared)

    with pytest.raises(ValueError):
        cast(board, prepared)


def test_spoiled_ballot_cannot_be_cast_later():
    """
    Una scheda sprecata ha rivelato il voto: non si può più depositare.
    """

    prepared = prepare(VoterChoice(list_index=0))

    board = spoil(empty_board(), prepared)

    with pytest.raises(ValueError):
        cast(board, prepared)


def board_with_three_ballots():
    """
    Bacheca con due schede depositate e una sprecata.
    """

    board = empty_board()
    board = cast(board, prepare(VoterChoice(list_index=0)))
    board = spoil(board, prepare(VoterChoice(list_index=1)))
    board = cast(board, prepare(VoterChoice(list_index=None)))

    return board


def test_chain_is_valid():
    """
    Una bacheca costruita correttamente supera il controllo V4.
    """

    assert verify_board_chain(board_with_three_ballots(), TEST_PARAMS)


def test_chain_detects_a_changed_state():
    """
    Cambiare una scheda da CAST a SPOILED rompe la catena.
    """

    board = board_with_three_ballots()

    tampered = replace(
        board,
        entries=(
            replace(board.entries[0], state=SPOILED),
        ) + board.entries[1:],
    )

    assert not verify_board_chain(tampered, TEST_PARAMS)


def test_chain_detects_a_removed_ballot():
    """
    Togliere una scheda rompe la catena.
    """

    board = board_with_three_ballots()

    tampered = replace(
        board,
        entries=(board.entries[0], board.entries[2]),
    )

    assert not verify_board_chain(tampered, TEST_PARAMS)


def test_chain_detects_a_replaced_ciphertext():
    """
    Sostituire un cifrato cambia l'impronta della scheda.
    """

    board = board_with_three_ballots()
    entry = board.entries[0]

    tampered_ballot = replace(
        entry.ballot,
        blank_ciphertext=Ciphertext(alpha=1, beta=1),
    )

    tampered = replace(
        board,
        entries=(replace(entry, ballot=tampered_ballot),)
        + board.entries[1:],
    )

    assert not verify_board_chain(tampered, TEST_PARAMS)


def test_voter_finds_the_tracking_code():
    """
    L'elettore ritrova la sua scheda con il codice ricevuto.
    """

    board = board_with_three_ballots()

    code = board.entries[2].tracking_code

    assert find_entry(board, code) == board.entries[2]


def test_voter_roll_allows_a_single_vote():
    """
    Ogni avente diritto vota una sola volta, nella sua circoscrizione.
    """

    roll = create_voter_roll({"anna": 0, "bruno": 1})
    board = empty_board()

    prepared = prepare(VoterChoice(list_index=0))

    board, roll = cast_voter_ballot(
        board=board,
        roll=roll,
        voter_id="anna",
        district_index=0,
        layout=LAYOUT,
        ballot=prepared.ballot,
        proofs=prepared.proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
    )

    assert roll.voted == frozenset({"anna"})

    second = prepare(VoterChoice(list_index=1))

    for voter_id, district_index in (
        ("anna", 0),
        ("bruno", 0),
        ("carla", 0),
    ):
        with pytest.raises(ValueError):
            cast_voter_ballot(
                board=board,
                roll=roll,
                voter_id=voter_id,
                district_index=district_index,
                layout=LAYOUT,
                ballot=second.ballot,
                proofs=second.proofs,
                public_key=PUBLIC_KEY,
                params=TEST_PARAMS,
            )


def test_rejected_ballot_does_not_consume_the_vote():
    """
    Se la scheda viene rifiutata, l'elettore può ancora votare.
    """

    roll = create_voter_roll({"anna": 0})

    first = prepare(VoterChoice(list_index=0))
    second = prepare(VoterChoice(list_index=1))

    with pytest.raises(ValueError):
        cast_voter_ballot(
            board=empty_board(),
            roll=roll,
            voter_id="anna",
            district_index=0,
            layout=LAYOUT,
            ballot=first.ballot,
            proofs=second.proofs,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
        )

    assert roll.voted == frozenset()


def test_tally_counts_only_cast_ballots_of_the_district():
    """
    Il conteggio usa solo le schede CAST della circoscrizione,
    e la decifratura restituisce i totali in chiaro.
    """

    board = empty_board()
    board = cast(board, prepare(VoterChoice(list_index=0, preferences=(0,))))
    board = cast(board, prepare(VoterChoice(list_index=0, preferences=(0, 1))))
    board = spoil(board, prepare(VoterChoice(list_index=1)))
    board = cast(board, prepare(VoterChoice(list_index=None)))
    board = cast(board, prepare(VoterChoice(list_index=1), district_index=1))

    tally = tally_district(board, 0, LAYOUT, TEST_PARAMS)

    assert tally.ballot_count == 3

    result = decrypt_district_tally(
        tally=tally,
        secret_shares=CEREMONY.secret_shares,
        present_guardians=(1, 3),
        records=CEREMONY.records,
        quorum=2,
        params=TEST_PARAMS,
        extended_base_hash=CONTEXT,
    )

    assert result.list_votes == (2, 0)
    assert result.blank_votes == 1
    assert result.preference_votes == (2, 1, 0, 0)
    assert len(result.decryption_shares) == 2 + 1 + 4


def test_empty_district_decrypts_to_zero():
    """
    Una circoscrizione senza schede ha tutti i totali a zero.
    """

    tally = tally_district(empty_board(), 0, LAYOUT, TEST_PARAMS)

    result = decrypt_district_tally(
        tally=tally,
        secret_shares=CEREMONY.secret_shares,
        present_guardians=(2, 3),
        records=CEREMONY.records,
        quorum=2,
        params=TEST_PARAMS,
        extended_base_hash=CONTEXT,
    )

    assert result.ballot_count == 0
    assert result.list_votes == (0, 0)
    assert result.blank_votes == 0
    assert result.preference_votes == (0, 0, 0, 0)


def test_district_decryption_requires_the_quorum():
    """
    Un solo garante su tre non basta.
    """

    tally = tally_district(empty_board(), 0, LAYOUT, TEST_PARAMS)

    with pytest.raises(ValueError):
        decrypt_district_tally(
            tally=tally,
            secret_shares=CEREMONY.secret_shares,
            present_guardians=(1,),
            records=CEREMONY.records,
            quorum=2,
            params=TEST_PARAMS,
            extended_base_hash=CONTEXT,
        )
