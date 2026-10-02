"""
Test del modello della scheda politica.

Verifichiamo:
- le regole R1-R5;
- le strutture pubbliche e private della scheda;
- la generazione coordinata delle prove;
- la verifica completa della scheda politica.
"""
from dataclasses import replace

import pytest

from evoto.elgamal import (
    encrypt,
    public_key_from_secret,
)
from evoto.gruppo import TEST_PARAMS
from evoto.scheda import (
    BallotLayout,
    BallotProofs,
    BallotWitness,
    EncryptedBallot,
    PreferenceMetadata,
    _group_preference_indices_by_gender,
    _prove_ballot_r1_r2,
    _prove_ballot_r3,
    _prove_ballot_r4,
    _prove_ballot_r5,
    _validate_ballot_alignment,
    prove_ballot,
    prove_r1,
    prove_r2,
    prove_r3,
    prove_r4,
    prove_r5,
    verify_ballot,
    verify_r1,
    verify_r2,
    verify_r3,
    verify_r4,
    verify_r5,
)


PUBLIC_KEY = public_key_from_secret(
    123,
    TEST_PARAMS,
)

CONTEXT = 744

def _build_valid_ballot_case():
    """
    Costruisce una scheda politica valida completa per i test.
    """

    layout = BallotLayout(
        list_count=2,
        preference_metadata=(
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=0, gender="M"),
            PreferenceMetadata(list_index=1, gender="F"),
            PreferenceMetadata(list_index=1, gender="M"),
        ),
        max_preferences=3,
        max_preferences_per_gender=2,
    )

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=20),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=30,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=40),
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=50),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=60),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=70),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1, 0),
        blank_plaintext=0,
        preference_plaintexts=(1, 1, 0, 0),
        list_nonces=(10, 20),
        blank_nonce=30,
        preference_nonces=(40, 50, 60, 70),
    )

    proofs = prove_ballot(
        layout=layout,
        ballot=ballot,
        witness=witness,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    return layout, ballot, witness, proofs


@pytest.mark.parametrize("value", [0, 1])
def test_r1_accepts_binary_value(value):
    """R1 deve accettare sia 0 sia 1."""

    nonce = 50 + value

    ciphertext = encrypt(
        value,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=nonce,
    )

    proof = prove_r1(
        ciphertext=ciphertext,
        plaintext=value,
        nonce=nonce,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r1(
        ciphertext=ciphertext,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_r1_rejects_non_binary_plaintext():
    """R1 non deve permettere di provare il valore 2."""

    ciphertext = encrypt(
        2,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=52,
    )

    with pytest.raises(ValueError):
        prove_r1(
            ciphertext=ciphertext,
            plaintext=2,
            nonce=52,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r2_accepts_exactly_one_choice():
    """R2 accetta una sola scelta tra liste e scheda bianca."""

    plaintexts = (0, 1, 0)
    nonces = (10, 20, 30)

    ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(plaintexts, nonces)
    )

    proof = prove_r2(
        ciphertexts=ciphertexts,
        plaintexts=plaintexts,
        nonces=nonces,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r2(
        ciphertexts=ciphertexts,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


@pytest.mark.parametrize(
    "plaintexts",
    [
        (0, 0, 0),
        (1, 1, 0),
    ],
)
def test_r2_rejects_invalid_number_of_choices(plaintexts):
    """R2 rifiuta zero scelte o più di una scelta."""

    nonces = (10, 20, 30)

    ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(plaintexts, nonces)
    )

    with pytest.raises(ValueError):
        prove_r2(
            ciphertexts=ciphertexts,
            plaintexts=plaintexts,
            nonces=nonces,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r2_accepts_zero_derived_nonce():
    """
    R2 deve accettare una randomness aggregata uguale a 0 modulo q.
    """

    plaintexts = (1, 0)
    nonces = (600, 689)

    assert sum(nonces) % TEST_PARAMS.q == 0

    ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(plaintexts, nonces)
    )

    proof = prove_r2(
        ciphertexts=ciphertexts,
        plaintexts=plaintexts,
        nonces=nonces,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r2(
        ciphertexts=ciphertexts,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


@pytest.mark.parametrize(
    ("list_value", "preference_value"),
    [
        (0, 0),
        (1, 0),
        (1, 1),
    ],
)
def test_r3_accepts_valid_preference_relation(
    list_value,
    preference_value,
):
    """
    R3 accetta tutti i casi coerenti tra lista e preferenza.
    """

    list_nonce = 100
    preference_nonce = 40

    list_ciphertext = encrypt(
        list_value,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=list_nonce,
    )

    preference_ciphertext = encrypt(
        preference_value,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=preference_nonce,
    )

    proof = prove_r3(
        list_ciphertext=list_ciphertext,
        preference_ciphertext=preference_ciphertext,
        list_plaintext=list_value,
        preference_plaintext=preference_value,
        list_nonce=list_nonce,
        preference_nonce=preference_nonce,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r3(
        list_ciphertext=list_ciphertext,
        preference_ciphertext=preference_ciphertext,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_r3_rejects_preference_outside_selected_list():
    """
    R3 rifiuta una preferenza quando la lista non è selezionata.
    """

    list_ciphertext = encrypt(
        0,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=100,
    )

    preference_ciphertext = encrypt(
        1,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=40,
    )

    with pytest.raises(ValueError):
        prove_r3(
            list_ciphertext=list_ciphertext,
            preference_ciphertext=preference_ciphertext,
            list_plaintext=0,
            preference_plaintext=1,
            list_nonce=100,
            preference_nonce=40,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r3_accepts_zero_derived_nonce():
    """
    R3 deve accettare una randomness derivata uguale a 0 modulo q.
    """

    list_nonce = 600
    preference_nonce = 600

    assert (
        list_nonce - preference_nonce
    ) % TEST_PARAMS.q == 0

    list_ciphertext = encrypt(
        1,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=list_nonce,
    )

    preference_ciphertext = encrypt(
        1,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=preference_nonce,
    )

    proof = prove_r3(
        list_ciphertext=list_ciphertext,
        preference_ciphertext=preference_ciphertext,
        list_plaintext=1,
        preference_plaintext=1,
        list_nonce=list_nonce,
        preference_nonce=preference_nonce,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r3(
        list_ciphertext=list_ciphertext,
        preference_ciphertext=preference_ciphertext,
        proof=proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


@pytest.mark.parametrize(
    "preference_plaintexts",
    [
        (0, 0, 0, 0),
        (1, 0, 0, 0),
        (1, 1, 0, 0),
        (1, 1, 1, 0),
    ],
)
def test_r4_accepts_up_to_three_preferences(
    preference_plaintexts,
):
    """
    R4 accetta da zero a tre preferenze complessive.
    """

    preference_nonces = (10, 20, 30, 40)

    preference_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            preference_plaintexts,
            preference_nonces,
        )
    )

    proof = prove_r4(
        preference_ciphertexts=preference_ciphertexts,
        preference_plaintexts=preference_plaintexts,
        preference_nonces=preference_nonces,
        max_preferences=3,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r4(
        preference_ciphertexts=preference_ciphertexts,
        proof=proof,
        max_preferences=3,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_r4_rejects_four_preferences():
    """
    R4 rifiuta una scheda con quattro preferenze.
    """

    preference_plaintexts = (1, 1, 1, 1)
    preference_nonces = (10, 20, 30, 40)

    preference_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            preference_plaintexts,
            preference_nonces,
        )
    )

    with pytest.raises(ValueError):
        prove_r4(
            preference_ciphertexts=preference_ciphertexts,
            preference_plaintexts=preference_plaintexts,
            preference_nonces=preference_nonces,
            max_preferences=3,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r4_accepts_zero_derived_nonce():
    """
    R4 accetta una randomness aggregata uguale a 0 modulo q.
    """

    preference_plaintexts = (1, 1)
    preference_nonces = (600, 689)

    assert sum(preference_nonces) % TEST_PARAMS.q == 0

    preference_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            preference_plaintexts,
            preference_nonces,
        )
    )

    proof = prove_r4(
        preference_ciphertexts=preference_ciphertexts,
        preference_plaintexts=preference_plaintexts,
        preference_nonces=preference_nonces,
        max_preferences=3,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r4(
        preference_ciphertexts=preference_ciphertexts,
        proof=proof,
        max_preferences=3,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


@pytest.mark.parametrize(
    "gender_plaintexts",
    [
        (0, 0, 0),
        (1, 0, 0),
        (1, 1, 0),
    ],
)
def test_r5_accepts_up_to_two_preferences_same_gender(
    gender_plaintexts,
):
    """
    R5 accetta da zero a due preferenze dello stesso genere.
    """

    gender_nonces = (10, 20, 30)

    gender_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            gender_plaintexts,
            gender_nonces,
        )
    )

    proof = prove_r5(
        gender_ciphertexts=gender_ciphertexts,
        gender_plaintexts=gender_plaintexts,
        gender_nonces=gender_nonces,
        max_preferences_per_gender=2,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r5(
        gender_ciphertexts=gender_ciphertexts,
        proof=proof,
        max_preferences_per_gender=2,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_r5_rejects_three_preferences_same_gender():
    """
    R5 rifiuta tre preferenze appartenenti allo stesso genere.
    """

    gender_plaintexts = (1, 1, 1)
    gender_nonces = (10, 20, 30)

    gender_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            gender_plaintexts,
            gender_nonces,
        )
    )

    with pytest.raises(ValueError):
        prove_r5(
            gender_ciphertexts=gender_ciphertexts,
            gender_plaintexts=gender_plaintexts,
            gender_nonces=gender_nonces,
            max_preferences_per_gender=2,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r5_accepts_zero_derived_nonce():
    """
    R5 accetta una randomness aggregata uguale a 0 modulo q.
    """

    gender_plaintexts = (1, 1)
    gender_nonces = (600, 689)

    assert sum(gender_nonces) % TEST_PARAMS.q == 0

    gender_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            gender_plaintexts,
            gender_nonces,
        )
    )

    proof = prove_r5(
        gender_ciphertexts=gender_ciphertexts,
        gender_plaintexts=gender_plaintexts,
        gender_nonces=gender_nonces,
        max_preferences_per_gender=2,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r5(
        gender_ciphertexts=gender_ciphertexts,
        proof=proof,
        max_preferences_per_gender=2,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_encrypted_ballot_contains_all_ciphertexts_in_order():
    """
    La scheda cifrata espone tutte le caselle nell'ordine previsto.
    """

    list_ciphertexts = (
        encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
        encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=20),
    )

    blank_ciphertext = encrypt(
        0,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=30,
    )

    preference_ciphertexts = (
        encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=40),
        encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=50),
    )

    ballot = EncryptedBallot(
        list_ciphertexts=list_ciphertexts,
        blank_ciphertext=blank_ciphertext,
        preference_ciphertexts=preference_ciphertexts,
    )

    assert ballot.all_ciphertexts() == (
        list_ciphertexts
        + (blank_ciphertext,)
        + preference_ciphertexts
    )


def test_ballot_proofs_groups_all_rules():
    """
    Le prove della scheda devono poter essere raccolte
    in un'unica struttura pubblica.
    """

    ciphertext = encrypt(
        1,
        PUBLIC_KEY,
        TEST_PARAMS,
        nonce=10,
    )

    proof = prove_r1(
        ciphertext=ciphertext,
        plaintext=1,
        nonce=10,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    proofs = BallotProofs(
        r1_proofs=(proof,),
        r2_proof=proof,
        r3_proofs=(proof,),
        r4_proof=proof,
        r5_proofs=(proof, proof),
    )

    assert proofs.r1_proofs == (proof,)
    assert proofs.r2_proof == proof
    assert proofs.r3_proofs == (proof,)
    assert proofs.r4_proof == proof
    assert proofs.r5_proofs == (proof, proof)


def test_preference_metadata_stores_list_and_gender():
    """
    I metadati di una preferenza identificano lista e genere.
    """

    metadata = PreferenceMetadata(
        list_index=1,
        gender="F",
    )

    assert metadata.list_index == 1
    assert metadata.gender == "F"


def test_ballot_layout_stores_official_preference_metadata():
    """
    La configurazione contiene i metadati ufficiali delle preferenze.
    """

    metadata = (
        PreferenceMetadata(list_index=0, gender="F"),
        PreferenceMetadata(list_index=1, gender="M"),
    )

    layout = BallotLayout(
        list_count=2,
        preference_metadata=metadata,
        max_preferences=3,
        max_preferences_per_gender=2,
    )

    assert layout.list_count == 2
    assert layout.preference_metadata == metadata


def test_ballot_layout_rejects_invalid_list_index():
    """
    La configurazione rifiuta preferenze associate
    a una lista inesistente.
    """

    with pytest.raises(ValueError):
        BallotLayout(
            list_count=1,
            max_preferences=3,
            max_preferences_per_gender=2,
            preference_metadata=(
                PreferenceMetadata(
                    list_index=1,
                    gender="F",
                ),
            ),
        )


def test_ballot_witness_stores_private_ballot_data():
    """
    Il witness raccoglie plaintext e nonce necessari alle prove.
    """

    witness = BallotWitness(
        list_plaintexts=(1, 0),
        blank_plaintext=0,
        preference_plaintexts=(1, 0),
        list_nonces=(10, 20),
        blank_nonce=30,
        preference_nonces=(40, 50),
    )

    assert witness.list_plaintexts == (1, 0)
    assert witness.blank_plaintext == 0
    assert witness.preference_plaintexts == (1, 0)

    assert witness.list_nonces == (10, 20)
    assert witness.blank_nonce == 30
    assert witness.preference_nonces == (40, 50)


def test_ballot_witness_rejects_mismatched_lengths():
    """
    Ogni plaintext deve avere il nonce corrispondente.
    """

    with pytest.raises(ValueError):
        BallotWitness(
            list_plaintexts=(1, 0),
            blank_plaintext=0,
            preference_plaintexts=(1,),
            list_nonces=(10,),
            blank_nonce=30,
            preference_nonces=(40,),
        )


def test_layout_ballot_and_witness_must_match():
    """
    Configurazione, scheda pubblica e witness
    devono descrivere la stessa struttura.
    """

    layout = BallotLayout(
        list_count=1,
        max_preferences=3,
        max_preferences_per_gender=2,
        preference_metadata=(
            PreferenceMetadata(
                list_index=0,
                gender="F",
            ),
        ),
    )

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=20,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=30),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1, 0),
        blank_plaintext=0,
        preference_plaintexts=(1,),
        list_nonces=(10, 40),
        blank_nonce=20,
        preference_nonces=(30,),
    )

    with pytest.raises(ValueError):
        _validate_ballot_alignment(
            layout,
            ballot,
            witness,
        )


def test_prove_ballot_r1_r2_generates_valid_proofs():
    """
    La scheda completa genera prove R1 e R2 verificabili.
    """

    layout = BallotLayout(
        list_count=2,
        max_preferences=3,
        max_preferences_per_gender=2,
        preference_metadata=(
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=1, gender="M"),
        ),
    )

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=20),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=30,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=40),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=50),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1, 0),
        blank_plaintext=0,
        preference_plaintexts=(1, 0),
        list_nonces=(10, 20),
        blank_nonce=30,
        preference_nonces=(40, 50),
    )

    r1_proofs, r2_proof = _prove_ballot_r1_r2(
        layout=layout,
        ballot=ballot,
        witness=witness,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert len(r1_proofs) == 5

    for ciphertext, proof in zip(
        ballot.all_ciphertexts(),
        r1_proofs,
    ):
        assert verify_r1(
            ciphertext=ciphertext,
            proof=proof,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )

    assert verify_r2(
        ciphertexts=(
            ballot.list_ciphertexts
            + (ballot.blank_ciphertext,)
        ),
        proof=r2_proof,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_prove_ballot_r3_generates_valid_proofs():
    """
    R3 deve usare automaticamente la lista associata
    a ciascuna preferenza.
    """

    layout = BallotLayout(
        list_count=2,
        max_preferences=3,
        max_preferences_per_gender=2,
        preference_metadata=(
            PreferenceMetadata(
                list_index=0,
                gender="F",
            ),
            PreferenceMetadata(
                list_index=1,
                gender="M",
            ),
        ),
    )

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=20),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=30,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=40),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=50),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1, 0),
        blank_plaintext=0,
        preference_plaintexts=(1, 0),
        list_nonces=(10, 20),
        blank_nonce=30,
        preference_nonces=(40, 50),
    )

    proofs = _prove_ballot_r3(
        layout=layout,
        ballot=ballot,
        witness=witness,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert len(proofs) == 2

    for index, proof in enumerate(proofs):
        metadata = layout.preference_metadata[index]

        assert verify_r3(
            list_ciphertext=ballot.list_ciphertexts[
                metadata.list_index
            ],
            preference_ciphertext=(
                ballot.preference_ciphertexts[index]
            ),
            proof=proof,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_prove_ballot_r4_generates_valid_proof():
    """
    R4 deve verificare il numero complessivo di preferenze.
    """

    layout = BallotLayout(
        list_count=2,
        max_preferences=3,
        max_preferences_per_gender=2,
        preference_metadata=(
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=0, gender="M"),
            PreferenceMetadata(list_index=1, gender="F"),
        ),
    )

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=20),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=30,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=40),
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=50),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=60),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1, 0),
        blank_plaintext=0,
        preference_plaintexts=(1, 1, 0),
        list_nonces=(10, 20),
        blank_nonce=30,
        preference_nonces=(40, 50, 60),
    )

    proof = _prove_ballot_r4(
        layout=layout,
        ballot=ballot,
        witness=witness,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r4(
        preference_ciphertexts=ballot.preference_ciphertexts,
        proof=proof,
        max_preferences=3,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_prove_ballot_r5_generates_valid_proofs_by_gender():
    """
    R5 deve raggruppare automaticamente le preferenze per genere.
    """

    layout = BallotLayout(
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

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=20),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=30,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=40),
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=50),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=60),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=70),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1, 0),
        blank_plaintext=0,
        preference_plaintexts=(1, 1, 0, 0),
        list_nonces=(10, 20),
        blank_nonce=30,
        preference_nonces=(40, 50, 60, 70),
    )

    proofs = _prove_ballot_r5(
        layout=layout,
        ballot=ballot,
        witness=witness,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    groups = _group_preference_indices_by_gender(
        layout
    )

    assert len(proofs) == 2
    assert groups == (
        (0, 2),
        (1, 3),
    )

    for indices, proof in zip(
        groups,
        proofs,
    ):
        gender_ciphertexts = tuple(
            ballot.preference_ciphertexts[index]
            for index in indices
        )

        assert verify_r5(
            gender_ciphertexts=gender_ciphertexts,
            proof=proof,
            max_preferences_per_gender=2,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_complete_ballot_proofs_are_valid():
    """
    Una scheda politica valida deve produrre
    un insieme completo di prove R1-R5 verificabili.
    """

    layout = BallotLayout(
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

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=20),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=30,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=40),
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=50),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=60),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=70),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1, 0),
        blank_plaintext=0,
        preference_plaintexts=(1, 1, 0, 0),
        list_nonces=(10, 20),
        blank_nonce=30,
        preference_nonces=(40, 50, 60, 70),
    )

    proofs = prove_ballot(
        layout=layout,
        ballot=ballot,
        witness=witness,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_ballot(
        layout=layout,
        ballot=ballot,
        proofs=proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_verify_ballot_rejects_missing_r1_proof():
    """
    La verifica fallisce se manca una prova R1.
    """

    layout = BallotLayout(
        list_count=1,
        max_preferences=3,
        max_preferences_per_gender=2,
        preference_metadata=(
            PreferenceMetadata(
                list_index=0,
                gender="F",
            ),
        ),
    )

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=20,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=30),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1,),
        blank_plaintext=0,
        preference_plaintexts=(1,),
        list_nonces=(10,),
        blank_nonce=20,
        preference_nonces=(30,),
    )

    proofs = prove_ballot(
        layout=layout,
        ballot=ballot,
        witness=witness,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    incomplete_proofs = BallotProofs(
        r1_proofs=proofs.r1_proofs[:-1],
        r2_proof=proofs.r2_proof,
        r3_proofs=proofs.r3_proofs,
        r4_proof=proofs.r4_proof,
        r5_proofs=proofs.r5_proofs,
    )

    assert not verify_ballot(
        layout=layout,
        ballot=ballot,
        proofs=incomplete_proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_ballot_cannot_choose_its_own_preference_metadata():
    """
    Lista e genere delle preferenze provengono dal layout
    ufficiale e non dalla scheda cifrata.
    """

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=20,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=30),
        ),
    )

    assert not hasattr(
        ballot,
        "preference_metadata",
    )


def test_verify_ballot_rejects_tampered_r1_proof():
    """
    La verifica fallisce se una prova R1 viene manomessa.
    """

    layout, ballot, _, proofs = _build_valid_ballot_case()

    original_proof = proofs.r1_proofs[0]
    original_branch = original_proof.branches[0]

    tampered_branch = replace(
        original_branch,
        response=(
            original_branch.response + 1
        ) % TEST_PARAMS.q,
    )

    tampered_proof = replace(
        original_proof,
        branches=(
            tampered_branch,
            *original_proof.branches[1:],
        ),
    )

    tampered_proofs = replace(
        proofs,
        r1_proofs=(
            tampered_proof,
            *proofs.r1_proofs[1:],
        ),
    )

    assert not verify_ballot(
        layout=layout,
        ballot=ballot,
        proofs=tampered_proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_verify_ballot_rejects_tampered_r3_proof():
    """
    La verifica fallisce se una prova R3 viene manomessa.
    """

    layout, ballot, _, proofs = _build_valid_ballot_case()

    original_proof = proofs.r3_proofs[0]
    original_branch = original_proof.branches[0]

    tampered_branch = replace(
        original_branch,
        challenge=(
            original_branch.challenge + 1
        ) % TEST_PARAMS.q,
    )

    tampered_proof = replace(
        original_proof,
        branches=(
            tampered_branch,
            *original_proof.branches[1:],
        ),
    )

    tampered_proofs = replace(
        proofs,
        r3_proofs=(
            tampered_proof,
            *proofs.r3_proofs[1:],
        ),
    )

    assert not verify_ballot(
        layout=layout,
        ballot=ballot,
        proofs=tampered_proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_verify_ballot_rejects_ballot_with_wrong_preference_count():
    """
    La verifica fallisce se la scheda non rispetta
    il numero di preferenze previsto dal layout.
    """

    layout, ballot, _, proofs = _build_valid_ballot_case()

    malformed_ballot = replace(
        ballot,
        preference_ciphertexts=(
            ballot.preference_ciphertexts[:-1]
        ),
    )

    assert not verify_ballot(
        layout=layout,
        ballot=malformed_ballot,
        proofs=proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_verify_ballot_rejects_missing_r3_proof():
    """
    La verifica fallisce se manca una prova R3.
    """

    layout, ballot, _, proofs = _build_valid_ballot_case()

    incomplete_proofs = replace(
        proofs,
        r3_proofs=proofs.r3_proofs[:-1],
    )

    assert not verify_ballot(
        layout=layout,
        ballot=ballot,
        proofs=incomplete_proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_verify_ballot_rejects_missing_r5_proof():
    """
    La verifica fallisce se manca una prova R5.
    """

    layout, ballot, _, proofs = _build_valid_ballot_case()

    incomplete_proofs = replace(
        proofs,
        r5_proofs=proofs.r5_proofs[:-1],
    )

    assert not verify_ballot(
        layout=layout,
        ballot=ballot,
        proofs=incomplete_proofs,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


@pytest.mark.parametrize(
    ("list_plaintexts", "blank_plaintext"),
    [
        ((0, 0), 0),
        ((1, 1), 0),
    ],
)
def test_prove_ballot_rejects_invalid_r2_choice(
    list_plaintexts,
    blank_plaintext,
):
    """
    La scheda completa viene rifiutata se R2
    non contiene esattamente una scelta.
    """

    layout = BallotLayout(
        list_count=2,
        max_preferences=3,
        max_preferences_per_gender=2,
        preference_metadata=(
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=1, gender="M"),
        ),
    )

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(
                list_plaintexts[0],
                PUBLIC_KEY,
                TEST_PARAMS,
                nonce=10,
            ),
            encrypt(
                list_plaintexts[1],
                PUBLIC_KEY,
                TEST_PARAMS,
                nonce=20,
            ),
        ),
        blank_ciphertext=encrypt(
            blank_plaintext,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=30,
        ),
        preference_ciphertexts=(
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=40),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=50),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=list_plaintexts,
        blank_plaintext=blank_plaintext,
        preference_plaintexts=(0, 0),
        list_nonces=(10, 20),
        blank_nonce=30,
        preference_nonces=(40, 50),
    )

    with pytest.raises(ValueError):
        prove_ballot(
            layout=layout,
            ballot=ballot,
            witness=witness,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_prove_ballot_rejects_preference_outside_selected_list():
    """
    La scheda completa viene rifiutata se una preferenza
    appartiene a una lista non selezionata.
    """

    layout = BallotLayout(
        list_count=2,
        max_preferences=3,
        max_preferences_per_gender=2,
        preference_metadata=(
            PreferenceMetadata(
                list_index=1,
                gender="F",
            ),
        ),
    )

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
            encrypt(0, PUBLIC_KEY, TEST_PARAMS, nonce=20),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=30,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=40),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1, 0),
        blank_plaintext=0,
        preference_plaintexts=(1,),
        list_nonces=(10, 20),
        blank_nonce=30,
        preference_nonces=(40,),
    )

    with pytest.raises(ValueError):
        prove_ballot(
            layout=layout,
            ballot=ballot,
            witness=witness,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_prove_ballot_rejects_four_total_preferences():
    """
    La scheda completa viene rifiutata se contiene
    più di tre preferenze complessive.
    """

    layout = BallotLayout(
        list_count=1,
        max_preferences=3,
        max_preferences_per_gender=2,
        preference_metadata=(
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=0, gender="M"),
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=0, gender="M"),
        ),
    )

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=20,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=30),
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=40),
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=50),
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=60),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1,),
        blank_plaintext=0,
        preference_plaintexts=(1, 1, 1, 1),
        list_nonces=(10,),
        blank_nonce=20,
        preference_nonces=(30, 40, 50, 60),
    )

    with pytest.raises(ValueError):
        prove_ballot(
            layout=layout,
            ballot=ballot,
            witness=witness,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_prove_ballot_rejects_three_preferences_same_gender():
    """
    La scheda completa viene rifiutata se contiene
    tre preferenze appartenenti allo stesso genere.
    """

    layout = BallotLayout(
        list_count=1,
        max_preferences=3,
        max_preferences_per_gender=2,
        preference_metadata=(
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=0, gender="F"),
            PreferenceMetadata(list_index=0, gender="F"),
        ),
    )

    ballot = EncryptedBallot(
        list_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=10),
        ),
        blank_ciphertext=encrypt(
            0,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=20,
        ),
        preference_ciphertexts=(
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=30),
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=40),
            encrypt(1, PUBLIC_KEY, TEST_PARAMS, nonce=50),
        ),
    )

    witness = BallotWitness(
        list_plaintexts=(1,),
        blank_plaintext=0,
        preference_plaintexts=(1, 1, 1),
        list_nonces=(10,),
        blank_nonce=20,
        preference_nonces=(30, 40, 50),
    )

    with pytest.raises(ValueError):
        prove_ballot(
            layout=layout,
            ballot=ballot,
            witness=witness,
            public_key=PUBLIC_KEY,
            params=TEST_PARAMS,
            context=CONTEXT,
        )


def test_r4_uses_configured_max_preferences():
    """
    R4 usa il limite massimo di preferenze configurato.
    """

    preference_plaintexts = (1, 1, 0)
    preference_nonces = (10, 20, 30)

    preference_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            preference_plaintexts,
            preference_nonces,
        )
    )

    proof = prove_r4(
        preference_ciphertexts=preference_ciphertexts,
        preference_plaintexts=preference_plaintexts,
        preference_nonces=preference_nonces,
        max_preferences=2,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r4(
        preference_ciphertexts=preference_ciphertexts,
        proof=proof,
        max_preferences=2,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )


def test_r5_uses_configured_max_preferences_per_gender():
    """
    R5 usa il limite per genere configurato.
    """

    gender_plaintexts = (1, 0)
    gender_nonces = (10, 20)

    gender_ciphertexts = tuple(
        encrypt(
            value,
            PUBLIC_KEY,
            TEST_PARAMS,
            nonce=nonce,
        )
        for value, nonce in zip(
            gender_plaintexts,
            gender_nonces,
        )
    )

    proof = prove_r5(
        gender_ciphertexts=gender_ciphertexts,
        gender_plaintexts=gender_plaintexts,
        gender_nonces=gender_nonces,
        max_preferences_per_gender=1,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )

    assert verify_r5(
        gender_ciphertexts=gender_ciphertexts,
        proof=proof,
        max_preferences_per_gender=1,
        public_key=PUBLIC_KEY,
        params=TEST_PARAMS,
        context=CONTEXT,
    )