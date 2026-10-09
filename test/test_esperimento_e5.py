"""
Test dell'esperimento E5 (costi di una scheda politica).

I conteggi della scheda di riferimento sono quelli della sezione 2.5
della proposta di progetto: 10 liste con capolista più 8 candidati
danno 91 cifrati e 175 prove.
"""

import argparse

import pytest

import evoto.gruppo
import evoto.prove
from esperimenti.e5_costi import (
    EG_4096_PARAMS,
    BallotDimensions,
    ballot_dimensions,
    ballot_size,
    count_exponentiations,
    format_bytes,
    format_seconds,
    measure_ballot,
    parse_int_list,
    project_district,
    python_pow,
    sample_choice,
    synthetic_layout,
)
from evoto.garanti import run_key_ceremony
from evoto.gruppo import (
    DEMO_PARAMS,
    TEST_PARAMS,
    is_subgroup_element,
    validate_group_parameters,
)
from evoto.scheda import PreferenceMetadata
from evoto.voto import (
    choice_to_plaintexts,
    prepare_ballot,
)


CEREMONY = run_key_ceremony(
    guardian_count=3,
    quorum=2,
    params=TEST_PARAMS,
    election_id=1,
)

REFERENCE_DIMENSIONS = BallotDimensions(
    ciphertexts=91,
    r1_proofs=91,
    r3_proofs=80,
    r5_proofs=2,
    proofs=175,
    branches=353,
)


def test_eg_4096_parameters_are_valid():
    """
    Il gruppo standard di ElectionGuard: p da 4096 bit,
    q = 2^256 - 189 divide p - 1, g ha ordine q.
    """

    assert validate_group_parameters(EG_4096_PARAMS)
    assert EG_4096_PARAMS.p.bit_length() == 4096
    assert EG_4096_PARAMS.q == 2**256 - 189
    assert (EG_4096_PARAMS.p - 1) % EG_4096_PARAMS.q == 0


def test_synthetic_layout_of_the_reference_ballot():
    """
    10 liste con 8 candidati ciascuna (oltre al capolista):
    80 caselle di preferenza, generi alternati, limiti 3 e 2.
    """

    layout = synthetic_layout(10, 8)

    assert layout.list_count == 10
    assert len(layout.preference_metadata) == 80
    assert layout.max_preferences == 3
    assert layout.max_preferences_per_gender == 2

    assert layout.preference_metadata[:3] == (
        PreferenceMetadata(list_index=0, gender="M"),
        PreferenceMetadata(list_index=0, gender="F"),
        PreferenceMetadata(list_index=0, gender="M"),
    )

    assert layout.preference_metadata[8] == PreferenceMetadata(
        list_index=1,
        gender="M",
    )


def test_synthetic_layout_rejects_invalid_sizes():
    """
    Serve almeno una lista e i candidati non possono essere negativi.
    """

    with pytest.raises(ValueError):
        synthetic_layout(0, 4)

    with pytest.raises(ValueError):
        synthetic_layout(3, -1)


def test_sample_choice_respects_the_rules():
    """
    La scelta di prova vota la prima lista con fino a tre preferenze,
    e rispetta R1-R5 in ogni configurazione.
    """

    cases = (
        ((10, 8), (0, 1, 2)),
        ((3, 2), (0, 1)),
        ((2, 1), (0,)),
        ((2, 0), ()),
    )

    for (lists, candidates), preferences in cases:
        layout = synthetic_layout(lists, candidates)
        choice = sample_choice(layout)

        assert choice.list_index == 0
        assert choice.preferences == preferences

        choice_to_plaintexts(layout, choice)


def test_reference_ballot_dimensions():
    """
    R1: 91 prove a 2 rami;  R2: 1 prova a 1 ramo;
    R3: 80 prove a 2 rami;  R4: 1 prova a 4 rami ({0, 1, 2, 3});
    R5: 2 prove a 3 rami ({0, 1, 2}), una per genere.

        prove = 91 + 1 + 80 + 1 + 2 = 175
        rami  = 182 + 1 + 160 + 4 + 6 = 353
    """

    layout = synthetic_layout(10, 8)

    prepared = prepare_ballot(
        layout,
        0,
        sample_choice(layout),
        CEREMONY.joint_public_key,
        TEST_PARAMS,
        CEREMONY.extended_base_hash,
    )

    assert ballot_dimensions(
        prepared.ballot,
        prepared.proofs,
    ) == REFERENCE_DIMENSIONS


def test_ballot_size_in_the_demo_group():
    """
    Gruppo demo: elementi da 256 byte, scalari da 32 byte.

        compatta    = 182 · 256 + 706 · 32 = 46592 + 22592 = 69184
        con impegni = 888 · 256 + 706 · 32 = 227328 + 22592 = 249920

    dove 182 = 2 · 91 elementi dei cifrati, 706 = 2 · 353 impegni
    (o scalari) dei rami.
    """

    assert ballot_size(REFERENCE_DIMENSIONS, DEMO_PARAMS, compact=True) == 69184
    assert ballot_size(REFERENCE_DIMENSIONS, DEMO_PARAMS, compact=False) == 249920


def test_ballot_size_in_the_4096_group():
    """
    Gruppo da 4096 bit: elementi da 512 byte.

        compatta    = 182 · 512 + 22592 = 115776   (circa 0,1 MB)
        con impegni = 888 · 512 + 22592 = 477248   (circa 0,5 MB)

    Sono le stime della sezione 2.5 della proposta.
    """

    assert ballot_size(REFERENCE_DIMENSIONS, EG_4096_PARAMS, compact=True) == 115776
    assert ballot_size(REFERENCE_DIMENSIONS, EG_4096_PARAMS, compact=False) == 477248


def test_count_exponentiations_counts_and_restores():
    """
    Un controllo di appartenenza al sottogruppo è una esponenziazione
    con esponente q; alla fine del blocco mod_pow torna quella originale.
    """

    original = evoto.prove.mod_pow

    with count_exponentiations(subgroup_order=TEST_PARAMS.q) as counter:
        assert is_subgroup_element(4, TEST_PARAMS)

    assert counter.count == 1
    assert counter.membership_checks == 1

    assert evoto.prove.mod_pow is original
    assert evoto.gruppo.mod_pow is original


def test_measure_ballot_in_the_test_group():
    """
    Le misure di una scheda piccola sono coerenti. 2 liste con
    2 candidati ciascuna:

        cifrati = 2 + 1 + 4 = 7
        prove   = 7 + 1 + 4 + 1 + 2 = 15
    """

    measure = measure_ballot(
        layout=synthetic_layout(2, 2),
        params=TEST_PARAMS,
        group="didattico",
        public_key=CEREMONY.joint_public_key,
        context=CEREMONY.extended_base_hash,
        repetitions=2,
    )

    assert measure.implementation == "gmpy2"
    assert measure.ciphertexts == 7
    assert measure.proofs == 15
    assert measure.encrypt_exponentiations > 0
    assert 0 < measure.verify_membership_checks < measure.verify_exponentiations
    assert measure.compact_size < measure.full_size


def test_python_pow_gives_the_same_counts():
    """
    Con pow() di Python al posto di gmpy2 la scheda resta valida e il
    numero di esponenziazioni non cambia.
    """

    layout = synthetic_layout(2, 2)

    arguments = {
        "layout": layout,
        "params": TEST_PARAMS,
        "group": "didattico",
        "public_key": CEREMONY.joint_public_key,
        "context": CEREMONY.extended_base_hash,
        "repetitions": 1,
    }

    with_gmpy2 = measure_ballot(**arguments)
    with_python = measure_ballot(**arguments, implementation=python_pow)

    assert with_python.implementation == "python"

    assert (
        with_python.encrypt_exponentiations,
        with_python.verify_exponentiations,
    ) == (
        with_gmpy2.encrypt_exponentiations,
        with_gmpy2.verify_exponentiations,
    )


def test_exponentiation_count_does_not_depend_on_the_group():
    """
    Lo stesso algoritmo esegue le stesse esponenziazioni nel gruppo
    didattico e in quello da 2048 bit.
    """

    layout = synthetic_layout(2, 1)

    demo_ceremony = run_key_ceremony(
        guardian_count=3,
        quorum=2,
        params=DEMO_PARAMS,
        election_id=1,
    )

    small = measure_ballot(
        layout=layout,
        params=TEST_PARAMS,
        group="didattico",
        public_key=CEREMONY.joint_public_key,
        context=CEREMONY.extended_base_hash,
        repetitions=1,
    )

    large = measure_ballot(
        layout=layout,
        params=DEMO_PARAMS,
        group="demo",
        public_key=demo_ceremony.joint_public_key,
        context=demo_ceremony.extended_base_hash,
        repetitions=1,
    )

    assert small.encrypt_exponentiations == large.encrypt_exponentiations
    assert small.verify_exponentiations == large.verify_exponentiations
    assert large.p_bits == 2048
    assert large.q_bits == 256


def test_project_district_in_the_test_group():
    """
    Bacheca e verifica crescono linearmente con gli elettori; la
    decifratura di un totale vicino a voters / 2 va a buon fine.
    """

    measure = measure_ballot(
        layout=synthetic_layout(2, 2),
        params=TEST_PARAMS,
        group="didattico",
        public_key=CEREMONY.joint_public_key,
        context=CEREMONY.extended_base_hash,
        repetitions=1,
    )

    projection = project_district(
        measure=measure,
        params=TEST_PARAMS,
        voters=100,
        samples=20,
    )

    assert projection.compact_board_bytes == 100 * measure.compact_size
    assert projection.full_board_bytes == 100 * measure.full_size
    assert projection.verify_seconds == pytest.approx(100 * measure.verify_seconds)
    assert projection.tally_seconds > 0
    assert projection.decryption_seconds > 0

    with pytest.raises(ValueError):
        project_district(measure=measure, params=TEST_PARAMS, voters=0)


def test_parse_int_list():
    """
    Gli elenchi della riga di comando sono interi separati da virgole.
    """

    assert parse_int_list("2,4,8") == (2, 4, 8)
    assert parse_int_list("10") == (10,)

    with pytest.raises(argparse.ArgumentTypeError):
        parse_int_list("")


def test_formatting_helpers():
    """
    Dimensioni in potenze di 1000, durate nell'unità più leggibile.
    """

    assert format_bytes(512) == "512 B"
    assert format_bytes(69184) == "69.18 KB"
    assert format_bytes(477248) == "477.25 KB"
    assert format_bytes(69184 * 1_000_000) == "69.18 GB"

    assert format_seconds(0.5) == "500.0 ms"
    assert format_seconds(3.856) == "3.86 s"
    assert format_seconds(600) == "10.0 min"
    assert format_seconds(3 * 3600) == "3.0 h"
