"""
Test dell'esperimento E2 (garanti assenti).

I casi piccoli sono calcolati a mano nelle docstring; l'elezione
simulata usa il gruppo didattico e pochi elettori.
"""

from collections import Counter
from pathlib import Path

import pytest

from esperimenti.e2_garanti_assenti import (
    count_compatible_polynomials,
    interpolate_secret,
    quorum_subsets,
    run_absent_guardians_experiment,
    run_secrecy_experiment,
    same_totals,
)
from evoto.configurazione import load_election_config
from evoto.gruppo import TEST_PARAMS
from evoto.urna import DistrictResult


CONFIG = load_election_config(
    Path(__file__).resolve().parent.parent
    / "config"
    / "elezione_esempio.json"
)

# Polinomi dell'esempio della sezione 38 della specifica:
# S(x) = 765 + 100x, share aggregate 865, 965, 1065.
EXAMPLE_COEFFICIENTS = (
    (300, 40),
    (400, 50),
    (65, 10),
)


def test_quorum_subsets_with_five_guardians():
    """
    Con 5 garanti e quorum 3 i gruppi validi sono
    C(5, 3) + C(5, 4) + C(5, 5) = 10 + 5 + 1 = 16.
    """

    subsets = quorum_subsets(5, 3)

    assert len(subsets) == 16
    assert subsets[:3] == ((1, 2, 3), (1, 2, 4), (1, 2, 5))
    assert subsets[9] == (3, 4, 5)
    assert subsets[-1] == (1, 2, 3, 4, 5)


def test_quorum_subsets_small_case():
    """
    Con 3 garanti e quorum 2: tre coppie e il gruppo completo.
    """

    assert quorum_subsets(3, 2) == (
        (1, 2),
        (1, 3),
        (2, 3),
        (1, 2, 3),
    )


def test_quorum_subsets_rejects_invalid_quorum():
    """
    Il quorum deve stare tra 1 e il numero di garanti.
    """

    with pytest.raises(ValueError):
        quorum_subsets(3, 0)

    with pytest.raises(ValueError):
        quorum_subsets(3, 4)


def test_one_share_is_compatible_with_every_secret():
    """
    q = 11, quorum 3, S(x) = 5 + 3x + 7x^2 mod 11.

        S(1) = 5 + 3 + 7 = 15 = 4 mod 11

    Con la sola share S(1) = 4, ogni segreto a_0 è compatibile con
    11 polinomi: per ogni a_2 c'è un solo a_1 con a_0 + a_1 + a_2 = 4.
    """

    counts = count_compatible_polynomials(
        {1: 4},
        quorum=3,
        q=11,
    )

    assert counts == Counter({secret: 11 for secret in range(11)})


def test_two_shares_below_quorum_reveal_nothing():
    """
    Con S(1) = 4 e S(2) = 5 + 6 + 28 = 39 = 6 mod 11 ogni segreto
    è compatibile con esattamente un polinomio di secondo grado.
    """

    counts = count_compatible_polynomials(
        {1: 4, 2: 6},
        quorum=3,
        q=11,
    )

    assert counts == Counter({secret: 1 for secret in range(11)})


def test_quorum_shares_fix_the_secret():
    """
    Aggiungendo S(3) = 5 + 9 + 63 = 77 = 0 mod 11 resta un solo
    polinomio, quindi un solo segreto: 5.
    """

    counts = count_compatible_polynomials(
        {1: 4, 2: 6, 3: 0},
        quorum=3,
        q=11,
    )

    assert counts == Counter({5: 1})


def test_example_of_the_specification():
    """
    Esempio della sezione 38: quorum 2, q = 1289.

    La sola share s_1 = 865 è compatibile con tutti i 1289 segreti;
    le share s_1 = 865 e s_3 = 1065 fissano il segreto 765.
    """

    one_share = count_compatible_polynomials(
        {1: 865},
        quorum=2,
        q=TEST_PARAMS.q,
    )

    assert len(one_share) == TEST_PARAMS.q
    assert set(one_share.values()) == {1}

    two_shares = count_compatible_polynomials(
        {1: 865, 3: 1065},
        quorum=2,
        q=TEST_PARAMS.q,
    )

    assert two_shares == Counter({765: 1})


def test_count_rejects_invalid_input():
    """
    Serve almeno una share e gli indici devono stare tra 1 e q - 1.
    """

    with pytest.raises(ValueError):
        count_compatible_polynomials({}, quorum=2, q=11)

    with pytest.raises(ValueError):
        count_compatible_polynomials({0: 3}, quorum=2, q=11)

    with pytest.raises(ValueError):
        count_compatible_polynomials({11: 3}, quorum=2, q=11)


def test_interpolate_secret_example():
    """
    Garanti 1 e 3 dell'esempio: λ_1 = 646, λ_3 = 644.

        646 · 865 + 644 · 1065 = 1244650 = 765 mod 1289

    Con la sola share del garante 1 il coefficiente è 1 e il risultato
    è la share stessa, cioè un valore sbagliato.
    """

    assert interpolate_secret({1: 865, 3: 1065}, TEST_PARAMS) == 765
    assert interpolate_secret({1: 865, 2: 965, 3: 1065}, TEST_PARAMS) == 765
    assert interpolate_secret({1: 865}, TEST_PARAMS) == 865

    with pytest.raises(ValueError):
        interpolate_secret({}, TEST_PARAMS)


def test_secrecy_experiment_on_the_example():
    """
    Con i polinomi della sezione 38 e quorum 2:
    - una share: 1289 segreti compatibili, un polinomio ciascuno;
    - due share: un solo segreto;
    - Lagrange con due share dà s = 765 e g^765 = 530 = K;
    - Lagrange forzato con una share dà 865 e g^865 è diverso da K.
    """

    report = run_secrecy_experiment(
        guardian_count=3,
        quorum=2,
        params=TEST_PARAMS,
        election_id=1,
        coefficients=EXAMPLE_COEFFICIENTS,
    )

    assert [
        (row.known_guardians, row.compatible_secrets, row.polynomials_per_secret)
        for row in report.rows
    ] == [
        ((1,), 1289, (1,)),
        ((1, 2), 1, (1,)),
    ]

    assert report.full_matches_key
    assert not report.forced_matches_key


def test_absent_guardians_give_the_same_result():
    """
    Esperimento E2 in piccolo: 5 garanti, quorum 3, tre elettori per
    circoscrizione.

    Tutti i 16 gruppi di almeno 3 garanti decifrano gli stessi totali
    del conteggio in chiaro, con gli stessi seggi ed eletti, e il
    verificatore indipendente accetta ogni registro. Tutti i 10 gruppi
    di 2 garanti vengono rifiutati.
    """

    report = run_absent_guardians_experiment(
        config=CONFIG,
        voters_per_district=3,
        guardian_count=5,
        quorum=3,
        params=TEST_PARAMS,
        seed=7,
    )

    assert report.ballot_count == 9
    assert len(report.outcomes) == 16

    for outcome in report.outcomes:
        assert outcome.same_totals
        assert outcome.same_scrutiny
        assert outcome.registry_verified

    assert report.below_quorum_subsets == 10
    assert report.rejected_below_quorum == 10


def test_absent_guardians_without_verifier():
    """
    Senza verificatore l'esito del registro resta None.
    """

    report = run_absent_guardians_experiment(
        config=CONFIG,
        voters_per_district=1,
        guardian_count=3,
        quorum=2,
        params=TEST_PARAMS,
        seed=3,
        verify_registry=False,
    )

    assert len(report.outcomes) == 4
    assert all(
        outcome.registry_verified is None
        for outcome in report.outcomes
    )
    assert report.rejected_below_quorum == report.below_quorum_subsets == 3


def test_same_totals_detects_a_difference():
    """
    Due risultati che differiscono in un solo voto non coincidono;
    le share di decifratura non contano nel confronto.
    """

    first = DistrictResult(
        district_index=0,
        ballot_count=3,
        list_votes=(2, 1),
        blank_votes=0,
        preference_votes=(1, 0),
        decryption_shares=(),
    )

    same = DistrictResult(
        district_index=0,
        ballot_count=3,
        list_votes=(2, 1),
        blank_votes=0,
        preference_votes=(1, 0),
        decryption_shares=((),),
    )

    different = DistrictResult(
        district_index=0,
        ballot_count=3,
        list_votes=(1, 2),
        blank_votes=0,
        preference_votes=(1, 0),
        decryption_shares=(),
    )

    assert same_totals((first,), (same,))
    assert not same_totals((first,), (different,))
    assert not same_totals((first,), ())
