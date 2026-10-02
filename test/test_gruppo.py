"""
Test unitari per evoto.gruppo.

Usiamo principalmente il piccolo gruppo didattico:
    p = 2579
    q = 1289
    g = 4

È utile perché permette di verificare facilmente le proprietà
del gruppo senza usare ancora parametri crittografici molto grandi.
"""

from dataclasses import FrozenInstanceError
import hashlib

import pytest

from evoto.gruppo import (
    GroupParameters,
    H,
    DEMO_PARAMS,
    TEST_PARAMS,
    is_subgroup_element,
    mod_inverse,
    mod_pow,
    validate_group_parameters,
)


def test_demo_parameters_are_valid_2048_256_group():
    """
    I parametri della demo rispettano dimensioni e proprietà del gruppo.
    """

    assert DEMO_PARAMS.p.bit_length() == 2048
    assert DEMO_PARAMS.q.bit_length() == 256

    assert validate_group_parameters(
        DEMO_PARAMS
    )


def test_group_parameters_are_frozen():
    """
    GroupParameters deve essere immutabile.

    Questo evita che p, q oppure g vengano cambiati accidentalmente
    durante l'esecuzione del protocollo.
    """

    with pytest.raises(FrozenInstanceError):
        TEST_PARAMS.p = 123


def test_valid_group_parameters():
    """
    Il gruppo didattico deve rispettare tutti i controlli previsti.
    """

    assert validate_group_parameters(TEST_PARAMS)


def test_rejects_non_prime_p():
    """
    p deve essere primo.
    """

    params = GroupParameters(
        p=15,
        q=7,
        g=4,
    )

    assert not validate_group_parameters(params)


def test_rejects_non_prime_q():
    """
    q deve essere primo.
    """

    params = GroupParameters(
        p=17,
        q=8,
        g=2,
    )

    assert not validate_group_parameters(params)


def test_rejects_q_not_dividing_p_minus_one():
    """
    q deve dividere esattamente p - 1.
    """

    params = GroupParameters(
        p=23,
        q=5,
        g=2,
    )

    assert not validate_group_parameters(params)


def test_rejects_invalid_generator():
    """
    g deve appartenere al sottogruppo di ordine q.

    Qui usiamo g = 2 nel gruppo didattico:
    2 ha ordine 2578 e quindi non appartiene al sottogruppo
    di ordine 1289 scelto per il progetto.
    """

    params = GroupParameters(
        p=2579,
        q=1289,
        g=2,
    )

    assert not validate_group_parameters(params)


def test_mod_pow():
    """
    Controlla l'esponenziazione modulare.
    """

    result = mod_pow(4, 3, 2579)

    assert result == 64


def test_mod_pow_rejects_negative_exponent():
    """
    La nostra funzione non accetta esponenti negativi.
    """

    with pytest.raises(ValueError):
        mod_pow(4, -1, 2579)


def test_mod_inverse():
    """
    Verifica che l'inverso modulare sia corretto.

    Se x è l'inverso di 5 modulo 17:
        5 * x ≡ 1 (mod 17)
    """

    inverse = mod_inverse(5, 17)

    assert (5 * inverse) % 17 == 1


def test_mod_inverse_fails_when_inverse_does_not_exist():
    """
    Se value e modulus non sono coprimi, l'inverso non esiste.

    6 e 15 hanno infatti MCD uguale a 3.
    """

    with pytest.raises(ValueError):
        mod_inverse(6, 15)


def test_generator_is_subgroup_element():
    """
    Il generatore g deve appartenere al sottogruppo.
    """

    assert is_subgroup_element(TEST_PARAMS.g, TEST_PARAMS)


def test_identity_is_subgroup_element():
    """
    L'identità 1 appartiene sempre al sottogruppo.
    """

    assert is_subgroup_element(1, TEST_PARAMS)


def test_element_outside_subgroup():
    """
    Il valore 2 non appartiene al sottogruppo scelto.
    """

    assert not is_subgroup_element(2, TEST_PARAMS)


def test_zero_is_not_subgroup_element():
    """
    Zero non appartiene a Z_p* e quindi nemmeno al sottogruppo.
    """

    assert not is_subgroup_element(0, TEST_PARAMS)


def test_hash_is_deterministic():
    """
    Gli stessi input devono produrre sempre lo stesso hash.
    """

    first = H(1, 2, 255, params=TEST_PARAMS)
    second = H(1, 2, 255, params=TEST_PARAMS)

    assert first == second


def test_hash_known_vector():
    """
    Verifica un vettore noto dell'hash canonico.

    Gli interi:
        1, 2, 255

    diventano:
        |01|02|FF|

    Dopo SHA-256 e riduzione modulo 1289
    il risultato atteso è 74.
    """

    result = H(1, 2, 255, params=TEST_PARAMS)

    assert result == 74


def test_hash_base_context_reference_vector():
    """
    Controlla il vettore di riferimento per il contesto Q.

    La specifica F1 v0.2 stabilisce:
        Q = H(2579, 1289, 4, 3, 2, 1) = 889
    """

    result = H(
        2579,
        1289,
        4,
        3,
        2,
        1,
        params=TEST_PARAMS,
    )

    assert result == 889


def test_hash_extended_context_reference_vector():
    """
    Controlla il vettore di riferimento per il contesto Q_bar.

    La specifica F1 v0.2 stabilisce:
        Q_bar = H(889, 530) = 744
    """

    result = H(
        889,
        530,
        params=TEST_PARAMS,
    )

    assert result == 744


def test_hash_serialization_matches_specification():
    """
    Ricostruiamo manualmente la serializzazione prevista dalla specifica
    e controlliamo che H produca lo stesso risultato.

    Questo test è importante perché verifica non solo SHA-256,
    ma anche il formato "|x1|x2|...|".
    """

    serialized = b"|01|02|FF|"

    digest = hashlib.sha256(serialized).digest()
    expected = int.from_bytes(digest, byteorder="big") % TEST_PARAMS.q

    assert H(1, 2, 255, params=TEST_PARAMS) == expected


def test_hash_depends_on_input_order():
    """
    L'ordine degli elementi fa parte dell'input dell'hash.
    """

    first = H(1, 2, params=TEST_PARAMS)
    second = H(2, 1, params=TEST_PARAMS)

    assert first != second


def test_hash_rejects_negative_values():
    """
    La rappresentazione canonica scelta non accetta interi negativi.
    """

    with pytest.raises(ValueError):
        H(-1, params=TEST_PARAMS)