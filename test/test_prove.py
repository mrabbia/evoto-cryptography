"""
Test unitari per evoto.prove.

In questo file testiamo:
- Schnorr;
- Chaum-Pedersen generico;
- i vettori di riferimento della specifica F1 v0.2.
"""
import pytest

from evoto.gruppo import TEST_PARAMS
from evoto.prove import (
    ChaumPedersenProof,
    SchnorrProof,
    prove_chaum_pedersen,
    prove_schnorr,
    verify_chaum_pedersen,
    verify_schnorr,
    prove_value_in_set,
    verify_value_in_set,
)
from evoto.elgamal import Ciphertext

def test_schnorr_reference_vector():
    """
    Vettore ufficiale della specifica F1 v0.2.

    Garante 1, impegno K_1,0:
        secret = 300
        public_value = 2228
        context = (Q, i, j) = (889, 1, 0)
        nonce = 7

    Valori attesi:
        h = 910
        c = 957
        z = 949
    """

    proof = prove_schnorr(
        secret=300,
        public_value=2228,
        params=TEST_PARAMS,
        context=(889, 1, 0),
        nonce=7,
    )

    assert proof == SchnorrProof(
        commitment=910,
        challenge=957,
        response=949,
    )


def test_schnorr_verification():
    """
    Una prova Schnorr corretta deve essere accettata.
    """

    proof = prove_schnorr(
        secret=300,
        public_value=2228,
        params=TEST_PARAMS,
        context=(889, 1, 0),
        nonce=7,
    )

    assert verify_schnorr(
        public_value=2228,
        proof=proof,
        params=TEST_PARAMS,
        context=(889, 1, 0),
    )


def test_schnorr_rejects_wrong_context():
    """
    Cambiando il contesto, la challenge non coincide più.

    Questo dimostra che Fiat-Shamir lega la prova
    al contesto specifico dell'elezione.
    """

    proof = prove_schnorr(
        secret=300,
        public_value=2228,
        params=TEST_PARAMS,
        context=(889, 1, 0),
        nonce=7,
    )

    assert not verify_schnorr(
        public_value=2228,
        proof=proof,
        params=TEST_PARAMS,
        context=(889, 2, 0),
    )


def test_schnorr_rejects_tampered_response():
    """
    Una risposta modificata deve rendere la prova non valida.
    """

    proof = SchnorrProof(
        commitment=910,
        challenge=957,
        response=950,
    )

    assert not verify_schnorr(
        public_value=2228,
        proof=proof,
        params=TEST_PARAMS,
        context=(889, 1, 0),
    )


def test_chaum_pedersen_reference_vector():
    """
    Vettore ufficiale della specifica F1 v0.2.

    Share di decifratura del garante 1:
        secret = 865
        base_1 = g = 4
        public_1 = V_1 = 2502
        base_2 = A = 1196
        public_2 = M_1 = 60
        context = (Q_bar, l) = (744, 1)
        nonce = 7

    Valori attesi:
        a = 910
        b = 1033
        c = 524
        z = 828
    """

    proof = prove_chaum_pedersen(
        secret=865,
        base_1=4,
        public_1=2502,
        base_2=1196,
        public_2=60,
        params=TEST_PARAMS,
        context=(744, 1),
        nonce=7,
    )

    assert proof == ChaumPedersenProof(
        commitment_1=910,
        commitment_2=1033,
        challenge=524,
        response=828,
    )


def test_chaum_pedersen_verification():
    """
    Una prova Chaum-Pedersen corretta deve essere accettata.
    """

    proof = prove_chaum_pedersen(
        secret=865,
        base_1=4,
        public_1=2502,
        base_2=1196,
        public_2=60,
        params=TEST_PARAMS,
        context=(744, 1),
        nonce=7,
    )

    assert verify_chaum_pedersen(
        base_1=4,
        public_1=2502,
        base_2=1196,
        public_2=60,
        proof=proof,
        params=TEST_PARAMS,
        context=(744, 1),
    )


def test_chaum_pedersen_rejects_wrong_context():
    """
    Una prova valida per un garante non deve essere
    automaticamente valida per un altro contesto.
    """

    proof = prove_chaum_pedersen(
        secret=865,
        base_1=4,
        public_1=2502,
        base_2=1196,
        public_2=60,
        params=TEST_PARAMS,
        context=(744, 1),
        nonce=7,
    )

    assert not verify_chaum_pedersen(
        base_1=4,
        public_1=2502,
        base_2=1196,
        public_2=60,
        proof=proof,
        params=TEST_PARAMS,
        context=(744, 2),
    )


def test_chaum_pedersen_rejects_tampered_response():
    """
    Una risposta alterata deve rendere la prova non valida.
    """

    proof = ChaumPedersenProof(
        commitment_1=910,
        commitment_2=1033,
        challenge=524,
        response=829,
    )

    assert not verify_chaum_pedersen(
        base_1=4,
        public_1=2502,
        base_2=1196,
        public_2=60,
        proof=proof,
        params=TEST_PARAMS,
        context=(744, 1),
    )


def test_schnorr_rejects_invalid_secret():
    """
    Il segreto deve essere compreso tra 0 e q - 1.
    """

    with pytest.raises(ValueError):
        prove_schnorr(
            secret=TEST_PARAMS.q,
            public_value=2228,
            params=TEST_PARAMS,
            context=(889, 1, 0),
            nonce=7,
        )


def test_schnorr_rejects_zero_nonce():
    """
    Il nonce 0 non è ammesso.
    """

    with pytest.raises(ValueError):
        prove_schnorr(
            secret=300,
            public_value=2228,
            params=TEST_PARAMS,
            context=(889, 1, 0),
            nonce=0,
        )


def test_schnorr_rejects_invalid_public_value():
    """
    Il valore pubblico deve appartenere al sottogruppo.
    """

    with pytest.raises(ValueError):
        prove_schnorr(
            secret=300,
            public_value=2,
            params=TEST_PARAMS,
            context=(889, 1, 0),
            nonce=7,
        )


def test_chaum_pedersen_rejects_invalid_secret():
    """
    Il segreto deve essere compreso tra 0 e q - 1.
    """

    with pytest.raises(ValueError):
        prove_chaum_pedersen(
            secret=TEST_PARAMS.q,
            base_1=4,
            public_1=2502,
            base_2=1196,
            public_2=60,
            params=TEST_PARAMS,
            context=(744, 1),
            nonce=7,
        )


def test_chaum_pedersen_rejects_zero_nonce():
    """
    Il nonce 0 non è ammesso.
    """

    with pytest.raises(ValueError):
        prove_chaum_pedersen(
            secret=865,
            base_1=4,
            public_1=2502,
            base_2=1196,
            public_2=60,
            params=TEST_PARAMS,
            context=(744, 1),
            nonce=0,
        )


def test_chaum_pedersen_rejects_invalid_group_element():
    """
    Tutti gli elementi pubblici devono appartenere al sottogruppo.
    """

    with pytest.raises(ValueError):
        prove_chaum_pedersen(
            secret=865,
            base_1=2,
            public_1=2502,
            base_2=1196,
            public_2=60,
            params=TEST_PARAMS,
            context=(744, 1),
            nonce=7,
        )


def test_value_in_set_proof_for_zero():
    """
    Verifica una prova OR per un ciphertext che cifra 0.

    Il valore ammesso è {0, 1}.
    """

    ciphertext = Ciphertext(
        alpha=380,
        beta=22,
    )

    proof = prove_value_in_set(
        ciphertext=ciphertext,
        plaintext=0,
        nonce=22,
        allowed_values=(0, 1),
        public_key=530,
        params=TEST_PARAMS,
        context=744,
        proof_nonce=7,
    )

    assert verify_value_in_set(
        ciphertext=ciphertext,
        proof=proof,
        allowed_values=(0, 1),
        public_key=530,
        params=TEST_PARAMS,
        context=744,
    )


def test_value_in_set_proof_for_one():
    """
    Verifica una prova OR per un ciphertext che cifra 1.

    Anche qui il valore ammesso è {0, 1}.
    """

    ciphertext = Ciphertext(
        alpha=850,
        beta=2375,
    )

    proof = prove_value_in_set(
        ciphertext=ciphertext,
        plaintext=1,
        nonce=11,
        allowed_values=(0, 1),
        public_key=530,
        params=TEST_PARAMS,
        context=744,
        proof_nonce=7,
    )

    assert verify_value_in_set(
        ciphertext=ciphertext,
        proof=proof,
        allowed_values=(0, 1),
        public_key=530,
        params=TEST_PARAMS,
        context=744,
    )


def test_value_in_set_rejects_wrong_plaintext():
    """
    Non si può generare una prova per un valore
    che non appartiene all'insieme ammesso.
    """

    ciphertext = Ciphertext(
        alpha=850,
        beta=2375,
    )

    with pytest.raises(ValueError):
        prove_value_in_set(
            ciphertext=ciphertext,
            plaintext=2,
            nonce=11,
            allowed_values=(0, 1),
            public_key=530,
            params=TEST_PARAMS,
            context=744,
            proof_nonce=7,
        )


def test_value_in_set_rejects_wrong_context():
    """
    Una prova valida in un contesto non deve esserlo
    automaticamente in un altro.
    """

    ciphertext = Ciphertext(
        alpha=850,
        beta=2375,
    )

    proof = prove_value_in_set(
        ciphertext=ciphertext,
        plaintext=1,
        nonce=11,
        allowed_values=(0, 1),
        public_key=530,
        params=TEST_PARAMS,
        context=744,
        proof_nonce=7,
    )

    assert not verify_value_in_set(
        ciphertext=ciphertext,
        proof=proof,
        allowed_values=(0, 1),
        public_key=530,
        params=TEST_PARAMS,
        context=745,
    )


def test_value_in_set_proof_with_four_values():
    """
    Verifica che la prova OR funzioni anche con quattro rami.

    Questo è il caso usato, ad esempio, per dimostrare
    che un totale appartiene a {0, 1, 2, 3}.
    """

    # Cifriamo il valore 2 con nonce 11 e chiave pubblica 530.
    # alpha = g^11
    # beta = g^2 * K^11
    from evoto.elgamal import encrypt

    ciphertext = encrypt(
        message=2,
        public_key=530,
        params=TEST_PARAMS,
        nonce=11,
    )

    proof = prove_value_in_set(
        ciphertext=ciphertext,
        plaintext=2,
        nonce=11,
        allowed_values=(0, 1, 2, 3),
        public_key=530,
        params=TEST_PARAMS,
        context=744,
        proof_nonce=7,
    )

    assert verify_value_in_set(
        ciphertext=ciphertext,
        proof=proof,
        allowed_values=(0, 1, 2, 3),
        public_key=530,
        params=TEST_PARAMS,
        context=744,
    )