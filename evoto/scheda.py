"""
Modello della scheda politica del progetto evoto.

Questo modulo conterrà:
- la rappresentazione della scheda cifrata;
- le prove di validità R1-R5;
- la verifica crittografica delle regole della scheda.

Le primitive crittografiche sono riutilizzate dai moduli
elgamal.py e prove.py, senza ridefinirle.
"""

from dataclasses import dataclass
from evoto.elgamal import (
    Ciphertext,
    divide_ciphertexts,
    multiply_ciphertexts,
)
from evoto.gruppo import GroupParameters
from evoto.prove import (
    ValueSetProof,
    prove_value_in_set,
    verify_value_in_set,
)


@dataclass(frozen=True)
class EncryptedBallot:
    """
    Rappresenta una scheda politica cifrata.

    Contiene soltanto dati pubblici:
    - un ciphertext per ogni lista;
    - un ciphertext per la scheda bianca;
    - un ciphertext per ogni candidato selezionabile.
    """

    list_ciphertexts: tuple[Ciphertext, ...]
    blank_ciphertext: Ciphertext
    preference_ciphertexts: tuple[Ciphertext, ...]

    def all_ciphertexts(self) -> tuple[Ciphertext, ...]:
        """
        Restituisce tutti i ciphertext della scheda.

        L'ordine è: liste, scheda bianca, preferenze.
        """

        return (
            self.list_ciphertexts
            + (self.blank_ciphertext,)
            + self.preference_ciphertexts
        )


@dataclass(frozen=True)
class BallotProofs:
    """
    Raccoglie le prove pubbliche di validità di una scheda.

    Contiene:
    - una prova R1 per ogni ciphertext della scheda;
    - una prova R2 per la scelta tra liste e scheda bianca;
    - una prova R3 per ogni preferenza;
    - una prova R4 per il numero totale di preferenze;
    - una prova R5 per ciascun genere considerato.
    """

    r1_proofs: tuple[ValueSetProof, ...]
    r2_proof: ValueSetProof
    r3_proofs: tuple[ValueSetProof, ...]
    r4_proof: ValueSetProof
    r5_proofs: tuple[ValueSetProof, ...]
    

def prove_r1(
    ciphertext: Ciphertext,
    plaintext: int,
    nonce: int,
    public_key: int,
    params: GroupParameters,
    context: int,
) -> ValueSetProof:
    """
    Genera la prova R1 per una singola casella.

    R1 richiede che il valore cifrato appartenga a {0, 1}.
    """

    return prove_value_in_set(
        ciphertext=ciphertext,
        plaintext=plaintext,
        nonce=nonce,
        allowed_values=(0, 1),
        public_key=public_key,
        params=params,
        context=context,
    )


def verify_r1(
    ciphertext: Ciphertext,
    proof: ValueSetProof,
    public_key: int,
    params: GroupParameters,
    context: int,
) -> bool:
    """
    Verifica la prova R1 di una singola casella.
    """

    return verify_value_in_set(
        ciphertext=ciphertext,
        proof=proof,
        allowed_values=(0, 1),
        public_key=public_key,
        params=params,
        context=context,
    )


def _multiply_all(
    ciphertexts: tuple[Ciphertext, ...],
    params: GroupParameters,
) -> Ciphertext:
    """
    Moltiplica una sequenza non vuota di ciphertext.
    """

    if not ciphertexts:
        raise ValueError("È richiesto almeno un ciphertext.")

    result = ciphertexts[0]

    for ciphertext in ciphertexts[1:]:
        result = multiply_ciphertexts(
            result,
            ciphertext,
            params,
        )

    return result


def prove_r2(
    ciphertexts: tuple[Ciphertext, ...],
    plaintexts: tuple[int, ...],
    nonces: tuple[int, ...],
    public_key: int,
    params: GroupParameters,
    context: int,
) -> ValueSetProof:
    """
    Genera la prova R2.

    I ciphertext rappresentano i bit delle liste e della scheda bianca.
    La loro somma deve essere esattamente 1.
    """

    if not (
        len(ciphertexts)
        == len(plaintexts)
        == len(nonces)
    ):
        raise ValueError(
            "Ciphertext, plaintext e nonce devono avere la stessa lunghezza."
        )

    derived_ciphertext = _multiply_all(
        ciphertexts,
        params,
    )

    total_plaintext = sum(plaintexts)
    derived_nonce = sum(nonces) % params.q

    return prove_value_in_set(
        ciphertext=derived_ciphertext,
        plaintext=total_plaintext,
        nonce=derived_nonce,
        allowed_values=(1,),
        public_key=public_key,
        params=params,
        context=context,
    )


def verify_r2(
    ciphertexts: tuple[Ciphertext, ...],
    proof: ValueSetProof,
    public_key: int,
    params: GroupParameters,
    context: int,
) -> bool:
    """
    Verifica la prova R2.

    Il prodotto omomorfico dei ciphertext deve cifrare esattamente 1.
    """

    derived_ciphertext = _multiply_all(
        ciphertexts,
        params,
    )

    return verify_value_in_set(
        ciphertext=derived_ciphertext,
        proof=proof,
        allowed_values=(1,),
        public_key=public_key,
        params=params,
        context=context,
    )


def prove_r3(
    list_ciphertext: Ciphertext,
    preference_ciphertext: Ciphertext,
    list_plaintext: int,
    preference_plaintext: int,
    list_nonce: int,
    preference_nonce: int,
    public_key: int,
    params: GroupParameters,
    context: int,
) -> ValueSetProof:
    """
    Genera la prova R3 per una singola preferenza.

    La differenza lista - preferenza deve appartenere a {0, 1}.
    """

    derived_ciphertext = divide_ciphertexts(
        list_ciphertext,
        preference_ciphertext,
        params,
    )

    derived_plaintext = list_plaintext - preference_plaintext
    derived_nonce = (list_nonce - preference_nonce) % params.q

    return prove_value_in_set(
        ciphertext=derived_ciphertext,
        plaintext=derived_plaintext,
        nonce=derived_nonce,
        allowed_values=(0, 1),
        public_key=public_key,
        params=params,
        context=context,
    )


def verify_r3(
    list_ciphertext: Ciphertext,
    preference_ciphertext: Ciphertext,
    proof: ValueSetProof,
    public_key: int,
    params: GroupParameters,
    context: int,
) -> bool:
    """
    Verifica la prova R3 per una singola preferenza.
    """

    derived_ciphertext = divide_ciphertexts(
        list_ciphertext,
        preference_ciphertext,
        params,
    )

    return verify_value_in_set(
        ciphertext=derived_ciphertext,
        proof=proof,
        allowed_values=(0, 1),
        public_key=public_key,
        params=params,
        context=context,
    )


def prove_r4(
    preference_ciphertexts: tuple[Ciphertext, ...],
    preference_plaintexts: tuple[int, ...],
    preference_nonces: tuple[int, ...],
    public_key: int,
    params: GroupParameters,
    context: int,
) -> ValueSetProof:
    """
    Genera la prova R4.

    La somma complessiva delle preferenze deve appartenere
    all'insieme {0, 1, 2, 3}.
    """

    if not (
        len(preference_ciphertexts)
        == len(preference_plaintexts)
        == len(preference_nonces)
    ):
        raise ValueError(
            "Ciphertext, plaintext e nonce devono avere la stessa lunghezza."
        )

    derived_ciphertext = _multiply_all(
        preference_ciphertexts,
        params,
    )

    total_plaintext = sum(preference_plaintexts)
    derived_nonce = sum(preference_nonces) % params.q

    return prove_value_in_set(
        ciphertext=derived_ciphertext,
        plaintext=total_plaintext,
        nonce=derived_nonce,
        allowed_values=(0, 1, 2, 3),
        public_key=public_key,
        params=params,
        context=context,
    )


def verify_r4(
    preference_ciphertexts: tuple[Ciphertext, ...],
    proof: ValueSetProof,
    public_key: int,
    params: GroupParameters,
    context: int,
) -> bool:
    """
    Verifica la prova R4.

    La somma delle preferenze deve essere compresa tra 0 e 3.
    """

    derived_ciphertext = _multiply_all(
        preference_ciphertexts,
        params,
    )

    return verify_value_in_set(
        ciphertext=derived_ciphertext,
        proof=proof,
        allowed_values=(0, 1, 2, 3),
        public_key=public_key,
        params=params,
        context=context,
    )


def prove_r5(
    gender_ciphertexts: tuple[Ciphertext, ...],
    gender_plaintexts: tuple[int, ...],
    gender_nonces: tuple[int, ...],
    public_key: int,
    params: GroupParameters,
    context: int,
) -> ValueSetProof:
    """
    Genera la prova R5 per un singolo genere.

    La somma delle preferenze dello stesso genere deve
    appartenere all'insieme {0, 1, 2}.
    """

    if not (
        len(gender_ciphertexts)
        == len(gender_plaintexts)
        == len(gender_nonces)
    ):
        raise ValueError(
            "Ciphertext, plaintext e nonce devono avere la stessa lunghezza."
        )

    derived_ciphertext = _multiply_all(
        gender_ciphertexts,
        params,
    )

    total_plaintext = sum(gender_plaintexts)
    derived_nonce = sum(gender_nonces) % params.q

    return prove_value_in_set(
        ciphertext=derived_ciphertext,
        plaintext=total_plaintext,
        nonce=derived_nonce,
        allowed_values=(0, 1, 2),
        public_key=public_key,
        params=params,
        context=context,
    )


def verify_r5(
    gender_ciphertexts: tuple[Ciphertext, ...],
    proof: ValueSetProof,
    public_key: int,
    params: GroupParameters,
    context: int,
) -> bool:
    """
    Verifica la prova R5 per un singolo genere.
    """

    derived_ciphertext = _multiply_all(
        gender_ciphertexts,
        params,
    )

    return verify_value_in_set(
        ciphertext=derived_ciphertext,
        proof=proof,
        allowed_values=(0, 1, 2),
        public_key=public_key,
        params=params,
        context=context,
    )