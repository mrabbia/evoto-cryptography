"""
Modello della scheda politica del progetto evoto.

Questo modulo conterrà:
- la rappresentazione della scheda cifrata;
- le prove di validità R1-R5;
- la verifica crittografica delle regole della scheda.

Le primitive crittografiche sono riutilizzate dai moduli
elgamal.py e prove.py, senza ridefinirle.
"""

from evoto.elgamal import Ciphertext
from evoto.gruppo import GroupParameters
from evoto.prove import (
    ValueSetProof,
    prove_value_in_set,
    verify_value_in_set,
)


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