"""
Primitive ElGamal usate dal progetto evoto.

Questo modulo contiene:
- il tipo condiviso Ciphertext;
- generazione della chiave segreta;
- derivazione della chiave pubblica;
- cifratura ElGamal esponenziale;
- prodotto e divisione omomorfica di ciphertext;
- logaritmo discreto limitato con baby-step giant-step.
"""

from dataclasses import dataclass
from math import isqrt
import secrets

from evoto.gruppo import (
    GroupParameters,
    is_subgroup_element,
    mod_inverse,
    mod_pow,
)


@dataclass(frozen=True)
class Ciphertext:
    """
    Rappresentazione canonica di un cifrato ElGamal.

    alpha = g^r mod p
    beta  = g^v * K^r mod p
    """

    alpha: int
    beta: int


def generate_secret_key(params: GroupParameters) -> int:
    """
    Genera una chiave segreta casuale nell'intervallo 1, ..., q - 1.

    Escludiamo 0 perché produrrebbe una chiave pubblica uguale a 1.
    """

    return secrets.randbelow(params.q - 1) + 1


def public_key_from_secret(
    secret_key: int,
    params: GroupParameters,
) -> int:
    """
    Calcola la chiave pubblica K = g^s mod p.

    La chiave segreta deve essere compresa tra 1 e q - 1.
    """

    if not 1 <= secret_key < params.q:
        raise ValueError("La chiave segreta deve essere compresa tra 1 e q - 1.")

    return mod_pow(params.g, secret_key, params.p)


def encrypt(
    message: int,
    public_key: int,
    params: GroupParameters,
    nonce: int | None = None,
) -> Ciphertext:
    """
    Cifra un intero usando ElGamal esponenziale.

    Il messaggio viene codificato all'esponente:

        alpha = g^r mod p
        beta  = g^message * K^r mod p

    Se nonce non viene fornito, viene generato in modo sicuro.
    """

    if message < 0:
        raise ValueError("Il messaggio deve essere non negativo.")

    if not is_subgroup_element(public_key, params):
        raise ValueError("La chiave pubblica non appartiene al sottogruppo.")

    if nonce is None:
        nonce = secrets.randbelow(params.q - 1) + 1

    if not 1 <= nonce < params.q:
        raise ValueError("Il nonce deve essere compreso tra 1 e q - 1.")

    alpha = mod_pow(params.g, nonce, params.p)

    encoded_message = mod_pow(
        params.g,
        message,
        params.p,
    )

    public_key_part = mod_pow(
        public_key,
        nonce,
        params.p,
    )

    beta = (encoded_message * public_key_part) % params.p

    return Ciphertext(
        alpha=alpha,
        beta=beta,
    )


def multiply_ciphertexts(
    first: Ciphertext,
    second: Ciphertext,
    params: GroupParameters,
) -> Ciphertext:
    """
    Moltiplica due ciphertext componente per componente.

    Questa operazione corrisponde alla somma dei plaintext:

        Enc(x) * Enc(y) = Enc(x + y)
    """

    alpha = (first.alpha * second.alpha) % params.p
    beta = (first.beta * second.beta) % params.p

    return Ciphertext(
        alpha=alpha,
        beta=beta,
    )


def divide_ciphertexts(
    numerator: Ciphertext,
    denominator: Ciphertext,
    params: GroupParameters,
) -> Ciphertext:
    """
    Divide due ciphertext usando gli inversi modulari.

    Questa operazione corrisponde alla differenza dei plaintext:

        Enc(x) / Enc(y) = Enc(x - y)
    """

    alpha_inverse = mod_inverse(
        denominator.alpha,
        params.p,
    )

    beta_inverse = mod_inverse(
        denominator.beta,
        params.p,
    )

    alpha = (numerator.alpha * alpha_inverse) % params.p
    beta = (numerator.beta * beta_inverse) % params.p

    return Ciphertext(
        alpha=alpha,
        beta=beta,
    )


def bounded_discrete_log(
    value: int,
    params: GroupParameters,
    max_exponent: int,
) -> int | None:
    """
    Cerca x tale che:

        g^x = value mod p

    limitando la ricerca a:

        0 <= x <= max_exponent

    Usa baby-step giant-step, quindi è più efficiente
    di provare tutti gli esponenti uno alla volta.

    Restituisce None se il logaritmo non viene trovato
    nell'intervallo richiesto.
    """

    if max_exponent < 0:
        raise ValueError("max_exponent deve essere non negativo.")

    if not is_subgroup_element(value, params):
        raise ValueError("Il valore non appartiene al sottogruppo.")

    # Numero di passi circa uguale alla radice quadrata del limite.
    m = isqrt(max_exponent) + 1

    # Baby steps:
    # memorizziamo g^j per j = 0, ..., m - 1.
    baby_steps: dict[int, int] = {}

    current = 1

    for j in range(m):
        baby_steps.setdefault(current, j)
        current = (current * params.g) % params.p

    # Calcoliamo g^(-m) tramite l'inverso modulare.
    g_to_m = mod_pow(
        params.g,
        m,
        params.p,
    )

    factor = mod_inverse(
        g_to_m,
        params.p,
    )

    gamma = value

    # Giant steps:
    # cerchiamo una collisione con uno dei baby steps.
    for i in range(m + 1):
        if gamma in baby_steps:
            exponent = i * m + baby_steps[gamma]

            if exponent <= max_exponent:
                return exponent

        gamma = (gamma * factor) % params.p

    return None