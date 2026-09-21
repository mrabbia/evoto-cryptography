"""
Primitive di base per il gruppo crittografico usato da evoto.

Questo modulo contiene:
- i parametri condivisi del gruppo;
- operazioni modulari semplici;
- controllo dei parametri;
- controllo di appartenenza al sottogruppo;
- hash canonico H.

Gli altri moduli crittografici devono riutilizzare queste funzioni
senza creare implementazioni alternative.
"""

from dataclasses import dataclass
import hashlib

import gmpy2


@dataclass(frozen=True)
class GroupParameters:
    """
    Parametri del gruppo crittografico.

    p: modulo primo.
    q: ordine primo del sottogruppo.
    g: generatore del sottogruppo di ordine q.
    """

    p: int
    q: int
    g: int


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """
    Calcola base^exponent modulo modulus.

    Usiamo gmpy2 per rendere efficiente l'esponenziazione modulare.
    """

    if modulus <= 0:
        raise ValueError("Il modulo deve essere positivo.")

    if exponent < 0:
        raise ValueError("L'esponente deve essere non negativo.")

    return int(gmpy2.powmod(base, exponent, modulus))


def mod_inverse(value: int, modulus: int) -> int:
    """
    Calcola l'inverso moltiplicativo di value modulo modulus.

    L'inverso x soddisfa:
        value * x ≡ 1 (mod modulus)

    È utile, ad esempio, per divisioni modulari e coefficienti di Lagrange.
    """

    if modulus <= 1:
        raise ValueError("Il modulo deve essere maggiore di 1.")

    try:
        inverse = gmpy2.invert(value, modulus)
    except ZeroDivisionError as exc:
        raise ValueError(
            "L'inverso modulare non esiste per questi valori."
        ) from exc

    if inverse == 0:
        raise ValueError("L'inverso modulare non esiste per questi valori.")

    return int(inverse)


def validate_group_parameters(params: GroupParameters) -> bool:
    """
    Controlla che i parametri rispettino le proprietà richieste dal progetto.

    Verifichiamo:
    - p primo;
    - q primo;
    - q divide p - 1;
    - g è compreso tra 1 e p - 1;
    - g^q ≡ 1 mod p;
    - g non è l'identità 1.
    """

    p = params.p
    q = params.q
    g = params.g

    if p <= 2 or not gmpy2.is_prime(p):
        return False

    if q <= 1 or not gmpy2.is_prime(q):
        return False

    if (p - 1) % q != 0:
        return False

    if not 1 < g < p:
        return False

    if mod_pow(g, q, p) != 1:
        return False

    return True


def is_subgroup_element(value: int, params: GroupParameters) -> bool:
    """
    Controlla se value appartiene al sottogruppo di ordine q.

    Un elemento del sottogruppo deve soddisfare:
        value^q ≡ 1 mod p
    """

    if not 0 < value < params.p:
        return False

    return mod_pow(value, params.q, params.p) == 1


def _int_to_canonical_hex(value: int) -> str:
    """
    Converte un intero nel formato usato dall'hash canonico.

    Regole:
    - esadecimale;
    - lettere maiuscole;
    - numero pari di caratteri.

    Esempio:
        1   -> "01"
        255 -> "FF"
    """

    if value < 0:
        raise ValueError("L'hash canonico accetta solo interi non negativi.")

    encoded = format(value, "X")

    if len(encoded) % 2 != 0:
        encoded = "0" + encoded

    return encoded


def H(*values: int, params: GroupParameters) -> int:
    """
    Calcola l'hash canonico del progetto.

    La stringa data a SHA-256 ha la forma:

        |x1|x2|...|

    dove ogni xi è rappresentato in esadecimale maiuscolo
    e con lunghezza pari.

    Il risultato finale viene ridotto modulo q.
    """

    hasher = hashlib.sha256()

    # Il formato concordato comincia sempre con il separatore "|".
    hasher.update(b"|")

    for value in values:
        encoded = _int_to_canonical_hex(value)

        # Dopo ogni valore viene aggiunto nuovamente "|".
        hasher.update(encoded.encode("ascii"))
        hasher.update(b"|")

    digest_as_integer = int.from_bytes(hasher.digest(), byteorder="big")

    return digest_as_integer % params.q