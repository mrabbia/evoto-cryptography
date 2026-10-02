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


# Gruppo didattico usato nei test e nel notebook.
# Non è il gruppo di sicurezza previsto per la demo finale.
TEST_PARAMS = GroupParameters(
    p=2579,
    q=1289,
    g=4,
)


# Gruppo MODP 2048/256 usato per la demo finale
# Parametri pubblicati in RFC 5114, sezione 2.3
DEMO_PARAMS = GroupParameters(
    p=int(
        "87A8E61DB4B6663CFFBBD19C65195999"
        "8CEEF608660DD0F25D2CEED4435E3B00"
        "E00DF8F1D61957D4FAF7DF4561B2AA30"
        "16C3D91134096FAA3BF4296D830E9A7C"
        "209E0C6497517ABD5A8A9D306BCF67ED"
        "91F9E6725B4758C022E0B1EF4275BF7B"
        "6C5BFC11D45F9088B941F54EB1E59BB8"
        "BC39A0BF12307F5C4FDB70C581B23F76"
        "B63ACAE1CAA6B7902D52526735488A0E"
        "F13C6D9A51BFA4AB3AD8347796524D8E"
        "F6A167B5A41825D967E144E514056425"
        "1CCACB83E6B486F6B3CA3F7971506026"
        "C0B857F689962856DED4010ABD0BE621"
        "C3A3960A54E710C375F26375D7014103"
        "A4B54330C198AF126116D2276E11715F"
        "693877FAD7EF09CADB094AE91E1A1597",
        16,
    ),
    q=int(
        "8CF83642A709A097B447997640129DA2"
        "99B1A47D1EB3750BA308B0FE64F5FBD3",
        16,
    ),
    g=int(
        "3FB32C9B73134D0B2E77506660EDBD48"
        "4CA7B18F21EF205407F4793A1A0BA125"
        "10DBC15077BE463FFF4FED4AAC0BB555"
        "BE3A6C1B0C6B47B1BC3773BF7E8C6F62"
        "901228F8C28CBB18A55AE31341000A65"
        "0196F931C77A57F2DDF463E5E9EC144B"
        "777DE62AAAB8A8628AC376D282D6ED38"
        "64E67982428EBC831D14348F6F2F9193"
        "B5045AF2767164E1DFC967C1FB3F2E55"
        "A4BD1BFFE83B9C80D052B985D182EA0A"
        "DB2A3B7313D3FE14C8484B1E052588B9"
        "B7D2BBD2DF016199ECD06E1557CD0915"
        "B3353BBB64E0EC377FD028370DF92B52"
        "C7891428CDC67EB6184B523D1DB246C3"
        "2F63078490F00EF8D647D148D4795451"
        "5E2327CFEF98C582664B4C0F6CC41659",
        16,
    ),
)


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