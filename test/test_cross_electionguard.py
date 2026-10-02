"""
Test incrociati tra evoto ed ElectionGuard.

Questi test usano il clone locale contenuto in riferimento/
come banco di prova indipendente.

Se ElectionGuard non è disponibile localmente,
i test vengono saltati senza far fallire pytest.
"""

from pathlib import Path
import subprocess

import pytest


# Root del nostro repository.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ElectionGuard possiede un ambiente virtuale separato.
REFERENCE_ROOT = PROJECT_ROOT / "riferimento"


def _reference_python() -> Path | None:
    """
    Cerca l'interprete Python dell'ambiente ElectionGuard.

    Supportiamo sia Windows sia macOS/Linux.
    """

    windows_python = (
        REFERENCE_ROOT
        / ".venv"
        / "Scripts"
        / "python.exe"
    )

    unix_python = (
        REFERENCE_ROOT
        / ".venv"
        / "bin"
        / "python"
    )

    if windows_python.exists():
        return windows_python

    if unix_python.exists():
        return unix_python

    return None


def _run_with_reference_python(code: str) -> str:
    """
    Esegue un piccolo programma usando l'ambiente
    Python separato di ElectionGuard.
    """

    python_executable = _reference_python()

    if python_executable is None:
        pytest.skip(
            "Ambiente ElectionGuard locale non disponibile."
        )

    result = subprocess.run(
        [
            str(python_executable),
            "-c",
            code,
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout


def test_t1_elgamal_matches_electionguard():
    """
    T1.

    Con stessa chiave pubblica, stesso plaintext
    e stesso nonce, i ciphertext devono coincidere.
    """

    code = """
from electionguard.constants import (
    get_large_prime,
    get_small_prime,
    get_generator,
)
from electionguard.group import int_to_p, int_to_q
from electionguard.elgamal import elgamal_encrypt

from evoto.gruppo import GroupParameters
from evoto.elgamal import (
    encrypt,
    public_key_from_secret,
)

p = get_large_prime()
q = get_small_prime()
g = get_generator()

params = GroupParameters(
    p=p,
    q=q,
    g=g,
)

public_key = public_key_from_secret(
    2,
    params,
)

ours = encrypt(
    message=1,
    public_key=public_key,
    params=params,
    nonce=3,
)

electionguard = elgamal_encrypt(
    1,
    int_to_q(3),
    int_to_p(public_key),
)

success = (
    ours.alpha == int(electionguard.pad)
    and ours.beta == int(electionguard.data)
)

print("CROSS_RESULT=" + str(success))
"""

    output = _run_with_reference_python(code)

    assert "CROSS_RESULT=True" in output


def test_t2_hash_matches_electionguard():
    """
    T2.

    La nostra H viene confrontata con hash_elems.

    Gli interi vengono convertiti in ElementModQ
    perché ElectionGuard serializza i normali int
    Python in formato decimale.
    """

    code = """
from electionguard.constants import (
    get_large_prime,
    get_small_prime,
    get_generator,
)
from electionguard.group import int_to_q
from electionguard.hash import hash_elems

from evoto.gruppo import GroupParameters, H

p = get_large_prime()
q = get_small_prime()
g = get_generator()

params = GroupParameters(
    p=p,
    q=q,
    g=g,
)

values = (1, 2, 255)

ours = H(
    *values,
    params=params,
)

electionguard = hash_elems(
    *(int_to_q(value) for value in values)
)

print(
    "CROSS_RESULT="
    + str(ours == int(electionguard))
)
"""

    output = _run_with_reference_python(code)

    assert "CROSS_RESULT=True" in output


@pytest.mark.parametrize("plaintext", [0, 1])
def test_t3_electionguard_proof_verified_by_evoto(plaintext):
    """
    T3, prima direzione.

    ElectionGuard genera una prova 0/1
    e il nostro verificatore deve accettarla.
    """

    code = f"""
from electionguard.constants import (
    get_large_prime,
    get_small_prime,
    get_generator,
)
from electionguard.group import int_to_p, int_to_q
from electionguard.elgamal import elgamal_encrypt
from electionguard.chaum_pedersen import (
    make_disjunctive_chaum_pedersen,
)

from evoto.gruppo import GroupParameters
from evoto.elgamal import Ciphertext
from evoto.prove import (
    ValueSetBranchProof,
    ValueSetProof,
    verify_value_in_set,
)

p = get_large_prime()
q = get_small_prime()
g = get_generator()

params = GroupParameters(
    p=p,
    q=q,
    g=g,
)

public_key = pow(g, 2, p)
nonce = int_to_q(3)
context = int_to_q(12345)

eg_ciphertext = elgamal_encrypt(
    {plaintext},
    nonce,
    int_to_p(public_key),
)

eg_proof = make_disjunctive_chaum_pedersen(
    eg_ciphertext,
    nonce,
    int_to_p(public_key),
    context,
    int_to_q(99),
    {plaintext},
)

ciphertext = Ciphertext(
    alpha=int(eg_ciphertext.pad),
    beta=int(eg_ciphertext.data),
)

proof = ValueSetProof(
    branches=(
        ValueSetBranchProof(
            commitment_1=int(
                eg_proof.proof_zero_pad
            ),
            commitment_2=int(
                eg_proof.proof_zero_data
            ),
            challenge=int(
                eg_proof.proof_zero_challenge
            ),
            response=int(
                eg_proof.proof_zero_response
            ),
        ),
        ValueSetBranchProof(
            commitment_1=int(
                eg_proof.proof_one_pad
            ),
            commitment_2=int(
                eg_proof.proof_one_data
            ),
            challenge=int(
                eg_proof.proof_one_challenge
            ),
            response=int(
                eg_proof.proof_one_response
            ),
        ),
    )
)

success = verify_value_in_set(
    ciphertext=ciphertext,
    proof=proof,
    allowed_values=(0, 1),
    public_key=public_key,
    params=params,
    context=int(context),
)

print("CROSS_RESULT=" + str(success))
"""

    output = _run_with_reference_python(code)

    assert "CROSS_RESULT=True" in output


@pytest.mark.parametrize("plaintext", [0, 1])
def test_t3_evoto_proof_verified_by_electionguard(plaintext):
    """
    T3, seconda direzione.

    evoto genera una prova 0/1
    e ElectionGuard deve accettarla.
    """

    code = f"""
from electionguard.constants import (
    get_large_prime,
    get_small_prime,
    get_generator,
)
from electionguard.group import int_to_p, int_to_q
from electionguard.elgamal import ElGamalCiphertext
from electionguard.chaum_pedersen import (
    DisjunctiveChaumPedersenProof,
)

from evoto.gruppo import GroupParameters
from evoto.elgamal import encrypt
from evoto.prove import prove_value_in_set

p = get_large_prime()
q = get_small_prime()
g = get_generator()

params = GroupParameters(
    p=p,
    q=q,
    g=g,
)

public_key = pow(g, 2, p)

ciphertext = encrypt(
    message={plaintext},
    public_key=public_key,
    params=params,
    nonce=3,
)

proof = prove_value_in_set(
    ciphertext=ciphertext,
    plaintext={plaintext},
    nonce=3,
    allowed_values=(0, 1),
    public_key=public_key,
    params=params,
    context=12345,
    proof_nonce=7,
)

zero_branch = proof.branches[0]
one_branch = proof.branches[1]

global_challenge = (
    zero_branch.challenge
    + one_branch.challenge
) % q

eg_ciphertext = ElGamalCiphertext(
    int_to_p(ciphertext.alpha),
    int_to_p(ciphertext.beta),
)

eg_proof = DisjunctiveChaumPedersenProof(
    int_to_p(zero_branch.commitment_1),
    int_to_p(zero_branch.commitment_2),
    int_to_p(one_branch.commitment_1),
    int_to_p(one_branch.commitment_2),
    int_to_q(zero_branch.challenge),
    int_to_q(one_branch.challenge),
    int_to_q(global_challenge),
    int_to_q(zero_branch.response),
    int_to_q(one_branch.response),
)

success = eg_proof.is_valid(
    eg_ciphertext,
    int_to_p(public_key),
    int_to_q(12345),
)

print("CROSS_RESULT=" + str(success))
"""

    output = _run_with_reference_python(code)

    assert "CROSS_RESULT=True" in output


def test_t4_complete_tally_matches_electionguard_and_plaintext():
    """
    T4.

    Sugli stessi voti e nonce, i totali cifrati di evoto
    ed ElectionGuard coincidono e decifrano nel conteggio in chiaro.
    """

    code = """
from electionguard.constants import (
    get_large_prime,
    get_small_prime,
    get_generator,
)
from electionguard.group import int_to_p, int_to_q
from electionguard.elgamal import (
    elgamal_add,
    elgamal_encrypt,
)

from evoto.gruppo import (
    GroupParameters,
    mod_inverse,
    mod_pow,
)
from evoto.elgamal import (
    bounded_discrete_log,
    encrypt,
    multiply_ciphertexts,
    public_key_from_secret,
)

p = get_large_prime()
q = get_small_prime()
g = get_generator()

params = GroupParameters(
    p=p,
    q=q,
    g=g,
)

secret_key = 2

public_key = public_key_from_secret(
    secret_key,
    params,
)

# Tre caselle indipendenti aggregate su cinque schede
# La terza casella può essere interpretata come scheda bianca
ballots = (
    (1, 0, 0),
    (0, 1, 0),
    (1, 0, 0),
    (0, 0, 1),
    (0, 1, 0),
)

nonces = (
    (3, 5, 7),
    (11, 13, 17),
    (19, 23, 29),
    (31, 37, 41),
    (43, 47, 53),
)

success = True

for selection_index in range(3):
    ours_ciphertexts = []
    electionguard_ciphertexts = []

    for ballot_index, ballot in enumerate(ballots):
        plaintext = ballot[selection_index]
        nonce = nonces[
            ballot_index
        ][selection_index]

        ours_ciphertexts.append(
            encrypt(
                message=plaintext,
                public_key=public_key,
                params=params,
                nonce=nonce,
            )
        )

        electionguard_ciphertexts.append(
            elgamal_encrypt(
                plaintext,
                int_to_q(nonce),
                int_to_p(public_key),
            )
        )

    ours_tally = ours_ciphertexts[0]

    for ciphertext in ours_ciphertexts[1:]:
        ours_tally = multiply_ciphertexts(
            ours_tally,
            ciphertext,
            params,
        )

    electionguard_tally = elgamal_add(
        *electionguard_ciphertexts
    )

    same_ciphertext = (
        ours_tally.alpha
        == int(electionguard_tally.pad)
        and ours_tally.beta
        == int(electionguard_tally.data)
    )

    decryption_factor = mod_pow(
        ours_tally.alpha,
        secret_key,
        p,
    )

    encoded_total = (
        ours_tally.beta
        * mod_inverse(
            decryption_factor,
            p,
        )
    ) % p

    ours_total = bounded_discrete_log(
        encoded_total,
        params,
        max_exponent=len(ballots),
    )

    electionguard_total = (
        electionguard_tally.decrypt(
            int_to_q(secret_key)
        )
    )

    clear_total = sum(
        ballot[selection_index]
        for ballot in ballots
    )

    success = success and (
        same_ciphertext
        and ours_total == clear_total
        and electionguard_total == clear_total
    )

print("CROSS_RESULT=" + str(success))
"""

    output = _run_with_reference_python(code)

    assert "CROSS_RESULT=True" in output