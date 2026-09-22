"""
Prove a conoscenza zero usate dal progetto evoto.

In questo primo blocco implementiamo:
- prova di Schnorr;
- prova di Chaum-Pedersen generica.

Entrambe vengono rese non interattive tramite Fiat-Shamir,
usando l'hash canonico H definito in evoto.gruppo.
"""

from dataclasses import dataclass
import secrets

from evoto.gruppo import (
    GroupParameters,
    H,
    is_subgroup_element,
    mod_inverse,
    mod_pow,
)


@dataclass(frozen=True)
class SchnorrProof:
    """
    Prova di conoscenza di un esponente x tale che:

        Y = g^x mod p
    """

    commitment: int
    challenge: int
    response: int


@dataclass(frozen=True)
class ChaumPedersenProof:
    """
    Prova che due logaritmi discreti hanno lo stesso esponente:

        Y1 = g1^x
        Y2 = g2^x
    """

    commitment_1: int
    commitment_2: int
    challenge: int
    response: int


def prove_schnorr(
    secret: int,
    public_value: int,
    params: GroupParameters,
    context: tuple[int, ...],
    nonce: int | None = None,
) -> SchnorrProof:
    """
    Genera una prova di Schnorr.

    context contiene i valori che identificano la prova.

    Per esempio, per un impegno K_i,j:
        context = (Q, i, j)

    La challenge diventa quindi:
        H(Q, i, j, g, K_i,j, h)
    """

    if not 0 <= secret < params.q:
        raise ValueError("Il segreto deve essere compreso tra 0 e q - 1.")

    if not is_subgroup_element(public_value, params):
        raise ValueError("Il valore pubblico non appartiene al sottogruppo.")

    if nonce is None:
        nonce = secrets.randbelow(params.q - 1) + 1

    if not 1 <= nonce < params.q:
        raise ValueError("Il nonce deve essere compreso tra 1 e q - 1.")

    # Impegno della prova: h = g^u.
    commitment = mod_pow(
        params.g,
        nonce,
        params.p,
    )

    # Fiat-Shamir lega contesto, enunciato e impegno.
    challenge = H(
        *context,
        params.g,
        public_value,
        commitment,
        params=params,
    )

    # Risposta: z = u + c*x mod q.
    response = (
        nonce
        + challenge * secret
    ) % params.q

    return SchnorrProof(
        commitment=commitment,
        challenge=challenge,
        response=response,
    )


def verify_schnorr(
    public_value: int,
    proof: SchnorrProof,
    params: GroupParameters,
    context: tuple[int, ...],
) -> bool:
    """
    Verifica una prova di Schnorr.

    Controlliamo:
    - appartenenza al sottogruppo;
    - challenge e risposta nel range corretto;
    - challenge Fiat-Shamir;
    - equazione g^z = h * Y^c mod p.
    """

    if not is_subgroup_element(public_value, params):
        return False

    if not is_subgroup_element(proof.commitment, params):
        return False

    if not 0 <= proof.challenge < params.q:
        return False

    if not 0 <= proof.response < params.q:
        return False

    expected_challenge = H(
        *context,
        params.g,
        public_value,
        proof.commitment,
        params=params,
    )

    if proof.challenge != expected_challenge:
        return False

    left = mod_pow(
        params.g,
        proof.response,
        params.p,
    )

    right = (
        proof.commitment
        * mod_pow(
            public_value,
            proof.challenge,
            params.p,
        )
    ) % params.p

    return left == right


def prove_chaum_pedersen(
    secret: int,
    base_1: int,
    public_1: int,
    base_2: int,
    public_2: int,
    params: GroupParameters,
    context: tuple[int, ...],
    nonce: int | None = None,
) -> ChaumPedersenProof:
    """
    Genera una prova di Chaum-Pedersen.

    Dimostra che:

        public_1 = base_1^secret
        public_2 = base_2^secret

    senza rivelare secret.

    La challenge è:

        H(context..., base_1, public_1,
                      base_2, public_2,
                      a, b)
    """

    if not 0 <= secret < params.q:
        raise ValueError("Il segreto deve essere compreso tra 0 e q - 1.")

    for value in (
        base_1,
        public_1,
        base_2,
        public_2,
    ):
        if not is_subgroup_element(value, params):
            raise ValueError(
                "Tutti gli elementi pubblici devono appartenere al sottogruppo."
            )

    if nonce is None:
        nonce = secrets.randbelow(params.q - 1) + 1

    if not 1 <= nonce < params.q:
        raise ValueError("Il nonce deve essere compreso tra 1 e q - 1.")

    # Impegni della prova.
    commitment_1 = mod_pow(
        base_1,
        nonce,
        params.p,
    )

    commitment_2 = mod_pow(
        base_2,
        nonce,
        params.p,
    )

    challenge = H(
        *context,
        base_1,
        public_1,
        base_2,
        public_2,
        commitment_1,
        commitment_2,
        params=params,
    )

    response = (
        nonce
        + challenge * secret
    ) % params.q

    return ChaumPedersenProof(
        commitment_1=commitment_1,
        commitment_2=commitment_2,
        challenge=challenge,
        response=response,
    )


def verify_chaum_pedersen(
    base_1: int,
    public_1: int,
    base_2: int,
    public_2: int,
    proof: ChaumPedersenProof,
    params: GroupParameters,
    context: tuple[int, ...],
) -> bool:
    """
    Verifica una prova di Chaum-Pedersen.

    Controlliamo entrambe le equazioni:

        base_1^z = a * public_1^c
        base_2^z = b * public_2^c
    """

    for value in (
        base_1,
        public_1,
        base_2,
        public_2,
        proof.commitment_1,
        proof.commitment_2,
    ):
        if not is_subgroup_element(value, params):
            return False

    if not 0 <= proof.challenge < params.q:
        return False

    if not 0 <= proof.response < params.q:
        return False

    expected_challenge = H(
        *context,
        base_1,
        public_1,
        base_2,
        public_2,
        proof.commitment_1,
        proof.commitment_2,
        params=params,
    )

    if proof.challenge != expected_challenge:
        return False

    left_1 = mod_pow(
        base_1,
        proof.response,
        params.p,
    )

    right_1 = (
        proof.commitment_1
        * mod_pow(
            public_1,
            proof.challenge,
            params.p,
        )
    ) % params.p

    left_2 = mod_pow(
        base_2,
        proof.response,
        params.p,
    )

    right_2 = (
        proof.commitment_2
        * mod_pow(
            public_2,
            proof.challenge,
            params.p,
        )
    ) % params.p

    return (
        left_1 == right_1
        and left_2 == right_2
    )


@dataclass(frozen=True)
class ValueSetBranchProof:
    """
    Singolo ramo della prova OR.

    Ogni ramo contiene:
    - due impegni;
    - una challenge parziale;
    - una risposta.
    """

    commitment_1: int
    commitment_2: int
    challenge: int
    response: int


@dataclass(frozen=True)
class ValueSetProof:
    """
    Prova OR che il plaintext appartiene a un insieme di valori ammessi.

    I rami sono nello stesso ordine di allowed_values.
    """

    branches: tuple[ValueSetBranchProof, ...]


def prove_value_in_set(
    ciphertext,
    plaintext: int,
    nonce: int,
    allowed_values: tuple[int, ...],
    public_key: int,
    params: GroupParameters,
    context: int,
    proof_nonce: int | None = None,
) -> ValueSetProof:
    """
    Dimostra che il ciphertext cifra uno dei valori ammessi.

    Il ramo corrispondente al plaintext reale viene costruito
    onestamente. Gli altri rami vengono simulati.

    La challenge complessiva viene calcolata con Fiat-Shamir.
    """

    if not allowed_values:
        raise ValueError("allowed_values non può essere vuoto.")

    if len(set(allowed_values)) != len(allowed_values):
        raise ValueError("allowed_values non può contenere duplicati.")

    if plaintext not in allowed_values:
        raise ValueError("Il plaintext non appartiene ai valori ammessi.")

    if not 1 <= nonce < params.q:
        raise ValueError("Il nonce deve essere compreso tra 1 e q - 1.")

    if not is_subgroup_element(public_key, params):
        raise ValueError("La chiave pubblica non appartiene al sottogruppo.")

    if not is_subgroup_element(ciphertext.alpha, params):
        raise ValueError("alpha non appartiene al sottogruppo.")

    if not is_subgroup_element(ciphertext.beta, params):
        raise ValueError("beta non appartiene al sottogruppo.")

    if proof_nonce is None:
        proof_nonce = secrets.randbelow(params.q - 1) + 1

    if not 1 <= proof_nonce < params.q:
        raise ValueError("Il nonce della prova deve essere compreso tra 1 e q - 1.")

    real_index = allowed_values.index(plaintext)

    # Prepariamo le strutture temporanee dei vari rami.
    commitments: list[tuple[int, int] | None] = []
    challenges: list[int | None] = []
    responses: list[int | None] = []

    for index, value in enumerate(allowed_values):
        if index == real_index:
            # Nel ramo reale usiamo un nonce vero.
            commitment_1 = mod_pow(
                params.g,
                proof_nonce,
                params.p,
            )

            commitment_2 = mod_pow(
                public_key,
                proof_nonce,
                params.p,
            )

            commitments.append(
                (commitment_1, commitment_2)
            )
            challenges.append(None)
            responses.append(None)

        else:
            # Nei rami simulati scegliamo challenge e risposta casuali.
            simulated_challenge = secrets.randbelow(params.q)
            simulated_response = secrets.randbelow(params.q)

            # Calcoliamo beta / g^value.
            encoded_value = mod_pow(
                params.g,
                value,
                params.p,
            )

            adjusted_beta = (
                ciphertext.beta
                * mod_inverse(encoded_value, params.p)
            ) % params.p

            # Ricostruiamo gli impegni in modo che
            # le equazioni di verifica risultino vere.
            alpha_challenge = mod_pow(
                ciphertext.alpha,
                simulated_challenge,
                params.p,
            )

            adjusted_beta_challenge = mod_pow(
                adjusted_beta,
                simulated_challenge,
                params.p,
            )

            commitment_1 = (
                mod_pow(
                    params.g,
                    simulated_response,
                    params.p,
                )
                * mod_inverse(
                    alpha_challenge,
                    params.p,
                )
            ) % params.p

            commitment_2 = (
                mod_pow(
                    public_key,
                    simulated_response,
                    params.p,
                )
                * mod_inverse(
                    adjusted_beta_challenge,
                    params.p,
                )
            ) % params.p

            commitments.append(
                (commitment_1, commitment_2)
            )
            challenges.append(simulated_challenge)
            responses.append(simulated_response)

    # Costruiamo la challenge globale Fiat-Shamir.
    hash_values = [
        context,
        ciphertext.alpha,
        ciphertext.beta,
    ]

    for commitment_1, commitment_2 in commitments:
        hash_values.extend(
            [commitment_1, commitment_2]
        )

    global_challenge = H(
        *hash_values,
        params=params,
    )

    # La challenge del ramo reale completa la somma modulo q.
    simulated_sum = sum(
        challenge
        for challenge in challenges
        if challenge is not None
    ) % params.q

    real_challenge = (
        global_challenge - simulated_sum
    ) % params.q

    real_response = (
        proof_nonce
        + real_challenge * nonce
    ) % params.q

    challenges[real_index] = real_challenge
    responses[real_index] = real_response

    branches = tuple(
        ValueSetBranchProof(
            commitment_1=commitments[index][0],
            commitment_2=commitments[index][1],
            challenge=challenges[index],
            response=responses[index],
        )
        for index in range(len(allowed_values))
    )

    return ValueSetProof(
        branches=branches,
    )


def verify_value_in_set(
    ciphertext,
    proof: ValueSetProof,
    allowed_values: tuple[int, ...],
    public_key: int,
    params: GroupParameters,
    context: int,
) -> bool:
    """
    Verifica una prova OR.

    Il verificatore non conosce quale ramo sia quello reale.
    Controlla quindi tutti i rami allo stesso modo.
    """

    if not allowed_values:
        return False

    if len(set(allowed_values)) != len(allowed_values):
        return False

    if len(proof.branches) != len(allowed_values):
        return False

    if not is_subgroup_element(public_key, params):
        return False

    if not is_subgroup_element(ciphertext.alpha, params):
        return False

    if not is_subgroup_element(ciphertext.beta, params):
        return False

    hash_values = [
        context,
        ciphertext.alpha,
        ciphertext.beta,
    ]

    challenge_sum = 0

    for value, branch in zip(
        allowed_values,
        proof.branches,
    ):
        if not is_subgroup_element(
            branch.commitment_1,
            params,
        ):
            return False

        if not is_subgroup_element(
            branch.commitment_2,
            params,
        ):
            return False

        if not 0 <= branch.challenge < params.q:
            return False

        if not 0 <= branch.response < params.q:
            return False

        hash_values.extend(
            [
                branch.commitment_1,
                branch.commitment_2,
            ]
        )

        challenge_sum = (
            challenge_sum + branch.challenge
        ) % params.q

        # Calcoliamo beta / g^value.
        encoded_value = mod_pow(
            params.g,
            value,
            params.p,
        )

        adjusted_beta = (
            ciphertext.beta
            * mod_inverse(
                encoded_value,
                params.p,
            )
        ) % params.p

        # Prima equazione:
        # g^z = a * alpha^c
        left_1 = mod_pow(
            params.g,
            branch.response,
            params.p,
        )

        right_1 = (
            branch.commitment_1
            * mod_pow(
                ciphertext.alpha,
                branch.challenge,
                params.p,
            )
        ) % params.p

        if left_1 != right_1:
            return False

        # Seconda equazione:
        # K^z = b * (beta / g^value)^c
        left_2 = mod_pow(
            public_key,
            branch.response,
            params.p,
        )

        right_2 = (
            branch.commitment_2
            * mod_pow(
                adjusted_beta,
                branch.challenge,
                params.p,
            )
        ) % params.p

        if left_2 != right_2:
            return False

    expected_challenge = H(
        *hash_values,
        params=params,
    )

    return challenge_sum == expected_challenge