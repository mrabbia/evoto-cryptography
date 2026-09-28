"""
Bacheca pubblica e conteggio omomorfico del progetto evoto.

Questo modulo contiene:
- l'aggregazione omomorfica dei cifrati;
- la bacheca a sola aggiunta con la catena dei codici di tracciamento;
- il deposito delle schede (CAST) e delle schede sprecate (SPOILED)
  per la sfida di Benaloh;
- il rifiuto delle schede copiate da altri elettori;
- la lista privata degli aventi diritto;
- il conteggio e la decifratura dei totali di ogni circoscrizione.

Segue la specifica condivisa docs/spec_f1.md, sezioni 43, 44 e 45.
"""

from dataclasses import dataclass

from evoto.decifratura import (
    DecryptionShare,
    compute_decryption_share,
    decrypt_tally,
    verify_decryption_share,
)
from evoto.elgamal import (
    Ciphertext,
    encrypt,
    multiply_ciphertexts,
)
from evoto.garanti import (
    GuardianRecord,
    compute_verification_key,
)
from evoto.gruppo import (
    GroupParameters,
    H,
)
from evoto.scheda import (
    BallotLayout,
    BallotProofs,
    BallotWitness,
    EncryptedBallot,
    verify_ballot,
)


# Stati di una scheda sulla bacheca.
CAST = "CAST"
SPOILED = "SPOILED"

# Codifica intera degli stati, usata nell'hash dei codici di tracciamento.
STATE_CODES = {
    CAST: 1,
    SPOILED: 2,
}


def aggregate_ciphertexts(
    ciphertexts: tuple[Ciphertext, ...],
    params: GroupParameters,
) -> Ciphertext:
    """
    Somma i voti restando sui cifrati.

        (A, B) = (∏ alpha_j, ∏ beta_j) = Enc(Σ v_j)

    Nessuna scheda viene decifrata: il risultato è il tally cifrato,
    l'unico valore che i garanti decifreranno.

    Con una lista vuota restituisce Enc(0) = (1, 1), cioè l'elemento
    neutro del prodotto.
    """

    tally = Ciphertext(
        alpha=1,
        beta=1,
    )

    for ciphertext in ciphertexts:
        tally = multiply_ciphertexts(
            tally,
            ciphertext,
            params,
        )

    return tally


@dataclass(frozen=True)
class BoardEntry:
    """
    Una riga della bacheca pubblica.

    sequence: posizione sulla bacheca, a partire da 1.
    district_index: circoscrizione della scheda.
    state: CAST oppure SPOILED.
    ballot_hash: impronta della scheda, mostrata all'elettore.
    tracking_code: codice di tracciamento, concatenato al precedente.
    revealed_witness: voti e nonce rivelati, solo per le schede SPOILED.
    """

    sequence: int
    district_index: int
    state: str
    ballot: EncryptedBallot
    proofs: BallotProofs
    ballot_hash: int
    tracking_code: int
    revealed_witness: BallotWitness | None


@dataclass(frozen=True)
class BulletinBoard:
    """
    Bacheca pubblica a sola aggiunta.

    Ogni funzione che deposita una scheda restituisce una nuova bacheca:
    le righe già pubblicate non vengono mai modificate.
    """

    extended_base_hash: int
    genesis_code: int
    entries: tuple[BoardEntry, ...]

    def last_tracking_code(self) -> int:
        """
        Restituisce l'ultimo codice della catena, oppure il codice
        iniziale se la bacheca è vuota.
        """

        if not self.entries:
            return self.genesis_code

        return self.entries[-1].tracking_code


@dataclass(frozen=True)
class VoterRoll:
    """
    Lista degli aventi diritto, tenuta dal seggio e mai pubblicata.

    voter_districts associa a ogni elettore la sua circoscrizione.
    voted contiene chi ha già depositato la scheda.

    La bacheca non contiene nessun identificativo degli elettori:
    solo così una scheda pubblica non si può collegare a una persona.
    """

    voter_districts: dict[str, int]
    voted: frozenset[str]


@dataclass(frozen=True)
class DistrictTally:
    """
    Totali cifrati di una circoscrizione, uno per casella.

    ballot_count è il numero di schede CAST aggregate: è pubblico
    e limita il logaritmo discreto della decifratura.
    """

    district_index: int
    ballot_count: int
    list_tallies: tuple[Ciphertext, ...]
    blank_tally: Ciphertext
    preference_tallies: tuple[Ciphertext, ...]

    def all_ciphertexts(self) -> tuple[Ciphertext, ...]:
        """
        Restituisce i totali cifrati nell'ordine canonico:
        liste, scheda bianca, preferenze.
        """

        return (
            self.list_tallies
            + (self.blank_tally,)
            + self.preference_tallies
        )


@dataclass(frozen=True)
class DistrictResult:
    """
    Risultato in chiaro di una circoscrizione.

    decryption_shares[k] contiene le share di decifratura dei garanti
    presenti per il k-esimo totale, nell'ordine canonico: servono al
    verificatore per ricontrollare ogni decifratura.
    """

    district_index: int
    ballot_count: int
    list_votes: tuple[int, ...]
    blank_votes: int
    preference_votes: tuple[int, ...]
    decryption_shares: tuple[tuple[DecryptionShare, ...], ...]


def compute_ballot_hash(
    ballot: EncryptedBallot,
    district_index: int,
    extended_base_hash: int,
    params: GroupParameters,
) -> int:
    """
    Calcola l'impronta di una scheda cifrata.

        H(Q_bar, d, alpha_1, beta_1, ..., alpha_m, beta_m)

    con i cifrati nell'ordine canonico della scheda.

    Il dispositivo la mostra all'elettore prima che scelga se depositare
    o sprecare la scheda: da quel momento non può più cambiarla.
    """

    if district_index < 0:
        raise ValueError("L'indice della circoscrizione deve essere non negativo.")

    values = [
        extended_base_hash,
        district_index,
    ]

    for ciphertext in ballot.all_ciphertexts():
        values.extend(
            [ciphertext.alpha, ciphertext.beta]
        )

    return H(
        *values,
        params=params,
    )


def compute_genesis_code(
    extended_base_hash: int,
    params: GroupParameters,
) -> int:
    """
    Calcola il primo anello della catena dei codici.

        code_0 = H(Q_bar)

    Lega la bacheca a una sola elezione.
    """

    return H(
        extended_base_hash,
        params=params,
    )


def compute_tracking_code(
    previous_code: int,
    sequence: int,
    state: str,
    ballot_hash: int,
    params: GroupParameters,
) -> int:
    """
    Calcola il codice di tracciamento di una riga della bacheca.

        code_i = H(code_(i-1), i, stato, impronta)

    Ogni codice dipende da tutti i precedenti: togliere, riordinare
    o modificare una riga cambia tutti i codici successivi.
    """

    if state not in STATE_CODES:
        raise ValueError("Lo stato della scheda deve essere CAST o SPOILED.")

    if sequence < 1:
        raise ValueError("La posizione sulla bacheca parte da 1.")

    return H(
        previous_code,
        sequence,
        STATE_CODES[state],
        ballot_hash,
        params=params,
    )


def create_bulletin_board(
    extended_base_hash: int,
    params: GroupParameters,
) -> BulletinBoard:
    """
    Crea una bacheca vuota per l'elezione identificata da Q_bar.
    """

    return BulletinBoard(
        extended_base_hash=extended_base_hash,
        genesis_code=compute_genesis_code(extended_base_hash, params),
        entries=(),
    )


def _ciphertext_key(
    ballot: EncryptedBallot,
) -> tuple[tuple[int, int], ...]:
    """
    Restituisce tutti i cifrati della scheda come tupla di coppie.

    Serve a riconoscere una scheda copiata da un altro elettore.
    """

    return tuple(
        (ciphertext.alpha, ciphertext.beta)
        for ciphertext in ballot.all_ciphertexts()
    )


def verify_spoiled_ballot(
    ballot: EncryptedBallot,
    witness: BallotWitness,
    public_key: int,
    params: GroupParameters,
) -> bool:
    """
    Controlla una scheda sprecata ricifrandola con i dati rivelati.

    Se il dispositivo ha cifrato onestamente, voti e nonce rivelati
    producono esattamente gli stessi cifrati. È la sfida di Benaloh:
    il dispositivo non sa in anticipo quali schede verranno controllate.
    """

    plaintexts = (
        witness.list_plaintexts
        + (witness.blank_plaintext,)
        + witness.preference_plaintexts
    )

    nonces = (
        witness.list_nonces
        + (witness.blank_nonce,)
        + witness.preference_nonces
    )

    ciphertexts = ballot.all_ciphertexts()

    if not len(ciphertexts) == len(plaintexts) == len(nonces):
        return False

    for ciphertext, plaintext, nonce in zip(
        ciphertexts,
        plaintexts,
        nonces,
        strict=True,
    ):
        try:
            expected = encrypt(
                message=plaintext,
                public_key=public_key,
                params=params,
                nonce=nonce,
            )
        except ValueError:
            return False

        if expected != ciphertext:
            return False

    return True


def submit_ballot(
    board: BulletinBoard,
    district_index: int,
    layout: BallotLayout,
    ballot: EncryptedBallot,
    proofs: BallotProofs,
    public_key: int,
    params: GroupParameters,
    state: str,
    revealed_witness: BallotWitness | None = None,
) -> BulletinBoard:
    """
    Pubblica una scheda sulla bacheca e restituisce la nuova bacheca.

    Prima di pubblicarla controlliamo che:
    - le prove R1-R5 siano valide per il layout della circoscrizione;
    - la scheda non sia la copia di una scheda già presente;
    - una scheda SPOILED rivelata corrisponda davvero ai suoi cifrati;
    - una scheda CAST non riveli nulla.
    """

    if state not in STATE_CODES:
        raise ValueError("Lo stato della scheda deve essere CAST o SPOILED.")

    if state == CAST and revealed_witness is not None:
        raise ValueError("Una scheda depositata non deve rivelare il voto.")

    if state == SPOILED and revealed_witness is None:
        raise ValueError("Una scheda sprecata deve rivelare voti e nonce.")

    valid = verify_ballot(
        layout=layout,
        ballot=ballot,
        proofs=proofs,
        public_key=public_key,
        params=params,
        context=board.extended_base_hash,
    )

    if not valid:
        raise ValueError("Le prove di validità della scheda non sono valide.")

    # Una scheda copiata permetterebbe di votare come un altro elettore
    # e, in una circoscrizione piccola, di scoprire il suo voto.
    key = _ciphertext_key(ballot)

    for entry in board.entries:
        if _ciphertext_key(entry.ballot) == key:
            raise ValueError("La scheda è già presente sulla bacheca.")

    if state == SPOILED and not verify_spoiled_ballot(
        ballot,
        revealed_witness,
        public_key,
        params,
    ):
        raise ValueError(
            "I dati rivelati non corrispondono alla scheda sprecata."
        )

    sequence = len(board.entries) + 1

    ballot_hash = compute_ballot_hash(
        ballot,
        district_index,
        board.extended_base_hash,
        params,
    )

    tracking_code = compute_tracking_code(
        board.last_tracking_code(),
        sequence,
        state,
        ballot_hash,
        params,
    )

    entry = BoardEntry(
        sequence=sequence,
        district_index=district_index,
        state=state,
        ballot=ballot,
        proofs=proofs,
        ballot_hash=ballot_hash,
        tracking_code=tracking_code,
        revealed_witness=revealed_witness,
    )

    return BulletinBoard(
        extended_base_hash=board.extended_base_hash,
        genesis_code=board.genesis_code,
        entries=board.entries + (entry,),
    )


def cast_ballot(
    board: BulletinBoard,
    district_index: int,
    layout: BallotLayout,
    ballot: EncryptedBallot,
    proofs: BallotProofs,
    public_key: int,
    params: GroupParameters,
) -> BulletinBoard:
    """
    Deposita una scheda: verrà contata e non rivela nulla.
    """

    return submit_ballot(
        board=board,
        district_index=district_index,
        layout=layout,
        ballot=ballot,
        proofs=proofs,
        public_key=public_key,
        params=params,
        state=CAST,
    )


def spoil_ballot(
    board: BulletinBoard,
    district_index: int,
    layout: BallotLayout,
    ballot: EncryptedBallot,
    proofs: BallotProofs,
    witness: BallotWitness,
    public_key: int,
    params: GroupParameters,
) -> BulletinBoard:
    """
    Pubblica una scheda sprecata insieme ai dati che la aprono.

    Non viene contata: serve soltanto a controllare il dispositivo.
    L'elettore poi prepara una nuova scheda, con nuovi nonce.
    """

    return submit_ballot(
        board=board,
        district_index=district_index,
        layout=layout,
        ballot=ballot,
        proofs=proofs,
        public_key=public_key,
        params=params,
        state=SPOILED,
        revealed_witness=witness,
    )


def verify_board_chain(
    board: BulletinBoard,
    params: GroupParameters,
) -> bool:
    """
    Ricalcola impronte e codici di tutta la bacheca.

    È il controllo V4 del verificatore: una riga tolta, aggiunta,
    spostata o modificata rompe la catena.
    """

    if board.genesis_code != compute_genesis_code(
        board.extended_base_hash,
        params,
    ):
        return False

    previous_code = board.genesis_code

    for position, entry in enumerate(board.entries, start=1):
        if entry.sequence != position:
            return False

        if entry.state not in STATE_CODES:
            return False

        ballot_hash = compute_ballot_hash(
            entry.ballot,
            entry.district_index,
            board.extended_base_hash,
            params,
        )

        if entry.ballot_hash != ballot_hash:
            return False

        tracking_code = compute_tracking_code(
            previous_code,
            entry.sequence,
            entry.state,
            ballot_hash,
            params,
        )

        if entry.tracking_code != tracking_code:
            return False

        previous_code = tracking_code

    return True


def find_entry(
    board: BulletinBoard,
    tracking_code: int,
) -> BoardEntry | None:
    """
    Cerca una scheda sulla bacheca a partire dal suo codice.

    È il controllo che fa l'elettore: il suo codice deve comparire
    con lo stato CAST.
    """

    for entry in board.entries:
        if entry.tracking_code == tracking_code:
            return entry

    return None


def create_voter_roll(
    voter_districts: dict[str, int],
) -> VoterRoll:
    """
    Crea la lista degli aventi diritto, con la circoscrizione di ognuno.
    """

    for district_index in voter_districts.values():
        if district_index < 0:
            raise ValueError(
                "L'indice della circoscrizione deve essere non negativo."
            )

    return VoterRoll(
        voter_districts=dict(voter_districts),
        voted=frozenset(),
    )


def cast_voter_ballot(
    board: BulletinBoard,
    roll: VoterRoll,
    voter_id: str,
    district_index: int,
    layout: BallotLayout,
    ballot: EncryptedBallot,
    proofs: BallotProofs,
    public_key: int,
    params: GroupParameters,
) -> tuple[BulletinBoard, VoterRoll]:
    """
    Deposita la scheda di un elettore e lo segna come votante.

    Controlliamo che l'elettore abbia diritto al voto, nella sua
    circoscrizione, e che non abbia già votato. Il deposito e la
    registrazione avvengono insieme: se la scheda viene rifiutata,
    l'elettore può ancora votare.
    """

    if voter_id not in roll.voter_districts:
        raise ValueError(f"{voter_id} non è nella lista degli aventi diritto.")

    if roll.voter_districts[voter_id] != district_index:
        raise ValueError(f"{voter_id} vota in un'altra circoscrizione.")

    if voter_id in roll.voted:
        raise ValueError(f"{voter_id} ha già votato.")

    new_board = cast_ballot(
        board=board,
        district_index=district_index,
        layout=layout,
        ballot=ballot,
        proofs=proofs,
        public_key=public_key,
        params=params,
    )

    new_roll = VoterRoll(
        voter_districts=roll.voter_districts,
        voted=roll.voted | {voter_id},
    )

    return new_board, new_roll


def tally_district(
    board: BulletinBoard,
    district_index: int,
    layout: BallotLayout,
    params: GroupParameters,
) -> DistrictTally:
    """
    Calcola i totali cifrati di una circoscrizione.

    Per ogni casella si moltiplicano i cifrati delle schede CAST
    della circoscrizione. Le schede SPOILED non vengono contate.

    È anche il calcolo che il verificatore ripete per il controllo V5.
    """

    ballots = tuple(
        entry.ballot
        for entry in board.entries
        if entry.state == CAST and entry.district_index == district_index
    )

    list_count = layout.list_count
    preference_count = len(layout.preference_metadata)

    for ballot in ballots:
        if len(ballot.list_ciphertexts) != list_count:
            raise ValueError("Una scheda non rispetta il layout.")

        if len(ballot.preference_ciphertexts) != preference_count:
            raise ValueError("Una scheda non rispetta il layout.")

    list_tallies = tuple(
        aggregate_ciphertexts(
            tuple(ballot.list_ciphertexts[index] for ballot in ballots),
            params,
        )
        for index in range(list_count)
    )

    blank_tally = aggregate_ciphertexts(
        tuple(ballot.blank_ciphertext for ballot in ballots),
        params,
    )

    preference_tallies = tuple(
        aggregate_ciphertexts(
            tuple(ballot.preference_ciphertexts[index] for ballot in ballots),
            params,
        )
        for index in range(preference_count)
    )

    return DistrictTally(
        district_index=district_index,
        ballot_count=len(ballots),
        list_tallies=list_tallies,
        blank_tally=blank_tally,
        preference_tallies=preference_tallies,
    )


def decrypt_district_tally(
    tally: DistrictTally,
    secret_shares: dict[int, int],
    present_guardians: tuple[int, ...],
    records: tuple[GuardianRecord, ...],
    quorum: int,
    params: GroupParameters,
    extended_base_hash: int,
) -> DistrictResult:
    """
    Decifra tutti i totali di una circoscrizione con i garanti presenti.

    Ogni garante presente produce una share per ogni totale; ogni share
    viene verificata con la chiave di verifica ricavata dagli impegni
    pubblici prima di essere combinata.

    secret_shares contiene le share dei garanti simulati: in un sistema
    reale ogni garante calcolerebbe la propria share sul suo computer.
    """

    if len(set(present_guardians)) != len(present_guardians):
        raise ValueError("Un garante non può comparire due volte.")

    if len(present_guardians) < quorum:
        raise ValueError("I garanti presenti sono meno del quorum.")

    verification_keys = {
        index: compute_verification_key(index, records, params)
        for index in present_guardians
    }

    totals = []
    all_shares = []

    for ciphertext in tally.all_ciphertexts():
        shares = tuple(
            compute_decryption_share(
                guardian_index=index,
                secret_share=secret_shares[index],
                tally=ciphertext,
                params=params,
                extended_base_hash=extended_base_hash,
            )
            for index in present_guardians
        )

        for share in shares:
            valid = verify_decryption_share(
                share=share,
                verification_key=verification_keys[share.guardian_index],
                tally=ciphertext,
                params=params,
                extended_base_hash=extended_base_hash,
            )

            if not valid:
                raise ValueError(
                    f"La share del garante {share.guardian_index} "
                    "non è valida."
                )

        totals.append(
            decrypt_tally(
                tally=ciphertext,
                shares=shares,
                quorum=quorum,
                params=params,
                max_total=tally.ballot_count,
            )
        )

        all_shares.append(shares)

    list_count = len(tally.list_tallies)

    return DistrictResult(
        district_index=tally.district_index,
        ballot_count=tally.ballot_count,
        list_votes=tuple(totals[:list_count]),
        blank_votes=totals[list_count],
        preference_votes=tuple(totals[list_count + 1:]),
        decryption_shares=tuple(all_shares),
    )
