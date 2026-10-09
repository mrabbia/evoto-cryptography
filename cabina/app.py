"""
Applicazione Flask della cabina elettorale dimostrativa.

Le pagine mostrano soltanto lo stato di ElectionSession (sessione.py):
qui non c'è crittografia, solo la lettura dei moduli e la scelta della
pagina da mostrare.

Pagine:
    /                   stato dell'elezione e fasi del protocollo
    /cabina             accesso con il codice dell'elettore
    /cabina/<codice>    scheda della circoscrizione
    /scheda/<token>/... deposito oppure sfida di Benaloh
    /bacheca            bacheca pubblica e ricerca del codice
    /spoglio            chiusura con i garanti presenti
    /risultati          voti, seggi ed eletti
    /verifica           verificatore indipendente e manomissioni
    /registro.json      registro pubblico da scaricare
"""

from pathlib import Path

from flask import (
    Flask,
    Response,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.datastructures import MultiDict

from cabina.sessione import (
    CHECK_DESCRIPTIONS,
    CLOSED,
    TAMPERINGS,
    ElectionSession,
    format_code,
)
from evoto.urna import CAST
from evoto.voto import (
    VoterChoice,
    choice_to_plaintexts,
)


def parse_choice(form: MultiDict) -> VoterChoice:
    """
    Legge la scelta dal modulo della scheda.

    lista vale l'indice della lista oppure "bianca"; preferenze sono
    gli indici delle caselle di preferenza segnate.
    """

    raw_list = form.get("lista", "")

    try:
        preferences = tuple(
            sorted(int(value) for value in form.getlist("preferenze"))
        )
        list_index = int(raw_list) if raw_list not in ("", "bianca") else None
    except ValueError as error:
        raise ValueError("Il modulo della scheda non è valido.") from error

    if raw_list == "bianca":
        if preferences:
            raise ValueError("Una scheda bianca non può avere preferenze.")

        return VoterChoice(list_index=None)

    if list_index is None and not preferences:
        raise ValueError("Segna una lista oppure la scheda bianca.")

    return VoterChoice(
        list_index=list_index,
        preferences=preferences,
    )


def create_app(
    election: ElectionSession,
    registry_path: Path | None = None,
) -> Flask:
    """
    Crea l'applicazione web per una sessione d'elezione.

    Se registry_path è indicato, alla chiusura il registro pubblico
    viene scritto anche in quel file, per lanciare il verificatore
    dal terminale.
    """

    app = Flask(__name__)

    @app.context_processor
    def common_values() -> dict[str, object]:
        def code(value: int, short: bool = False) -> str:
            return format_code(value, election.params, short=short)

        return {
            "election": election,
            "config": election.config,
            "closed": election.phase == CLOSED,
            "code": code,
            "CAST": CAST,
        }

    def error_page(message: str, back: str | None = None, status: int = 400):
        return (
            render_template(
                "errore.html",
                message=message,
                back=back,
            ),
            status,
        )

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            counts=election.counts(),
            board_is_valid=election.board_is_valid(),
        )

    @app.route("/cabina", methods=["GET", "POST"])
    def access():
        error = None

        if request.method == "POST":
            voter_id = request.form.get("codice", "").strip().upper()

            try:
                election.voter_district(voter_id)
            except ValueError as exception:
                error = str(exception)
            else:
                return redirect(url_for("ballot", voter_id=voter_id))

        codes: dict[int, list[str]] = {}

        for voter_id, district in election.available_demo_codes().items():
            codes.setdefault(district, []).append(voter_id)

        return render_template(
            "accesso.html",
            codes=codes,
            error=error,
        )

    @app.route("/cabina/<voter_id>", methods=["GET", "POST"])
    def ballot(voter_id: str):
        try:
            district = election.voter_district(voter_id)
        except ValueError as exception:
            return error_page(str(exception), url_for("access"))

        error = None

        if request.method == "POST":
            try:
                choice = parse_choice(request.form)
                pending = election.prepare(voter_id, choice)
            except ValueError as exception:
                error = str(exception)
            else:
                layout = election.layouts[district]

                return render_template(
                    "conferma.html",
                    pending=pending,
                    district=election.config.districts[district],
                    description=election.describe_choice(
                        district,
                        *choice_to_plaintexts(layout, choice),
                    ),
                    ciphertexts=len(layout.preference_metadata)
                    + layout.list_count
                    + 1,
                    proofs=len(pending.prepared.proofs.r1_proofs)
                    + len(pending.prepared.proofs.r3_proofs)
                    + len(pending.prepared.proofs.r5_proofs)
                    + 2,
                )

        return render_template(
            "scheda.html",
            voter_id=voter_id,
            district=election.config.districts[district],
            layout=election.layouts[district],
            groups=election.ballot_view(district),
            error=error,
        )

    @app.post("/scheda/<token>/deposita")
    def cast(token: str):
        try:
            entry = election.cast(token)
        except ValueError as exception:
            return error_page(str(exception), url_for("access"))

        return render_template(
            "ricevuta.html",
            entry=entry,
            district=election.config.districts[entry.district_index],
        )

    @app.post("/scheda/<token>/sfida")
    def spoil(token: str):
        try:
            voter_id = election.pending(token).voter_id
            report = election.spoil(token)
        except ValueError as exception:
            return error_page(str(exception), url_for("access"))

        return render_template(
            "sfida.html",
            report=report,
            voter_id=voter_id,
        )

    @app.get("/bacheca")
    def board():
        search = request.args.get("codice", "").strip()
        found = election.find_entries(search) if search else ()

        return render_template(
            "bacheca.html",
            entries=election.board.entries,
            counts=election.counts(),
            board_is_valid=election.board_is_valid(),
            search=search,
            found={entry.sequence for entry in found},
        )

    @app.route("/spoglio", methods=["GET", "POST"])
    def closing():
        if election.phase == CLOSED:
            return redirect(url_for("results"))

        error = None
        selected = (1, 3, 5)

        if request.method == "POST":
            try:
                selected = tuple(
                    int(value) for value in request.form.getlist("garanti")
                )
                election.close(selected)
            except ValueError as exception:
                error = str(exception)
            else:
                if registry_path is not None:
                    registry_path.parent.mkdir(parents=True, exist_ok=True)
                    registry_path.write_text(
                        election.registry_json(),
                        encoding="utf-8",
                    )

                return redirect(url_for("results"))

        return render_template(
            "spoglio.html",
            counts=election.counts(),
            selected=selected,
            error=error,
        )

    @app.get("/risultati")
    def results():
        return render_template(
            "risultati.html",
            absent=tuple(
                index
                for index in range(1, election.guardian_count + 1)
                if index not in election.present_guardians
            ),
        )

    @app.route("/verifica", methods=["GET", "POST"])
    def verification():
        report = None
        error = None

        if request.method == "POST" and election.phase == CLOSED:
            tampering = request.form.get("manomissione") or None

            try:
                report = election.verify(tampering)
            except ValueError as exception:
                error = str(exception)

        return render_template(
            "verifica.html",
            report=report,
            error=error,
            tamperings=TAMPERINGS,
            descriptions=CHECK_DESCRIPTIONS,
            registry_path=registry_path,
        )

    @app.get("/registro.json")
    def registry():
        tampering = request.args.get("manomissione") or None

        try:
            content = election.registry_json(tampering)
        except ValueError as exception:
            return error_page(str(exception), url_for("index"))

        name = (
            "registro.json"
            if tampering is None
            else f"registro_manomesso_{tampering}.json"
        )

        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={name}"},
        )

    return app
