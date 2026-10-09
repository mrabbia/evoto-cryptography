"""
Test del notebook didattico notebook/demo_didattica.ipynb.

Il notebook contiene controlli (assert) sui valori della sezione 38
della specifica. Qui le sue celle di codice vengono eseguite in ordine
con il solo interprete Python, senza Jupyter: se una formula della
libreria cambia, il test fallisce.
"""

import json
from pathlib import Path


NOTEBOOK = (
    Path(__file__).resolve().parent.parent
    / "notebook"
    / "demo_didattica.ipynb"
)


def load_notebook() -> dict:
    """
    Legge il notebook come JSON (formato nbformat 4).
    """

    with open(NOTEBOOK, encoding="utf-8") as notebook_file:
        return json.load(notebook_file)


def code_cells(notebook: dict) -> list[str]:
    """
    Restituisce il sorgente delle celle di codice, nell'ordine.
    """

    return [
        "".join(cell["source"])
        for cell in notebook["cells"]
        if cell["cell_type"] == "code"
    ]


def test_notebook_format():
    """
    Il file è un notebook nbformat 4 con kernel Python e contiene
    sia testo sia codice.
    """

    notebook = load_notebook()

    assert notebook["nbformat"] == 4
    assert notebook["metadata"]["kernelspec"]["language"] == "python"

    kinds = {cell["cell_type"] for cell in notebook["cells"]}

    assert kinds == {"markdown", "code"}
    assert len(code_cells(notebook)) >= 20


def test_published_outputs_come_from_a_full_run():
    """
    Le uscite salvate vengono da un'esecuzione completa e in ordine
    (1, 2, 3, ...) e nessuna cella è terminata con un errore.
    """

    notebook = load_notebook()

    cells = [
        cell
        for cell in notebook["cells"]
        if cell["cell_type"] == "code"
    ]

    assert [cell["execution_count"] for cell in cells] == list(
        range(1, len(cells) + 1)
    )

    for cell in cells:
        for output in cell["outputs"]:
            assert output["output_type"] != "error"


def test_notebook_cells_run_without_jupyter(monkeypatch):
    """
    Tutte le celle di codice girano in ordine nello stesso spazio dei
    nomi, partendo dalla cartella del notebook come farebbe Jupyter.
    Gli assert delle celle controllano i valori della specifica.
    """

    monkeypatch.chdir(NOTEBOOK.parent)

    namespace: dict[str, object] = {"__name__": "__notebook__"}

    for index, source in enumerate(code_cells(load_notebook()), start=1):
        exec(
            compile(source, f"cella {index}", "exec"),
            namespace,
        )

    assert namespace["K_joint"] == 530
    assert namespace["Q_bar"] == 744
    assert namespace["verdict"]["overall"]
