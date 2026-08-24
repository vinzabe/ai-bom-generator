import json
from pathlib import Path

import pytest

from aibom.cli import EXIT_FINDINGS, EXIT_OK, main

G = str(Path(__file__).parent / "fixtures" / "graph.json")


def test_generate_emits_sbom(capsys):
    assert main(["generate", G]) == EXIT_OK
    doc = json.loads(capsys.readouterr().out)
    assert doc["bomFormat"] == "CycloneDX"


def test_audit_flags_lineage(capsys):
    rc = main(["audit", G])
    assert rc == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "restrictive-license" in out and "undeclared-source" in out


def test_audit_json(capsys):
    main(["audit", G, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert any(item["findings"] for item in data)


def test_audit_single_component(capsys):
    main(["audit", G, "--component", "clean-data", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["component"] == "clean-data"
    assert data[0]["findings"] == []   # clean dataset, no bad lineage


def test_version():
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
