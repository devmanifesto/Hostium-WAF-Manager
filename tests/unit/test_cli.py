from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from hostium_waf.cli import app
from hostium_waf.fleet import COMANDOS_SOLO_LECTURA, _argv_ssh, auditar
from hostium_waf.inventory import load_inventory
from hostium_waf.models import Server

runner = CliRunner()


def test_version_json() -> None:
    resultado = runner.invoke(app, ["--json", "version"])
    assert resultado.exit_code == 0
    datos = json.loads(resultado.stdout)
    assert datos["version"] == "1.0.0"


def test_doctor_local() -> None:
    resultado = runner.invoke(app, ["doctor", "--local"])
    assert resultado.exit_code == 0, resultado.stdout + resultado.stderr


def test_rules_y_paquete(tmp_path: Path) -> None:
    assert runner.invoke(app, ["rules", "validate"]).exit_code == 0
    assert runner.invoke(app, ["rules", "check-ids"]).exit_code == 0
    construido = runner.invoke(
        app,
        ["package", "build", "--version", "1.1.2", "--engine", "2.9.15", "--output", str(tmp_path)],
    )
    assert construido.exit_code == 0, construido.stdout + construido.stderr
    verificado = runner.invoke(
        app,
        [
            "package",
            "verify",
            "--zip",
            str(tmp_path / "hostium-1.1.2.zip"),
            "--metadata",
            str(tmp_path / "meta_hostium.yaml"),
        ],
    )
    assert verificado.exit_code == 0, verificado.stdout + verificado.stderr
    mostrado = runner.invoke(app, ["metadata", "show", "--file", str(tmp_path / "meta_hostium.yaml")])
    assert mostrado.exit_code == 0
    assert "SHA512" in mostrado.stdout


def test_apply_esta_bloqueado() -> None:
    for comando in (
        ["deploy", "apply", "--ring", "pilot", "--version", "1.0.0", "--approve"],
        ["rollback", "apply", "--ring", "pilot", "--approve"],
        ["publish", "apply"],
        ["updates", "apply", "--approve"],
    ):
        resultado = runner.invoke(app, comando)
        assert resultado.exit_code == 3, comando


def test_publish_plan_sin_artefacto(tmp_path: Path) -> None:
    resultado = runner.invoke(app, ["publish", "plan", "--version", "9.9.9", "--output", str(tmp_path)])
    assert resultado.exit_code == 1


def test_fleet_de_ejemplo_no_abre_ssh(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("ssh no debe ejecutarse")

    monkeypatch.setattr("hostium_waf.fleet.subprocess.run", boom)
    resultado = runner.invoke(app, ["--json", "fleet", "audit", "--backend", "auto"])
    assert resultado.exit_code == 0, resultado.stdout
    datos = json.loads(resultado.stdout)
    assert datos["es_ejemplo"] is True
    assert datos["modifica_servidores"] is False
    assert {item["estado"] for item in datos["servidores"]} == {"omitido_ejemplo"}


def test_fleet_fixture(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("ssh no debe ejecutarse")

    monkeypatch.setattr("hostium_waf.fleet.subprocess.run", boom)
    resultado = runner.invoke(app, ["--json", "fleet", "audit", "--backend", "fixture"])
    assert resultado.exit_code == 0, resultado.stdout
    datos = json.loads(resultado.stdout)
    assert datos["servidores"][0]["fuente"] == "fixture"


def test_argv_ssh_es_lista_fija() -> None:
    server = Server(
        name="lab",
        ssh_host="lab.internal.example.com",
        ssh_user="auditor",
        ring="lab",
        environment="lab",
    )
    argv = _argv_ssh(server, COMANDOS_SOLO_LECTURA["httpd_syntax"])
    assert argv[0] == "ssh"
    assert "StrictHostKeyChecking=yes" in argv
    assert "StrictHostKeyChecking=no" not in argv
    assert argv[-1] == "httpd -t"
    inventario = load_inventory(Path("config/fleet.example.yaml"))
    auditoria = auditar(inventario, dry_run=True)
    assert auditoria.dry_run is True
    assert auditoria.ejecutado is False


def test_json_al_final_del_subcomando() -> None:
    resultado = runner.invoke(app, ["version", "--json"])
    assert resultado.exit_code == 0, resultado.stdout + resultado.stderr
    datos = json.loads(resultado.stdout)
    assert datos["ok"] is True
    assert datos["version"] == "1.0.0"
    anidado = runner.invoke(app, ["rules", "list", "--json"])
    assert anidado.exit_code == 0, anidado.stdout + anidado.stderr
    assert json.loads(anidado.stdout)["ok"] is True


def test_informe(tmp_path: Path) -> None:
    resultado = runner.invoke(app, ["report", "generate", "--format", "markdown", "--output", str(tmp_path / "informe.md")])
    assert resultado.exit_code == 0, resultado.stdout + resultado.stderr
    texto = (tmp_path / "informe.md").read_text(encoding="utf-8")
    assert "no demuestra protección" in texto
