from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hostium_waf.cli import app
from hostium_waf.errors import HostiumError
from hostium_waf.eventos import analizar_eventos, comparar_eventos


def linea(regla=942100, uid="tx1", *, bloqueo=False, uri="/checkout?password=secreto") -> str:
    accion = "Access denied with code 403 (phase 2)." if bloqueo else "Warning."
    return (f'ModSecurity: {accion} Pattern match at ARGS:nota. [id "{regla}"] '
            f'[data "valor secreto_cookie tarjeta_123"] [hostname "tienda.example.test"] '
            f'[uri "{uri}"] [unique_id "{uid}"] [ver "OWASP_CRS/3.3.10"]\n')


def test_correlacion_privacidad_y_deduplicacion(tmp_path: Path) -> None:
    log = tmp_path / "error.log"
    log.write_text(linea() * 2 + linea(949110, bloqueo=True) + linea(5500613, "tx2"), encoding="utf-8")
    informe = analizar_eventos(log, servidor="lab")
    assert informe["transacciones"] == 2
    assert informe["con_bloqueo_observado"] == 1
    assert informe["mensajes_unicos"] == 3
    detector = next(f for f in informe["grupos"] if f["regla_id"] == 942100)
    assert detector["con_bloqueo_observado"] == 1
    assert detector["variable"] == "ARGS:nota"
    assert not detector["evaluacion"]
    assert any(f["evaluacion"] for f in informe["grupos"])
    assert any(f["fuente"] == "Hostium" for f in informe["grupos"])
    texto = json.dumps(informe)
    for secreto in ("password", "secreto", "tarjeta_123", "secreto_cookie", "tienda.example.test", "/checkout", "tx1"):
        assert secreto not in texto
    claro = analizar_eventos(log, servidor="lab", incluir_ubicaciones=True)
    assert claro["grupos"][0]["ruta"] == "/checkout"
    assert "password" not in json.dumps(claro)


def test_sin_unique_id_no_mezcla_pedidos(tmp_path: Path) -> None:
    log = tmp_path / "error.log"
    log.write_text(linea().replace(' [unique_id "tx1"]', '') + linea(949110, bloqueo=True), encoding="utf-8")
    informe = analizar_eventos(log, servidor="lab")
    assert informe["sin_correlacion"] == 1
    assert next(f for f in informe["grupos"] if f["regla_id"] == 942100)["con_bloqueo_observado"] == 0


def test_solo_hits_no_son_bloqueos(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    log.write_text(linea(949110).replace("ModSecurity: ", "Message: "), encoding="utf-8")
    assert analizar_eventos(log, servidor="lab")["con_bloqueo_observado"] == 0


def test_entrada_no_soportada_falla(tmp_path: Path) -> None:
    log = tmp_path / "audit.json"
    log.write_text('{"request": {"body": "secret"}}', encoding="utf-8")
    with pytest.raises(HostiumError, match="No se encontraron"):
        analizar_eventos(log, servidor="lab")


def test_fecha_apache_y_linea_excesiva(tmp_path: Path) -> None:
    log = tmp_path / "error.log"
    log.write_text("x" * (1024 * 1024 + 20) + "\n" + "[Mon Nov 02 10:01:02.123456 2026] " + linea(bloqueo=True), encoding="utf-8")
    datos = analizar_eventos(log, servidor="lab")
    assert datos["mensajes_omitidos"] == 1
    assert datos["primera_fecha_local"] == "2026-11-02T10:01:02.123456"
    assert datos["grupos"][0]["codigos_denegacion"] == [403]


def test_comparacion_y_cli(tmp_path: Path) -> None:
    log = tmp_path / "error.log"
    log.write_text(linea(bloqueo=True), encoding="utf-8")
    runner = CliRunner()
    base = tmp_path / "base.json"
    primero = runner.invoke(app, ["logs", "analyze", "--input", str(log), "--server", "lab", "--output", str(base)])
    assert primero.exit_code == 0, primero.output
    log.write_text(linea() + linea(942100, "tx2"), encoding="utf-8")
    segundo = runner.invoke(app, ["logs", "analyze", "--input", str(log), "--server", "lab", "--baseline", str(base), "--json"])
    assert segundo.exit_code == 0, segundo.output
    assert json.loads(segundo.stdout)["comparacion"][0]["diferencia"] == -1
    actual = analizar_eventos(log, servidor="otro")
    with pytest.raises(HostiumError, match="mismo servidor"):
        comparar_eventos(actual, json.loads(base.read_text(encoding="utf-8")))
    protegido = runner.invoke(app, ["logs", "analyze", "--input", str(log), "--server", "lab", "--output", str(log)])
    assert protegido.exit_code == 1
