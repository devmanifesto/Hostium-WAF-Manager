"""El informe local resume la evidencia del contenedor sin tratarla como cPanel."""

from __future__ import annotations

import json
from pathlib import Path

from hostium_waf.reporting import cargar_evidencia_integracion, generar_informe

ROOT = Path(__file__).resolve().parents[2]


def test_evidencia_json_y_resumen(tmp_path: Path) -> None:
    (tmp_path / "integracion-estado.txt").write_text("ejecutada\n", encoding="utf-8")
    (tmp_path / "integracion-sin-crs.json").write_text(
        json.dumps([{"id": 5500100, "path": "/.env", "status": 403, "id_en_log": True, "ok": True, "ms": 2.0}]),
        encoding="utf-8",
    )
    evidencia = cargar_evidencia_integracion(tmp_path)
    assert evidencia is not None
    assert evidencia["estado"] == "ejecutada"
    assert evidencia["perfiles"]["sin-crs"]["aprobados"] == 1
    assert "cPanel" in evidencia["advertencia"]
    texto = generar_informe(formato="markdown", validacion=[], artefacto=None, auditoria=None, integracion=evidencia)
    assert "no demuestra protección" in texto
    assert "Perfil sin-crs: 1/1" in texto


def test_evidencia_acepta_el_yaml_viejo(tmp_path: Path) -> None:
    (tmp_path / "integracion-laboratorio.json").write_text(
        "- id: 5500000\n  ok: true\n  path: /\n  status: 403\n",
        encoding="utf-8",
    )
    evidencia = cargar_evidencia_integracion(tmp_path)
    assert evidencia is not None
    assert evidencia["perfiles"]["laboratorio"]["total"] == 1


def test_scripts_y_reglas_usan_lf() -> None:
    archivos = list((ROOT / "scripts").glob("*.sh"))
    archivos.append(ROOT / "rules" / "hostium" / "REQUEST-100-SENSITIVE-FILES.conf")
    archivos.append(ROOT / "rules" / "hostium" / "REQUEST-410-PHP-UPLOAD-PROGRESS.conf")
    archivos.append(ROOT / "rules" / "hostium" / "REQUEST-411-PHP-UPLOAD-PROGRESS-RESPONSE.conf.example")
    for ruta in archivos:
        datos = ruta.read_bytes()
        assert b"\r\n" not in datos, ruta.name
        assert datos.endswith(b"\n"), ruta.name
