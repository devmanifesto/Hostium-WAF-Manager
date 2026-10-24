from __future__ import annotations

import copy
from pathlib import Path

import yaml

from hostium_waf.settings import load_settings, load_yaml
from hostium_waf.validation import validar_exclusiones, validar_manifiesto, validar_repositorio

ROOT = Path(__file__).resolve().parents[2]


def _manifiesto() -> dict:
    return load_yaml(ROOT / "rules" / "manifests" / "rules.yaml")


def test_repositorio_real_valida() -> None:
    settings = load_settings(ROOT)
    data = _manifiesto()
    politica = load_yaml(ROOT / "config" / "policy.example.yaml")
    _, _, issues = validar_repositorio(ROOT, settings, data, politica)
    assert issues == []


def test_id_duplicado() -> None:
    data = _manifiesto()
    data["reglas"][2]["id"] = data["reglas"][1]["id"]
    issues = validar_manifiesto(data, rango_inicio=5500000, rango_fin=5509999)
    assert any(item.codigo == "id_duplicado" for item in issues)


def test_id_fuera_de_rango() -> None:
    data = _manifiesto()
    data["reglas"][1]["id"] = 10
    issues = validar_manifiesto(data, rango_inicio=5500000, rango_fin=5509999)
    assert any(item.codigo == "id_fuera_de_rango" for item in issues)


def test_sin_pruebas() -> None:
    data = _manifiesto()
    data["reglas"][1]["casos_de_prueba_positivos"] = []
    issues = validar_manifiesto(data, rango_inicio=5500000, rango_fin=5509999)
    assert any(item.codigo == "sin_pruebas" for item in issues)


def test_campo_faltante() -> None:
    data = _manifiesto()
    del data["reglas"][1]["motivacion"]
    issues = validar_manifiesto(data, rango_inicio=5500000, rango_fin=5509999)
    assert any(item.codigo == "campo_faltante" for item in issues)


def test_example_no_puede_empaquetarse() -> None:
    data = _manifiesto()
    data["reglas"][0]["incluir_en_paquete"] = True
    data["reglas"][0]["estado"] = "produccion"
    for grupo in ("casos_de_prueba_positivos", "casos_de_prueba_negativos"):
        for caso in data["reglas"][0][grupo]:
            caso["ejecucion"] = "automatizada"
    issues = validar_manifiesto(data, rango_inicio=5500000, rango_fin=5509999)
    assert any(item.codigo == "ejemplo_en_paquete" for item in issues)


def test_exclusion_sin_fecha(tmp_path: Path) -> None:
    del tmp_path
    issues = validar_exclusiones(
        {
            "version_esquema": 1,
            "exclusiones": [
                {
                    "id": "EXC-1",
                    "tipo": "runtime",
                    "regla_objetivo": "941100",
                    "motivo": "ajax",
                    "owner": "equipo",
                    "fecha_revision": "mañana",
                    "alcance": "ruta",
                }
            ],
        }
    )
    assert any(item.codigo == "fecha" for item in issues)


def test_severidad_invalida() -> None:
    data = copy.deepcopy(_manifiesto())
    data["reglas"][1]["severidad"] = "GRAVE"
    issues = validar_manifiesto(data, rango_inicio=5500000, rango_fin=5509999)
    assert any(item.codigo == "severidad" for item in issues)


def test_yaml_del_manifiesto_es_mapa() -> None:
    texto = (ROOT / "rules" / "manifests" / "rules.yaml").read_text(encoding="utf-8")
    assert isinstance(yaml.safe_load(texto), dict)
