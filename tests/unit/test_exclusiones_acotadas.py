from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from hostium_waf.errors import HostiumError
from hostium_waf.exclusiones_crs import render_exclusiones
from hostium_waf.puntaje_crs import comprobar_fuente_instalada
from hostium_waf.validation import _revisar_conf_empaquetable, validar_exclusiones

ROOT = Path(__file__).resolve().parents[2]


def catalogo() -> dict:
    return yaml.safe_load((ROOT / "tests/fixtures/exclusiones-laboratorio.yaml").read_text(encoding="utf-8"))


def test_cadena_y_ctl_final() -> None:
    data = catalogo()
    texto = render_exclusiones(data)
    assert validar_exclusiones(data) == []
    assert _revisar_conf_empaquetable(texto, "rules/hostium/REQUEST-900-CRS-EXCLUSIONS.conf", []) == []
    assert "SecAction" not in texto
    assert "REQUEST_URI" not in texto
    assert texto.count("SecRule REQUEST_HEADERS:Host") == 5
    assert texto.count("SecRule REQUEST_FILENAME") == 5
    assert texto.count("SecRule REQUEST_METHOD") == 5
    assert "@streq /turnero.php" in texto
    assert "@beginsWith /admin1911/sell/catalog/products/" in texto
    for bloque in texto.split("SecRule REQUEST_HEADERS:Host")[1:]:
        assert "ctl:" not in bloque.split("SecRule REQUEST_METHOD")[0]
        assert "ctl:" in bloque.split("SecRule REQUEST_METHOD")[1]


@pytest.mark.parametrize(("clave", "valor"), [
    ("dominios", []), ("dominios", ["*.example.test"]), ("dominios", ["example.test\nSecAction"]),
    ("metodos", []), ("metodos", [".*"]), ("fecha_revision", "2000-01-01"),
    ("habilitada", "true"), ("ticket", ""), ("owner", "equipo\nSecAction"), ("id", "no-numero"),
    ("uri", {"operador": "@contains", "valor": "/sell/catalog/"}),
    ("uri", {"operador": "@beginsWith", "valor": "/turnero.php"}),
    ("uri", {"operador": "@streq", "valor": "/turnero.php?dato=x"}),
    ("uri", {"operador": "@streq", "valor": "/a/../turnero.php"}),
])
def test_rechaza_alcance_inseguro(clave, valor) -> None:
    data = catalogo()
    data["exclusiones"][0][clave] = valor
    assert validar_exclusiones(data)
    with pytest.raises(ValueError):
        render_exclusiones(data)


def test_no_excluir_coleccion_entera_y_no_adivinar_dominio() -> None:
    data = catalogo()
    data["exclusiones"][0]["controles"][0]["variable"] = "ARGS"
    assert any(i.codigo == "exclusion" for i in validar_exclusiones(data))
    data = yaml.safe_load((ROOT / "config/exclusions.yaml").read_text(encoding="utf-8"))
    assert all(not i["habilitada"] and not i["dominios"] for i in data["exclusiones"])
    assert "ctl:" not in render_exclusiones(data)


def test_fecha_vencida_no_se_puede_regenerar_si_activa() -> None:
    data = catalogo()
    data["exclusiones"][0]["fecha_revision"] = "2000-01-01"
    assert any(i.codigo == "exclusion_vencida" for i in validar_exclusiones(data))
    copia = deepcopy(data)
    copia["exclusiones"][0].update(habilitada=False, pendiente="Revisión pendiente")
    assert validar_exclusiones(copia) == []


def test_puntaje_rechaza_crs_distinto(tmp_path) -> None:
    comprobar_fuente_instalada(ROOT, ROOT / "third_party/coreruleset-v3.3.10/rules")
    (tmp_path / "REQUEST-911-METHOD-ENFORCEMENT.conf").write_text("# fuente diferente\n", encoding="utf-8")
    with pytest.raises(HostiumError, match="CRS difiere"):
        comprobar_fuente_instalada(ROOT, tmp_path)
