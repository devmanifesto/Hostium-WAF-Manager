from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from zipfile import ZipFile

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


def test_pluginfile_sin_dominio_y_controles_previos() -> None:
    data = yaml.safe_load((ROOT / "config/exclusions.yaml").read_text(encoding="utf-8"))
    item = next(i for i in data["exclusiones"] if i["id"] == "5500905")
    assert item["dominios"] == []
    assert item["metodos"] == ["GET"]
    assert item["selector"] == "path"
    assert item.get("heredada_estable") is not True
    assert item["uri"] == {"operador": "@beginsWith", "valor": "/pluginfile.php/"}
    assert item["controles"] == [{"tipo": "ruleRemoveTargetById", "objetivo": "933210", "variable": "REQUEST_FILENAME"}]
    assert "fundacionarcor" not in yaml.safe_dump(item)
    texto = render_exclusiones(data)
    assert validar_exclusiones(data) == []
    bloque = next(b for b in texto.split("\n\n") if "id:5500905" in b)
    assert 'SecRule REQUEST_FILENAME "@beginsWith /pluginfile.php/"' in bloque
    assert 'SecRule REQUEST_METHOD "@rx \\A(?:GET)\\z"' in bloque
    assert bloque.count("chain") == 1
    assert "ctl:" not in bloque.split("SecRule REQUEST_METHOD")[0]
    assert bloque.count("ctl:ruleRemoveTargetById=933210;REQUEST_FILENAME") == 1
    assert "ARGS" not in bloque
    assert "REQUEST_HEADERS" not in bloque
    assert "allow" not in bloque
    prefijo = "/pluginfile.php/"
    dentro = "/pluginfile.php/1/course/overviewfiles/portada (1).png"
    fuera = "/course/overviewfiles/portada (1).png"
    consulta = "/pluginfile.php/1/course/overviewfiles/x.png"
    assert dentro.startswith(prefijo)
    assert not fuera.startswith(prefijo)
    assert consulta.startswith(prefijo)
    assert not "/files/system(.png".startswith(prefijo)
    with ZipFile(ROOT / "publish/stable/hostium-2.1.3.zip") as zf:
        viejo = zf.read("hostium/REQUEST-900-CRS-EXCLUSIONS.conf").decode("utf-8")
    for identificador in range(5500900, 5500905):
        assert re.findall(r"ctl:[^\s,\"\\]+", _bloque_id(viejo, identificador)) == re.findall(
            r"ctl:[^\s,\"\\]+", _bloque_id(texto, identificador),
        )


def _bloque_id(texto: str, identificador: int) -> str:
    return next(b for b in re.split(r"\n\s*\n", texto) if re.search(rf"\bid:{identificador}\b", b))


def test_no_excluir_coleccion_entera_y_no_adivinar_dominio() -> None:
    data = catalogo()
    data["exclusiones"][0]["controles"][0]["variable"] = "ARGS"
    assert any(i.codigo == "exclusion" for i in validar_exclusiones(data))
    data = yaml.safe_load((ROOT / "config/exclusions.yaml").read_text(encoding="utf-8"))
    assert sum(i.get("heredada_estable", False) for i in data["exclusiones"]) == 4
    assert next(i for i in data["exclusiones"] if i["id"] == "5500902")["dominios"] == ["clientes.hostium.com"]


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


@pytest.mark.parametrize("cambio", ["control", "id", "dominio", "metodo"])
def test_compatibilidad_no_permite_ampliar_estable(cambio) -> None:
    data = yaml.safe_load((ROOT / "config/exclusions.yaml").read_text(encoding="utf-8"))
    entrada = data["exclusiones"][0]
    if cambio == "control":
        entrada["controles"][0]["objetivo"] = "941100"
    elif cambio == "id":
        entrada["id"] = "5500999"
    elif cambio == "dominio":
        entrada["dominios"] = ["otro.example.test"]
    else:
        entrada["metodos"] = ["POST"]
    assert validar_exclusiones(data)
    with pytest.raises(ValueError):
        render_exclusiones(data)
