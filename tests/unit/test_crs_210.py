"""Aproximación de las URI y del puntaje de hostium-2.1.0. No es el motor ModSecurity."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from hostium_waf.packaging import Artefacto, build_package, build_tune_package, copiar_a_stable, copiar_tune_a_stable
from hostium_waf.settings import load_settings
from hostium_waf.validation import _revisar_conf_empaquetable, _revisar_conf_puntaje

ROOT = Path(__file__).resolve().parents[2]
EXCLUSIONES = ROOT / "rules" / "hostium" / "REQUEST-900-CRS-EXCLUSIONS.conf"
PUNTAJE = ROOT / "rules" / "hostium" / "REQUEST-910-CRS-ANOMALY-SCORE.conf"
UPLOAD = ROOT / "rules" / "hostium" / "REQUEST-410-PHP-UPLOAD-PROGRESS.conf"
SHA_200 = "d9644a8f5f8d83506a16d4beab39a27ef62b5a30f7cbccc07d3e29408e140c01"
_FAMILIAS = ("920", "921", "930", "931", "933", "941", "942", "943")


def _reglas(texto: str) -> dict[int, tuple[str, str, str]]:
    plano = re.sub(r"\\\s*\n", " ", texto)
    encontradas: dict[int, tuple[str, str, str]] = {}
    for bloque in re.findall(r"(?:SecRule|SecAction)\b.*?(?=(?:SecRule|SecAction)\b|$)", plano, flags=re.S):
        marca = re.search(r"\bid:(\d+)\b", bloque)
        assert marca is not None
        if bloque.lstrip().startswith("SecAction"):
            encontradas[int(marca.group(1))] = ("SecAction", "", "")
            continue
        operador = re.search(r'REQUEST_URI\s+"(@beginsWith|@contains|@rx)\s+([^"]+)"', bloque)
        assert operador is not None
        encontradas[int(marca.group(1))] = ("SecRule", operador.group(1), operador.group(2))
    return encontradas


def _coincide(operador: str, valor: str, path: str) -> bool:
    if operador == "@beginsWith":
        return path.startswith(valor)
    if operador == "@contains":
        return valor in path
    return re.search(valor, path) is not None


def test_selectores_de_las_cinco_exclusiones() -> None:
    texto = EXCLUSIONES.read_text(encoding="utf-8")
    reglas = _reglas(texto)
    assert set(reglas) == {5500900, 5500901, 5500902, 5500903, 5500904}
    for identificador in (5500900, 5500901, 5500902):
        assert reglas[identificador][0] == "SecAction"
    assert "ctl:ruleRemoveTargetById=941130;ARGS:firmadatos" in texto
    assert "ctl:ruleRemoveTargetById=941170;ARGS:firmadatos" in texto
    assert "ctl:ruleRemoveTargetById=942100;ARGS:vseleccionados" in texto
    assert "ctl:ruleRemoveTargetByTag=attack-xss;ARGS:emailglobalheader" in texto
    assert "ctl:ruleRemoveTargetByTag=attack-rce;ARGS:emailglobalfooter" in texto
    assert "941100" not in texto
    assert "922130" not in texto
    assert "chain" not in texto
    catalogo, valor = reglas[5500903][1:]
    assert catalogo == "@contains"
    assert _coincide(catalogo, valor, "/admin1911/sell/catalog/products/49")
    assert _coincide(catalogo, valor, "/otro/sell/catalog/products/1")
    assert not _coincide(catalogo, valor, "/admin1911/sell/orders/")
    assert not _coincide(catalogo, valor, "/login")
    turnero, ruta = reglas[5500904][1:]
    assert _coincide(turnero, ruta, "/aplicacion_customs/marketingdirecto/recibepostturnero.php")
    assert not _coincide(turnero, ruta, "/aplicacion_customs/marketingdirecto/index.php")
    assert not _coincide(turnero, ruta, "/login")


def test_el_conf_de_exclusion_no_abre_ni_quita_reglas() -> None:
    texto = EXCLUSIONES.read_text(encoding="utf-8")
    assert "REMOTE_ADDR" not in texto
    assert "allow" not in texto
    assert "SecRuleRemoveById" not in texto
    assert _revisar_conf_empaquetable(texto, EXCLUSIONES.relative_to(ROOT).as_posix(), []) == []
    con_quita = texto + "\nSecRuleRemoveById 941100\n"
    issues = _revisar_conf_empaquetable(con_quita, "rules/hostium/REQUEST-900-CRS-EXCLUSIONS.conf", [])
    assert any(item.codigo == "regla_prohibida" for item in issues)
    con_allow = texto + '\nSecRule ARGS "@rx x" "id:5500900,phase:1,allow,nolog"\n'
    issues = _revisar_conf_empaquetable(con_allow, "rules/hostium/REQUEST-900-CRS-EXCLUSIONS.conf", [])
    assert any("allow" in item.mensaje for item in issues)
    starter = (
        'SecRule REQUEST_URI "@beginsWith /app" \\\n'
        '    "id:5500900,\\\nphase:1,\\\npass,\\\nnolog,\\\nchain,\\\n'
        'ctl:ruleRemoveTargetById=941100;ARGS"\n'
    )
    issues = _revisar_conf_empaquetable(starter, "rules/hostium/REQUEST-900-CRS-EXCLUSIONS.conf", [])
    assert any("no usa cadena" in item.mensaje for item in issues)


def test_el_ctl_de_objetivo_no_entra_en_410() -> None:
    texto = UPLOAD.read_text(encoding="utf-8") + "\nctl:ruleRemoveTargetById=941100;ARGS\n"
    issues = _revisar_conf_empaquetable(texto, "rules/hostium/REQUEST-410-PHP-UPLOAD-PROGRESS.conf", [])
    assert any("REQUEST-900" in item.mensaje for item in issues)


def test_el_puntaje_baja_solo_cinco_archivos() -> None:
    texto = PUNTAJE.read_text(encoding="utf-8")
    assert 'SecRuleUpdateActionById 922130 "' in texto
    assert "SecRuleUpdateActionById 922100:1 " in texto
    assert "SecRuleUpdateActionById 932200:2 " in texto
    assert "-%{tx.critical_anomaly_score}" in texto
    assert "+%{tx.warning_anomaly_score}" in texto
    assert "SecAction \"id:5500910,phase:1,pass,nolog" in texto
    assert not re.search(r"\bSecRule\b", texto)
    for familia in _FAMILIAS:
        assert not re.search(rf"\b{familia}\d+\b", texto)
    assert _revisar_conf_puntaje(texto, "rules/hostium/REQUEST-910-CRS-ANOMALY-SCORE.conf") == []
    sola = 'SecRuleUpdateActionById 922130 "setvar:tx.anomaly_score_pl1=+%{tx.warning_anomaly_score}"\n'
    issues = _revisar_conf_puntaje(sola, "rules/hostium/REQUEST-910-CRS-ANOMALY-SCORE.conf")
    assert any(item.codigo == "regla_prohibida" for item in issues)


def test_el_zip_200_no_cambia_de_bytes(tmp_path: Path) -> None:
    publicado = ROOT / "publish" / "stable" / "hostium-2.0.0.zip"
    antes = hashlib.sha256(publicado.read_bytes()).hexdigest()
    assert antes == SHA_200
    settings = load_settings(ROOT)
    build_package(ROOT, settings, version="2.1.0", engine="2.9.15", output=tmp_path)
    despues = hashlib.sha256(publicado.read_bytes()).hexdigest()
    assert despues == antes


def test_copiar_a_stable_pisa_solo_la_metadata(tmp_path: Path) -> None:
    settings = load_settings(ROOT)
    artefacto = build_package(ROOT, settings, version="2.1.0", engine="2.9.15", output=tmp_path / "dist")
    estable = tmp_path / "publish" / "stable"
    estable.mkdir(parents=True)
    viejo = b"zip-2.0.0"
    (estable / "hostium-2.0.0.zip").write_bytes(viejo)
    (estable / "meta_hostium.yaml").write_text("distribution: hostium-2.0.0\n", encoding="utf-8")
    copiado = Artefacto(
        version=artefacto.version,
        engine=artefacto.engine,
        canal=artefacto.canal,
        distribution=artefacto.distribution,
        zip_path=artefacto.zip_path,
        metadata_path=artefacto.metadata_path,
        md5=artefacto.md5,
        sha512=artefacto.sha512,
        sha256=artefacto.sha256,
        archivos=artefacto.archivos,
        url=artefacto.url,
    )
    copiar_a_stable(tmp_path, copiado)
    assert (estable / "hostium-2.0.0.zip").read_bytes() == viejo
    assert (estable / "hostium-2.1.0.zip").read_bytes() == artefacto.zip_path.read_bytes()
    assert "hostium-2.1.0" in (estable / "meta_hostium.yaml").read_text(encoding="utf-8")


def test_tune_no_pisa_el_zip_de_hostium(tmp_path: Path) -> None:
    settings = load_settings(ROOT)
    tune = build_tune_package(ROOT, settings, engine="2.9.15", output=tmp_path / "tune")
    assert tune.distribution == "hostium-tune-2.1.1"
    from zipfile import ZipFile

    with ZipFile(tune.zip_path) as zf:
        assert zf.namelist() == [
            "hostium-tune/",
            "hostium-tune/REQUEST-910-CRS-ANOMALY-SCORE.conf",
        ]
        texto = zf.read("hostium-tune/REQUEST-910-CRS-ANOMALY-SCORE.conf").decode("utf-8")
    assert "SecAction \"id:5500910,phase:1,pass,nolog" in texto
    assert "SecRuleUpdateActionById 922130 " in texto
    assert "MULTIPART_PART_HEADERS" not in texto
    estable = tmp_path / "publish" / "stable"
    estable.mkdir(parents=True)
    (estable / "hostium-2.0.0.zip").write_bytes(b"zip-2.0.0")
    (estable / "meta_hostium.yaml").write_text("distribution: hostium-2.0.0\n", encoding="utf-8")
    copiar_tune_a_stable(tmp_path, tune)
    assert (estable / "hostium-2.0.0.zip").read_bytes() == b"zip-2.0.0"
    assert (estable / "meta_hostium.yaml").read_text(encoding="utf-8") == "distribution: hostium-2.0.0\n"
    assert "hostium-tune-2.1.1" in (estable / "meta_hostium-tune.yaml").read_text(encoding="utf-8")
