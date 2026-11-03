from __future__ import annotations

import hashlib
import io
import re
from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest
import yaml

from hostium_waf.errors import HostiumError
from hostium_waf.metadata import aplicar_comentario_modulo, descripcion_modulo, validar_metadata
from hostium_waf.packaging import build_package, inspect_zip, verify_package, zip_bytes
from hostium_waf.settings import load_settings

ROOT = Path(__file__).resolve().parents[2]


def _miembros() -> list[tuple[str, bytes]]:
    return [
        ("hostium/", b""),
        ("hostium/a.conf", b"SecRule ARGS \"@rx x\" \"id:1,phase:1,deny\"\n"),
    ]


def test_dos_builds_son_identicos(tmp_path: Path) -> None:
    settings = load_settings(ROOT)
    primero = build_package(ROOT, settings, version="2.1.2", engine="2.9.15", output=tmp_path / "a")
    segundo = build_package(ROOT, settings, version="2.1.2", engine="2.9.15", output=tmp_path / "b")
    assert primero.zip_path.read_bytes() == segundo.zip_path.read_bytes()
    assert primero.md5 == segundo.md5
    assert primero.sha512 == segundo.sha512
    assert verify_package(primero.zip_path, primero.metadata_path) == []


def test_no_declara_motor_no_ensayado(tmp_path: Path) -> None:
    with pytest.raises(HostiumError, match="Motor sin evidencia"):
        build_package(ROOT, load_settings(ROOT), version="2.1.2", engine="3.0.13", output=tmp_path)


def test_zip_solo_contiene_la_regla_productiva(tmp_path: Path) -> None:
    settings = load_settings(ROOT)
    artefacto = build_package(ROOT, settings, version="2.1.2", engine="2.9.15", output=tmp_path)
    with ZipFile(artefacto.zip_path) as zf:
        nombres = zf.namelist()
    assert nombres == [
        "hostium/",
        "hostium/REQUEST-410-PHP-UPLOAD-PROGRESS.conf",
        "hostium/REQUEST-900-CRS-EXCLUSIONS.conf",
    ]
    data = yaml.safe_load(artefacto.metadata_path.read_text(encoding="utf-8"))
    assert isinstance(next(clave for clave in data if clave != "attributes"), str)
    assert data["2.9.15"]["distribution"] == "hostium-2.1.2"
    assert "SHA512" in data["2.9.15"]
    assert "report_url" not in data["attributes"]
    assert data["attributes"]["description"] == "Reglas complementarias de seguridad administradas por Hostium 2.1.2"
    with ZipFile(artefacto.zip_path) as zf:
        textos: list[str] = []
        for nombre in zf.namelist():
            if not nombre.endswith(".conf"):
                continue
            texto = zf.read(nombre).decode("utf-8")
            textos.append(texto)
            assert texto.startswith("# Reglas complementarias de seguridad administradas por Hostium 2.1.2\n")
            assert set(re.findall(r"ver:'hostium/([^']+)'", texto)) == {"2.1.2"}
            assert "id:5500100" not in texto
            assert "id:5500101" not in texto
            assert "SecRuleRemoveById" not in texto
            assert "SecRuleEngine Off" not in texto
            assert "SecRuleUpdateActionById" not in texto
    unido = "\n".join(textos)
    assert '"@rx (?!)"' in unido
    assert "ver:'hostium/2.1.2'" in unido


def test_no_reconstruye_una_distribution_vieja(tmp_path: Path) -> None:
    settings = load_settings(ROOT)
    for version in ("1.0.0", "1.1.2", "2.0.0", "2.1.0", "2.1.1"):
        try:
            build_package(ROOT, settings, version=version, engine="2.9.15", output=tmp_path / version)
        except Exception as exc:
            assert "introducidas en 2.1.2" in str(exc)
        else:
            raise AssertionError(f"{version} no puede empaquetar reglas de 2.1.2")


def test_no_sobrescribe_bytes_distintos(tmp_path: Path) -> None:
    settings = load_settings(ROOT)
    artefacto = build_package(ROOT, settings, version="2.1.2", engine="2.9.15", output=tmp_path)
    artefacto.zip_path.write_bytes(artefacto.zip_path.read_bytes() + b"x")
    try:
        build_package(ROOT, settings, version="2.1.2", engine="2.9.15", output=tmp_path)
    except Exception as exc:
        assert "no se sobrescribe" in str(exc)
    else:
        raise AssertionError("debía rechazar la versión alterada")


def test_verify_detecta_hash_alterado(tmp_path: Path) -> None:
    settings = load_settings(ROOT)
    artefacto = build_package(ROOT, settings, version="2.1.2", engine="2.9.15", output=tmp_path)
    blob = bytearray(artefacto.zip_path.read_bytes())
    blob[-1] ^= 0x01
    alterado = tmp_path / "alterado.zip"
    alterado.write_bytes(blob)
    issues = verify_package(alterado, artefacto.metadata_path)
    assert any(item.codigo in {"hash", "zip"} for item in issues)


def test_rechaza_traversal_symlink_y_raiz(tmp_path: Path) -> None:
    malo = tmp_path / "malo.zip"
    info = ZipInfo("hostium/../../etc/passwd")
    link = ZipInfo("hostium/enlace.conf")
    link.external_attr = (0o120000 << 16)
    link.create_system = 3
    with ZipFile(malo, "w") as zf:
        zf.writestr("otro/archivo.conf", b"x")
        zf.writestr(info, b"x")
        zf.writestr(link, b"destino")
        zf.writestr("hostium/vacio.conf", b"")
        zf.writestr("hostium/doble.conf", b"a")
        zf.writestr("hostium/doble.conf", b"b")
    codigos = {item.codigo for item in inspect_zip(malo)}
    assert "zip_traversal" in codigos
    assert "zip_raiz" in codigos
    assert "zip_symlink" in codigos
    assert "zip_duplicado" in codigos


def test_zip_bytes_determinista() -> None:
    assert zip_bytes(_miembros()) == zip_bytes(_miembros())


def test_comentario_del_modulo_lleva_frase_y_version() -> None:
    assert descripcion_modulo("1.1.0") == "Reglas complementarias de seguridad administradas por Hostium 1.1.0"
    agregado = aplicar_comentario_modulo("# otra cosa\nSecRule\n", "1.2.3")
    assert agregado.startswith("# Reglas complementarias de seguridad administradas por Hostium 1.2.3\n# otra cosa\n")
    reescrito = aplicar_comentario_modulo(
        "# Reglas complementarias de seguridad administradas por Hostium 1.0.0\nSecRule\n",
        "1.1.0",
    )
    assert reescrito.startswith("# Reglas complementarias de seguridad administradas por Hostium 1.1.0\nSecRule\n")


def test_metadata_sin_sha512() -> None:
    issues = validar_metadata(
        {
            "2.9.15": {
                "MD5": hashlib.md5(b"a").hexdigest(),
                "distribution": "hostium-1.0.0",
                "url": "https://waf.hostium.com/stable/hostium-1.0.0.zip",
            },
            "attributes": {
                "name": "Hostium WAF Ruleset",
                "description": "x",
                "vendor_url": "https://hostium.com",
            },
        }
    )
    assert any(item.codigo == "campo_faltante" for item in issues)
    assert any(item.codigo == "comentario" for item in issues)


def test_clave_de_motor_numerica() -> None:
    # 2.9 se leería como float si no estuviera citado. El validador lo rechaza.
    data = yaml.safe_load(io.StringIO("2.9:\n  MD5: 'abc'\nattributes:\n  name: x\n"))
    issues = validar_metadata(data)
    assert any(item.codigo == "motor" for item in issues)
