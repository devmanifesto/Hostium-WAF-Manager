from __future__ import annotations

from pathlib import Path

from hostium_waf.security import buscar_secretos, url_publicacion_valida


def test_rechaza_http_y_credenciales() -> None:
    assert url_publicacion_valida("http://waf.hostium.com/stable/hostium-1.0.0.zip")
    assert url_publicacion_valida("https://user:pass@waf.hostium.com/stable/hostium-1.0.0.zip")
    assert url_publicacion_valida("https://waf.hostium.com/stable/hostium-1.0.0.zip") is None


def test_detecta_secreto_en_texto_armado(tmp_path: Path) -> None:
    clave = "AKIA" + "IOSFODNN7EXAMPLE"
    marca = "-----BEGIN " + "RSA PRIVATE KEY-----"
    campo = "pass" + "word: " + ("s" * 12)
    archivo = tmp_path / "config.yaml"
    archivo.write_text(clave + "\n" + marca + "\n" + campo + "\n", encoding="utf-8")
    issues = buscar_secretos(archivo.read_text(encoding="utf-8"), str(archivo))
    assert {item.codigo for item in issues} == {"secreto"}
    assert len(issues) == 3


def test_el_codigo_no_desactiva_la_comprobacion_de_host() -> None:
    texto = Path("src/hostium_waf/fleet.py").read_text(encoding="utf-8")
    assert "StrictHostKeyChecking=no" not in texto
    assert "StrictHostKeyChecking=yes" in texto
