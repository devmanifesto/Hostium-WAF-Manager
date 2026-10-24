"""Aproximación en Python del módulo PHP upload progress. No sustituye a ModSecurity."""

from __future__ import annotations

import re
from pathlib import Path

from hostium_waf.security import regex_peligrosa

ROOT = Path(__file__).resolve().parents[2]
CONF = ROOT / "rules" / "hostium" / "REQUEST-410-PHP-UPLOAD-PROGRESS.conf"

PASS = {5500600, 5500614, 5500619, 5500623, 5500624, 5500626}
IDS = {
    5500600,
    5500601,
    5500602,
    5500603,
    5500604,
    5500605,
    5500611,
    5500612,
    5500613,
    5500614,
    5500615,
    5500616,
    5500617,
    5500618,
    5500619,
    5500620,
    5500621,
    5500622,
    5500623,
    5500624,
    5500625,
    5500626,
}


class Parte:
    def __init__(self, variables: str, operador: str, acciones: str) -> None:
        self.variables = variables
        self.operador = operador
        self.acciones = acciones


def _desescapar(valor: str) -> str:
    salida: list[str] = []
    indice = 0
    while indice < len(valor):
        if valor[indice] == "\\" and indice + 1 < len(valor) and valor[indice + 1] in {'"', "\\"}:
            salida.append(valor[indice + 1])
            indice += 2
            continue
        salida.append(valor[indice])
        indice += 1
    return "".join(salida)


def parsear(texto: str) -> dict[int, list[Parte]]:
    plano = texto.replace("\\\r\n", "").replace("\\\n", "")
    trozos = re.split(r"(?m)^[ ]*SecRule\s+", plano)[1:]
    actual: int | None = None
    grupos: dict[int, list[Parte]] = {}
    for trozo in trozos:
        coincidencia = re.match(r'(?s)(\S+)\s+"((?:\\.|[^"])*)"\s+"((?:\\.|[^"])*)"', trozo)
        assert coincidencia is not None, trozo[:240]
        acciones = _desescapar(coincidencia.group(3))
        encontrado = re.search(r"\bid:(\d+)\b", acciones)
        if encontrado:
            actual = int(encontrado.group(1))
        assert actual is not None
        grupos.setdefault(actual, []).append(
            Parte(coincidencia.group(1), _desescapar(coincidencia.group(2)), acciones)
        )
    return grupos


REGLAS = parsear(CONF.read_text(encoding="utf-8"))


def _rx(identificador: int, indice: int = 0) -> re.Pattern[str]:
    operador = REGLAS[identificador][indice].operador
    for prefijo in ("!@rx ", "@rx "):
        if operador.startswith(prefijo):
            return re.compile(operador.removeprefix(prefijo))
    raise AssertionError(operador)


def test_ids_acciones_y_version() -> None:
    assert set(REGLAS) == IDS
    activas = "\n".join(
        linea for linea in CONF.read_text(encoding="utf-8").splitlines() if linea.strip() and not linea.strip().startswith("#")
    )
    assert regex_peligrosa(activas) is False
    for identificador, partes in REGLAS.items():
        assert "ver:'hostium/1.1.0'" in partes[0].acciones
        if identificador in PASS:
            assert "pass" in partes[0].acciones
            assert "deny" not in partes[0].acciones
            assert len(partes) == 1
        else:
            assert "deny" in partes[0].acciones
            assert "status:403" in partes[0].acciones
    assert len(REGLAS[5500601]) == 2
    assert "chain" in REGLAS[5500601][0].acciones
    assert "SecRequestBodyAccess On" in activas
    assert "SecResponseBodyAccess On" in activas
    assert "ctl:forceRequestBodyVariable=On" in REGLAS[5500600][0].acciones


def test_5500600_fuerza_el_cuerpo_solo_en_multipart() -> None:
    rx = _rx(5500600)
    assert rx.search("multipart/form-data; boundary=abc")
    assert rx.search("Multipart/Form-Data")
    assert rx.search("application/json") is None
    assert rx.search("multipart/form-data-evil") is None


def test_5500601_chunked_multipart() -> None:
    tipo = _rx(5500601, 0)
    transferencia = _rx(5500601, 1)
    assert tipo.search("multipart/form-data; boundary=x") and transferencia.search("gzip, chunked")
    assert transferencia.search("Chunked")
    assert not (tipo.search("application/json") and transferencia.search("chunked"))
    assert transferencia.search("gzip") is None
    assert transferencia.search("notchunked") is None


def test_5500602_cabeceras_de_parte() -> None:
    rx = _rx(5500602)
    assert rx.search("\r\nX-Pad: a" * 100)
    assert rx.search("\r\nX-Pad: a" * 99) is None
    assert rx.search("\r\nY-Pad: a" * 100) is None


def test_5500603_anidacion() -> None:
    rx = _rx(5500603)

    def nombre(niveles: int, igual: bool) -> str:
        base = "a" + ("[0]" * niveles)
        return base + ("=1" if igual else "")

    assert rx.search(nombre(40, True))
    assert rx.search(nombre(39, True)) is None
    assert rx.search(nombre(40, False))
    assert rx.search('name="' + "campo" + ("[0]" * 40) + '"')
    assert rx.search("nombre=juan") is None


def test_5500604_filename_vacio() -> None:
    rx = _rx(5500604)
    unidad = 'filename=""\r\nContent-Type: text/plain\r\n\r\n--b\r\nContent-Disposition: form-data; '
    assert rx.search(unidad * 50)
    assert rx.search(unidad * 49) is None
    legitimo = 'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n\r\nhola'
    assert rx.search(legitimo) is None


def test_5500605_cantidad_de_archivos() -> None:
    parte = REGLAS[5500605][0]
    assert parte.variables == "&FILES"
    assert parte.operador == "@ge 300"
    umbral = int(parte.operador.removeprefix("@ge "))
    assert 300 >= umbral
    assert not 299 >= umbral


def test_5500611_valor_serializado() -> None:
    rx = _rx(5500611)
    for muestra in ('<?php phpinfo();', "<?=1", 'O:8:"stdClass"', "a:1:{", "s:1:{", "|O:1", "|o:1"):
        assert rx.search(muestra), muestra
    for muestra in ("foto.jpg", "progreso", "O:no", "a:x:{"):
        assert rx.search(muestra) is None, muestra


def test_5500612_filename_con_carga() -> None:
    rx = _rx(5500612)
    assert rx.search('filename="<?php')
    assert rx.search('filename="O:8:"')
    assert rx.search('filename="foto.jpg"') is None
    assert rx.search("<?php") is None


def test_5500613_phpsessid_como_campo() -> None:
    parte = REGLAS[5500613][0]
    assert parte.variables == "ARGS_NAMES"
    assert parte.operador == "@streq PHPSESSID"
    assert "PHPSESSID" == "PHPSESSID"
    assert "phpSESSID" != "PHPSESSID"
    assert "MY_PHPSESSID" != "PHPSESSID"


def test_5500614_etiqueta_php_no_niega() -> None:
    rx = _rx(5500614)
    assert rx.search("hola <?php echo 1;")
    assert rx.search("<?PHP")
    assert rx.search("texto sobre php") is None


def test_5500615_inundacion_de_partes() -> None:
    rx = _rx(5500615)
    linea = "Content-Disposition: form-data;\r\n"
    assert rx.search(linea * 500)
    assert rx.search(linea * 499) is None
    assert rx.search("content-disposition: form-data;\r\n" * 500)
    assert rx.search("Content-Disposition: attachment;\r\n" * 500) is None


def test_5500616_pipe_inicial() -> None:
    rx = _rx(5500616)
    assert rx.search("|O:8:")
    assert rx.search("|o:1")
    assert rx.search("x|O:8:") is None
    assert rx.search("|9:") is None


def test_5500617_set_cookie_largo() -> None:
    rx = _rx(5500617)
    assert rx.search("PHPSESSID=" + ("a" * 200))
    assert rx.search("PHPSESSID=" + ("a" * 199)) is None
    assert rx.search("PHPSESSID=" + ("a" * 32) + "; Path=/") is None


def test_5500618_filename_gigante() -> None:
    rx = _rx(5500618)
    assert rx.search('filename="' + ("a" * 65535))
    assert rx.search('filename="' + ("a" * 65534)) is None


def test_5500619_campo_presente() -> None:
    parte = REGLAS[5500619][0]
    assert parte.operador == "@contains PHP_SESSION_UPLOAD_PROGRESS"
    assert "PHP_SESSION_UPLOAD_PROGRESS" in "antes PHP_SESSION_UPLOAD_PROGRESS despues"
    assert "PHP_SESSION_UPLOAD_PROGRESS" not in "php_session_upload_progress"


def test_5500620_avisos_de_sesion() -> None:
    rx = _rx(5500620)
    cuerpo = (
        "Session ID is too long or contains illegal characters\n"
        "Failed to read session data\n"
        "Failed to write session data"
    )
    assert rx.search(cuerpo)
    assert rx.search("Failed to write session data") is None
    invertido = (
        "Failed to write session data "
        "Session ID is too long or contains illegal characters "
        "Failed to read session data"
    )
    assert rx.search(invertido) is None


def test_5500621_cookie_invalida() -> None:
    parte = REGLAS[5500621][0]
    assert parte.operador.startswith("!@rx ")
    rx = _rx(5500621)

    def invalida(valor: str) -> bool:
        return rx.search(valor) is None

    assert invalida("_")
    assert invalida("abc def")
    assert invalida("abc/def")
    assert invalida("a" * 257)
    assert invalida("")
    assert not invalida("abcXYZ012")
    assert not invalida("a,b-c")
    assert not invalida("a" * 256)


def test_5500622_ruta_de_sesion() -> None:
    rx = _rx(5500622)
    assert rx.search("/tmp/sess_abcdef")
    assert rx.search("/var/lib/php/sessions/sess_abcDEF")
    assert rx.search("/var/www/sess_abc123")
    assert rx.search("/tmp/sess_abc") is None
    assert rx.search("/etc/sess_abcdef") is None
    assert rx.search("/blog/post") is None


def test_5500623_oom() -> None:
    rx = _rx(5500623)
    assert rx.search("Allowed memory size of 128 bytes exhausted")
    assert rx.search("memory exhausted") is None
    assert rx.search("Allowed memory size " + ("x" * 51) + "exhausted") is None


def test_5500624_decode() -> None:
    rx = _rx(5500624)
    assert rx.search("Session object destruction failed")
    assert rx.search("Failed to decode session object")
    assert rx.search("Session started") is None


def test_5500625_webshell() -> None:
    parte = REGLAS[5500625][0]
    assert parte.variables == "REQUEST_URI|ARGS"
    assert parte.operador == "@contains p2s_8512_shell.php"
    assert "p2s_8512_shell.php" in "/p2s_8512_shell.php"
    assert "p2s_8512_shell.php" not in "/shell.php"


def test_5500626_marcador() -> None:
    rx = _rx(5500626)
    assert rx.search("SHELL_ALIVE")
    assert rx.search("PAYLOAD_PERSISTED")
    assert rx.search("hola") is None
