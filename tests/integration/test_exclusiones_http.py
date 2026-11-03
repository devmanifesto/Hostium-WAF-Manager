"""Casos sintéticos: efecto del ctl y conservación de CRS fuera del alcance."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from copy import deepcopy

import pytest
import yaml
from test_http import CRS_DIGEST_FILE, CRS_TAG, ROOT, _docker, _esperar, _exigir_docker, _id_en_esta_uri, _logs, _montaje, _publicar

from hostium_waf.exclusiones_crs import render_exclusiones

CASOS = [
    (5500900, "/firma.php", "firmadatos", "data:image/jpeg;base64,/9j/", 941170),
    (5500900, "/firma.php", "firmadatos", "data:image/jpeg;base64,/9j/", 941130),
    (5500901, "/cuentas.php", "vseleccionados", "1' OR '1'='1", 942100),
    (5500902, "/configgeneral.php", "emailglobalheader", "<script>alert(1)</script>", 941100),
    (5500902, "/configgeneral.php", "emailglobalfooter", "<script>alert(1)</script>", 941100),
    (5500902, "/configgeneral.php", "emailglobalheader", "; /bin/bash -c id", 932100),
    (5500902, "/configgeneral.php", "emailglobalheader", "<!DOCTYPE html><html><body>Correo</body></html>", 921130),
    (5500902, "/configgeneral.php", "emailglobalfooter", "<!DOCTYPE html><html><body>Pie</body></html>", 921130),
    (5500903, "/admin1911/sell/catalog/products/49", "description", "<iframe src=x>", 941160),
    (5500904, "/turnero.php", "datos", 'O:8:"stdClass":0:{}', 933170),
]


@pytest.fixture(scope="module")
def crs_acotado(tmp_path_factory):
    _exigir_docker()
    imagen = f"{CRS_TAG}@{CRS_DIGEST_FILE.read_text(encoding='utf-8').strip()}"
    pull = _docker("pull", imagen, timeout=600)
    assert pull.returncode == 0, pull.stderr[-2000:]
    carpeta = tmp_path_factory.mktemp("crs-acotado")
    catalogo = yaml.safe_load((ROOT / "tests/fixtures/exclusiones-laboratorio.yaml").read_text(encoding="utf-8"))
    servidores = {}
    nombres = []
    try:
        for modo in ("base", "acotado", "produccion"):
            reglas = carpeta / modo
            reglas.mkdir()
            datos = deepcopy(catalogo)
            if modo == "base":
                for entrada in datos["exclusiones"]:
                    entrada.update(habilitada=False, pendiente="Base de laboratorio sin exclusiones")
            texto = render_exclusiones(datos)
            if modo == "produccion":
                texto = (ROOT / "rules/hostium/REQUEST-900-CRS-EXCLUSIONS.conf").read_text(encoding="utf-8")
            # Se incluye deliberadamente DESPUÉS de CRS: fase 1 debe anticipar los controles de fase 2.
            conf = reglas / "RESPONSE-999-HOSTIUM-LAB.conf"
            conf.write_text(texto, encoding="utf-8", newline="\n")
            nombre = f"hostium-waf-tuning-{modo}"
            nombres.append(nombre)
            _docker("rm", "-f", nombre)
            alta = _docker(
                "run", "-d", "--name", nombre, "-p", "127.0.0.1::8080",
                "-e", "BACKEND=http://127.0.0.1:9", "-e", "SERVER_NAME=localhost", "-e", "PORT=8080",
                "-e", "MODSEC_RULE_ENGINE=On", "-e", "MODSEC_AUDIT_ENGINE=On", "-e", "MODSEC_STATUS_ENGINE=Off",
                *_montaje(conf, "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-HOSTIUM-LAB.conf"), imagen,
            )
            assert alta.returncode == 0, alta.stderr[-2000:]
            base = _publicar(nombre, "8080")
            _esperar(base + "/")
            sintaxis = _docker("exec", nombre, "apachectl", "-t")
            assert sintaxis.returncode == 0, sintaxis.stdout + sintaxis.stderr
            servidores[modo] = (base, nombre)
        yield servidores
    finally:
        for nombre in nombres:
            _docker("rm", "-f", nombre)


def pedir(servidor, path, campo, valor, *, host="tuning.example.test", metodo="POST"):
    base, nombre = servidor
    anteriores = set(_logs(nombre).splitlines())
    cuerpo = urllib.parse.urlencode({campo: valor}).encode()
    if metodo == "GET":
        path += ("&" if "?" in path else "?") + cuerpo.decode()
        data = None
    else:
        data = cuerpo
    req = urllib.request.Request(base + path, data=data, method=metodo, headers={"Host": host, "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=15) as respuesta:
            status = respuesta.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    nuevas = "\n".join(linea for linea in _logs(nombre).splitlines() if linea not in anteriores)
    return status, nuevas


@pytest.mark.integration
@pytest.mark.parametrize(("exclusion", "path", "campo", "valor", "objetivo"), CASOS)
def test_exclusion_solo_en_alcance(crs_acotado, exclusion, path, campo, valor, objetivo):
    filas = []
    for modo, ruta, variable, host, metodo, esperado in (
        ("base", path, campo, "tuning.example.test", "POST", True),
        ("acotado", path, campo, "tuning.example.test", "POST", False),
        ("acotado", path, campo, "otro.example.test", "POST", True),
        ("acotado", "/otro.php", campo, "tuning.example.test", "POST", True),
        ("acotado", path, campo, "tuning.example.test", "GET", True),
        ("acotado", path, "otro_campo", "tuning.example.test", "POST", True),
    ):
        status, delta = pedir(crs_acotado[modo], ruta, variable, valor, host=host, metodo=metodo)
        presente = _id_en_esta_uri(delta, objetivo, ruta)
        filas.append({"modo": modo, "ruta": ruta, "metodo": metodo, "status": status, "id": objetivo, "id_en_log": presente, "esperado": esperado})
        assert presente is esperado, (exclusion, filas[-1], delta[-5000:])
        if esperado:
            assert status == 403, filas[-1]
    destino = ROOT / "reports"
    destino.mkdir(exist_ok=True)
    (destino / f"tuning-{exclusion}-{campo}-{objetivo}.json").write_text(json.dumps(filas, indent=2) + "\n", encoding="utf-8")


@pytest.mark.integration
def test_query_y_sufijos_no_activan_exclusion(crs_acotado):
    for ruta, campo, valor, objetivo in (
        ("/checkout?referencia=/admin1911/sell/catalog/products/", "description", "<iframe src=x>", 941160),
        ("/turnero.php.otro", "datos", 'O:8:"stdClass":0:{}', 933170),
    ):
        status, delta = pedir(crs_acotado["acotado"], ruta, campo, valor)
        assert status == 403
        assert _id_en_esta_uri(delta, objetivo, urllib.parse.urlsplit(ruta).path), delta[-5000:]


@pytest.mark.integration
def test_otras_reglas_siguen_protegiendo_el_campo(crs_acotado):
    status, delta = pedir(crs_acotado["acotado"], "/firma.php", "firmadatos", "<script>alert(1)</script>")
    assert status == 403
    assert _id_en_esta_uri(delta, 941100, "/firma.php"), delta[-5000:]


@pytest.mark.integration
def test_whmcs_real_no_bloquea_html_y_conserva_protocolo(crs_acotado):
    ruta = "/admin1911/configgeneral.php"
    for campo in ("emailglobalheader", "emailglobalfooter"):
        status, delta = pedir(crs_acotado["produccion"], ruta + "?action=save", campo,
                              "<!DOCTYPE html><html><head><title>Correo</title></head><body>Plantilla</body></html>",
                              host="clientes.hostium.com")
        assert status == 503, (status, delta[-5000:])  # backend de laboratorio deliberadamente ausente
        for objetivo in (921130, 949110):
            assert not _id_en_esta_uri(delta, objetivo, ruta), delta[-5000:]
    status, delta = pedir(crs_acotado["produccion"], ruta, "emailglobalheader", "\r\nSet-Cookie: hostium_lab=1", host="clientes.hostium.com")
    assert status == 403
    assert _id_en_esta_uri(delta, 921120, ruta), delta[-5000:]
    status, delta = pedir(crs_acotado["produccion"], ruta, "otro_campo", "<html>", host="clientes.hostium.com")
    assert status == 403 and _id_en_esta_uri(delta, 921130, ruta), delta[-5000:]
    status, delta = pedir(crs_acotado["produccion"], ruta, "emailglobalheader", "<html>", host="otro.example.test")
    assert status == 403 and _id_en_esta_uri(delta, 921130, ruta), delta[-5000:]


def _ruta_log(path: str) -> str:
    # Apache deja la URI decodificada en el mensaje de ModSecurity.
    return urllib.parse.unquote(urllib.parse.urlsplit(path).path)


def _get(servidor, path, *, host="moodle.example.test"):
    base, nombre = servidor
    anteriores = set(_logs(nombre).splitlines())
    req = urllib.request.Request(base + path, method="GET", headers={"Host": host})
    try:
        with urllib.request.urlopen(req, timeout=15) as respuesta:
            status = respuesta.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    nuevas = "\n".join(linea for linea in _logs(nombre).splitlines() if linea not in anteriores)
    return status, nuevas


@pytest.mark.integration
def test_pluginfile_no_toca_args_ni_el_nombre_fuera_del_prefijo(crs_acotado):
    # CRS 3.3.10, 933210, coincide con la forma (1) (1) vista en zinc. Un solo (1) no es ese patrón.
    evidencia = "/pluginfile.php/1/course/overviewfiles/portada%20uca%20(1)%20(1)%20(1)%20(1).png"
    status, delta = _get(crs_acotado["produccion"], evidencia)
    assert status == 503, delta[-5000:]
    ruta = _ruta_log(evidencia)
    assert not _id_en_esta_uri(delta, 933210, ruta), delta[-5000:]
    assert not _id_en_esta_uri(delta, 949110, ruta), delta[-5000:]
    corta = "/pluginfile.php/1/course/overviewfiles/portada%20(1).png"
    status, delta = _get(crs_acotado["produccion"], corta)
    assert status == 503, delta[-5000:]
    assert not _id_en_esta_uri(delta, 933210, _ruta_log(corta)), delta[-5000:]
    assert not _id_en_esta_uri(delta, 949110, _ruta_log(corta)), delta[-5000:]
    fuera = "/course/overviewfiles/portada%20uca%20(1)%20(1)%20(1)%20(1).png"
    status, delta = _get(crs_acotado["produccion"], fuera)
    ruta = _ruta_log(fuera)
    assert status == 403, delta[-5000:]
    assert _id_en_esta_uri(delta, 933210, ruta), delta[-5000:]
    assert _id_en_esta_uri(delta, 949110, ruta), delta[-5000:]
    consulta = "/pluginfile.php/1/course/overviewfiles/x.png?x=uca(1)(1)"
    status, delta = _get(crs_acotado["produccion"], consulta)
    ruta = _ruta_log(consulta)
    assert status == 403, delta[-5000:]
    assert _id_en_esta_uri(delta, 933210, ruta), delta[-5000:]
    assert "found within ARGS" in delta
    assert _id_en_esta_uri(delta, 949110, ruta), delta[-5000:]
    sistema = "/files/system(id).png"
    status, delta = _get(crs_acotado["produccion"], sistema)
    assert status == 403, delta[-5000:]
    assert _id_en_esta_uri(delta, 933160, sistema), delta[-5000:]
    assert _id_en_esta_uri(delta, 949110, sistema), delta[-5000:]


def pedir_form(servidor, path, campos, *, host):
    base, nombre = servidor
    anteriores = set(_logs(nombre).splitlines())
    data = urllib.parse.urlencode(campos).encode()
    req = urllib.request.Request(
        base + path,
        data=data,
        method="POST",
        headers={"Host": host, "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as respuesta:
            status = respuesta.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    nuevas = "\n".join(linea for linea in _logs(nombre).splitlines() if linea not in anteriores)
    return status, nuevas


@pytest.mark.integration
def test_editor_wordpress_solo_excerpt_y_content(crs_acotado):
    host = "capacitaciones.municipalidadsalta.gob.ar"
    encabezados = {"excerpt": "<h2>Lavado de manos</h2>", "content": '<h3 class="x">texto</h3>'}
    status, delta = pedir_form(crs_acotado["produccion"], "/wp-admin/post.php", encabezados, host=host)
    assert status == 503, delta[-5000:]
    for regla in (941100, 941160, 949110):
        assert not _id_en_esta_uri(delta, regla, "/wp-admin/post.php"), delta[-5000:]
    # 941160 no mira h2 ni h3. El img es la etiqueta de esa regla; los encabezados van en el mismo cuerpo.
    cuerpo = {"excerpt": "<h2>Lavado de manos</h2>", "content": '<h3 class="x">texto</h3><img src=x>'}
    status, delta = pedir_form(crs_acotado["produccion"], "/wp-admin/post.php", cuerpo, host=host)
    assert status == 503, delta[-5000:]
    for regla in (941100, 941160, 949110):
        assert not _id_en_esta_uri(delta, regla, "/wp-admin/post.php"), delta[-5000:]
    status, delta = pedir_form(crs_acotado["produccion"], "/", cuerpo, host=host)
    assert status == 403, delta[-5000:]
    assert _id_en_esta_uri(delta, 949110, "/"), delta[-5000:]
    status, delta = pedir_form(crs_acotado["produccion"], "/wp-admin/post.php", cuerpo, host="otro.example.test")
    assert status == 403, delta[-5000:]
    assert _id_en_esta_uri(delta, 949110, "/wp-admin/post.php"), delta[-5000:]
    status, delta = pedir_form(
        crs_acotado["produccion"],
        "/wp-admin/post.php",
        {"q": "<script>alert(1)</script>"},
        host=host,
    )
    assert status == 403, delta[-5000:]
    assert _id_en_esta_uri(delta, 949110, "/wp-admin/post.php"), delta[-5000:]


def pedir_multipart(servidor, path, partes, *, host):
    base, nombre = servidor
    anteriores = set(_logs(nombre).splitlines())
    limite = "----hostiumlab"
    trozos = []
    for campo, valor in partes:
        trozos.append(
            f"--{limite}\r\nContent-Disposition: form-data; name=\"{campo}\"\r\n\r\n{valor}\r\n"
        )
    trozos.append(f"--{limite}--\r\n")
    req = urllib.request.Request(
        base + path,
        data="".join(trozos).encode(),
        method="POST",
        headers={"Host": host, "Content-Type": f"multipart/form-data; boundary={limite}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as respuesta:
            status = respuesta.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    nuevas = "\n".join(linea for linea in _logs(nombre).splitlines() if linea not in anteriores)
    return status, nuevas


@pytest.mark.integration
def test_comentario_de_imno_no_sale_del_prefijo(crs_acotado):
    # CRS 3.3.10, 933210. (3364)668153 solo no es el patrón; la frase de evidencia sí, porque hay otro paréntesis.
    evidencia = "GARANTIAS: AVENALI ADOLFO (3364)668153 (padre inq)"
    ruta = "/modules_/imno_/saveData.php"
    status, delta = pedir_form(crs_acotado["produccion"], ruta, {"comentario": evidencia}, host="inmobiliaria.example.test")
    assert status == 503, delta[-5000:]
    assert not _id_en_esta_uri(delta, 933210, ruta), delta[-5000:]
    assert not _id_en_esta_uri(delta, 949110, ruta), delta[-5000:]
    status, delta = pedir_form(crs_acotado["produccion"], "/index.php", {"comentario": evidencia}, host="inmobiliaria.example.test")
    assert status == 403, delta[-5000:]
    assert _id_en_esta_uri(delta, 933210, "/index.php"), delta[-5000:]
    assert _id_en_esta_uri(delta, 949110, "/index.php"), delta[-5000:]


@pytest.mark.integration
def test_partes_del_quiz_no_suman_922130(crs_acotado):
    partes = [(f"q{indice}:", "respuesta") for indice in range(1, 4)]
    ruta = "/mod/quiz/processattempt.php"
    status, delta = pedir_multipart(crs_acotado["produccion"], ruta, partes, host="moodle.example.test")
    assert status == 503, delta[-5000:]
    assert not _id_en_esta_uri(delta, 922130, ruta), delta[-5000:]
    assert not _id_en_esta_uri(delta, 949110, ruta), delta[-5000:]
    status, delta = pedir_multipart(crs_acotado["produccion"], "/index.php", partes, host="moodle.example.test")
    assert status == 403, delta[-5000:]
    assert _id_en_esta_uri(delta, 922130, "/index.php"), delta[-5000:]
    assert _id_en_esta_uri(delta, 949110, "/index.php"), delta[-5000:]


@pytest.mark.integration
def test_foro_solo_quita_message_text(crs_acotado):
    ruta = "/mod/forum/post.php"
    status, delta = pedir_form(
        crs_acotado["produccion"], ruta, {"message[text]": "<h2>hola</h2>"}, host="moodle.example.test",
    )
    assert status == 503, delta[-5000:]
    assert not _id_en_esta_uri(delta, 941100, ruta), delta[-5000:]
    assert not _id_en_esta_uri(delta, 941160, ruta), delta[-5000:]
    # 941160 no mira h2. El img es la etiqueta de esa regla, en el mismo campo exceptuado.
    status, delta = pedir_form(
        crs_acotado["produccion"], ruta, {"message[text]": "<h2>hola</h2><img src=x>"}, host="moodle.example.test",
    )
    assert status == 503, delta[-5000:]
    assert not _id_en_esta_uri(delta, 941100, ruta), delta[-5000:]
    assert not _id_en_esta_uri(delta, 941160, ruta), delta[-5000:]
    status, delta = pedir_form(
        crs_acotado["produccion"], "/index.php", {"message[text]": "<img src=x>"}, host="moodle.example.test",
    )
    assert status == 403, delta[-5000:]
    assert _id_en_esta_uri(delta, 941160, "/index.php"), delta[-5000:]
    status, delta = pedir_form(
        crs_acotado["produccion"], ruta, {"otro": "<script>alert(1)</script>"}, host="moodle.example.test",
    )
    assert status == 403, delta[-5000:]
    assert _id_en_esta_uri(delta, 949110, ruta), delta[-5000:]
