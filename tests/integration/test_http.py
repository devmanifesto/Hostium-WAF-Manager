"""Casos HTTP contra Apache aislado. No sustituyen una prueba en cPanel."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "hostium-waf-apache:local"
CRS_TAG = "owasp/modsecurity-crs:3.3.10-apache-202610180210-lts"
CRS_DIGEST_FILE = ROOT / "docker" / "crs-image.txt"


def _montaje(origen: Path, destino: str, *, solo_lectura: bool = True) -> list[str]:
    modo = f"type=bind,source={origen.resolve()},target={destino}"
    if solo_lectura:
        modo += ",readonly"
    return ["--mount", modo]


def _docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _exigir_docker() -> None:
    if shutil.which("docker") is None or _docker("info", timeout=30).returncode != 0:
        _marcar("omitida")
        pytest.skip("Docker no está en ejecución. La prueba de integración no se ejecutó.")


def _marcar(estado: str) -> None:
    destino = ROOT / "reports"
    destino.mkdir(exist_ok=True)
    (destino / "integracion-estado.txt").write_text(estado + "\n", encoding="utf-8")


def _construir() -> str:
    resultado = _docker(
        "build",
        "-t",
        IMAGE,
        "-f",
        str(ROOT / "docker" / "hostium-only" / "Dockerfile"),
        str(ROOT / "docker" / "hostium-only"),
        timeout=600,
    )
    if resultado.returncode != 0:
        _marcar("omitida")
        pytest.skip("No se pudo construir la imagen local:\n" + resultado.stderr[-2000:])
    version = _docker("run", "--rm", IMAGE, "cat", "/etc/hostium-modsec-version.txt", timeout=60)
    return version.stdout


def _publicar(contenedor: str, puerto_interno: str) -> str:
    mapeo = _docker("port", contenedor, puerto_interno)
    linea = mapeo.stdout.strip().splitlines()[-1]
    host_puerto = linea.rsplit(":", 1)[-1]
    return f"http://127.0.0.1:{host_puerto}"


def _esperar(url: str) -> None:
    fin = time.time() + 40
    while time.time() < fin:
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except urllib.error.HTTPError:
            return
        except Exception:
            time.sleep(0.4)
    logs = _docker("logs", url)
    raise AssertionError(f"Apache no respondió. Último error de espera. Logs:\n{logs.stderr[-2000:]}")


def _logs(contenedor: str) -> str:
    partes = []
    for ruta in ("/var/log/apache2/modsec_audit.log", "/var/log/apache2/error.log"):
        resultado = _docker("exec", contenedor, "cat", ruta)
        partes.append(resultado.stdout)
        partes.append(resultado.stderr)
    logs = _docker("logs", contenedor)
    partes.append(logs.stdout)
    partes.append(logs.stderr)
    return "\n".join(partes)


def _pedir(base: str, caso: dict) -> tuple[int, float]:
    peticion = urllib.request.Request(base + caso["path"], method=caso["metodo"])
    for clave, valor in (caso.get("headers") or {}).items():
        peticion.add_header(clave, valor)
    inicio = time.perf_counter()
    try:
        with urllib.request.urlopen(peticion, timeout=10) as respuesta:
            status = respuesta.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    return status, (time.perf_counter() - inicio) * 1000


def _casos(ejecucion: str) -> list[tuple[int, dict]]:
    data = yaml.safe_load((ROOT / "rules" / "manifests" / "rules.yaml").read_text(encoding="utf-8"))
    encontrados = []
    for regla in data["reglas"]:
        for grupo in ("casos_de_prueba_positivos", "casos_de_prueba_negativos"):
            for caso in regla[grupo]:
                if caso["ejecucion"] == ejecucion:
                    encontrados.append((regla["id"], caso))
    return encontrados


_UNIQUE_ID = re.compile(r'\[unique_id "([^"]+)"\]')


def _id_en_esta_uri(texto: str, regla_id: int, path: str) -> bool:
    """El id cuenta solo si comparte la URI exacta o el unique_id de esa petición.

    Una ventana de líneas vecinas mezcla el 403 anterior con la ruta siguiente.
    """
    identificador = f'[id "{regla_id}"]'
    marca = f'[uri "{path}"]'
    transacciones: set[str] = set()
    for linea in texto.splitlines():
        if marca not in linea:
            continue
        if identificador in linea:
            return True
        encontrado = _UNIQUE_ID.search(linea)
        if encontrado:
            transacciones.add(encontrado.group(1))
    if not transacciones:
        return False
    for linea in texto.splitlines():
        if identificador not in linea:
            continue
        encontrado = _UNIQUE_ID.search(linea)
        if encontrado and encontrado.group(1) in transacciones:
            return True
    return False


def _evaluar(base: str, contenedor: str, ejecucion: str, informe: str) -> list[dict]:
    resultados = []
    fallos = []
    for regla_id, caso in _casos(ejecucion):
        antes = _logs(contenedor)
        status, milisegundos = _pedir(base, caso)
        despues = _logs(contenedor)
        delta = despues[len(antes) :] if despues.startswith(antes) else despues
        presente = _id_en_esta_uri(delta, regla_id, caso["path"])
        ok = status == 403 and presente if caso["dispara"] else not presente
        fila = {
            "id": regla_id,
            "titulo": caso["titulo"],
            "path": caso["path"],
            "status": status,
            "id_en_log": presente,
            "ms": round(milisegundos, 1),
            "ok": ok,
        }
        resultados.append(fila)
        if not ok:
            fallos.append(fila)
    destino = ROOT / "reports" / f"integracion-{informe}.json"
    destino.write_text(json.dumps(resultados, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if fallos:
        raise AssertionError(f"Casos fallidos en {ejecucion}: {fallos}\n{_logs(contenedor)[-3000:]}")
    return resultados


@pytest.fixture(scope="module")
def apache_hostium(tmp_path_factory: pytest.TempPathFactory):
    _exigir_docker()
    version = _construir()
    reglas = tmp_path_factory.mktemp("reglas")
    origen = ROOT / "rules" / "hostium" / "REQUEST-100-SENSITIVE-FILES.conf"
    shutil.copy(origen, reglas / origen.name)
    nombre = "hostium-waf-http"
    _docker("rm", "-f", nombre)
    alta = _docker(
        "run",
        "-d",
        "--name",
        nombre,
        "-p",
        "127.0.0.1::80",
        *_montaje(reglas, "/etc/modsecurity/hostium"),
        IMAGE,
    )
    if alta.returncode != 0:
        pytest.fail(alta.stderr)
    try:
        base = _publicar(nombre, "80")
        _esperar(base + "/")
        sintaxis = _docker("exec", nombre, "apache2ctl", "configtest")
        if sintaxis.returncode != 0:
            pytest.fail(sintaxis.stdout + sintaxis.stderr)
        yield {"base": base, "nombre": nombre, "reglas": reglas, "version": version, "sintaxis": sintaxis.stderr}
    finally:
        _docker("rm", "-f", nombre)


@pytest.mark.integration
def test_reglas_productivas_sin_crs(apache_hostium: dict) -> None:
    _marcar("ejecutada")
    _evaluar(apache_hostium["base"], apache_hostium["nombre"], "automatizada", "sin-crs")
    (ROOT / "reports" / "modsec-version.txt").write_text(apache_hostium["version"], encoding="utf-8")


@pytest.mark.integration
def test_selftest_solo_en_laboratorio(apache_hostium: dict) -> None:
    base = apache_hostium["base"]
    nombre = apache_hostium["nombre"]
    antes = _logs(nombre)
    status, _ = _pedir(base, {"path": "/", "metodo": "GET", "headers": {"X-Hostium-Selftest": "lab-selftest-5500000"}})
    delta = _logs(nombre)[len(antes) :]
    assert "5500000" not in delta
    assert status != 403 or "5500000" not in delta
    reglas = apache_hostium["reglas"]
    shutil.copy(ROOT / "rules" / "hostium" / "REQUEST-000-SELFTEST.conf.example", reglas / "REQUEST-000-SELFTEST.conf")
    recarga = _docker("exec", nombre, "apache2ctl", "graceful")
    if recarga.returncode != 0:
        pytest.fail(recarga.stderr)
    time.sleep(1)
    try:
        _evaluar(base, nombre, "laboratorio", "laboratorio")
    finally:
        (reglas / "REQUEST-000-SELFTEST.conf").unlink(missing_ok=True)


@pytest.mark.integration
def test_coexistencia_con_crs() -> None:
    _exigir_docker()
    imagen = CRS_TAG
    if CRS_DIGEST_FILE.is_file():
        digest = CRS_DIGEST_FILE.read_text(encoding="utf-8").strip()
        if digest.startswith("sha256:"):
            imagen = f"{CRS_TAG}@{digest}"
    pull = _docker("pull", imagen, timeout=600)
    if pull.returncode != 0:
        if os.environ.get("HOSTIUM_REQUIRE_INTEGRATION") == "1":
            pytest.fail(pull.stderr[-2000:])
        _marcar("omitida")
        pytest.skip("No se pudo descargar la imagen CRS. No es un resultado de protección.")
    inspect = _docker("image", "inspect", "--format", "{{index .RepoDigests 0}}", CRS_TAG)
    digest = inspect.stdout.strip()
    if "@" in digest:
        digest = digest.split("@", 1)[1]
    if digest.startswith("sha256:"):
        CRS_DIGEST_FILE.write_text(digest + "\n", encoding="utf-8")
    nombre = "hostium-waf-crs"
    _docker("rm", "-f", nombre)
    conf = ROOT / "rules" / "hostium" / "REQUEST-100-SENSITIVE-FILES.conf"
    alta = _docker(
        "run",
        "-d",
        "--name",
        nombre,
        "-p",
        "127.0.0.1::8080",
        "-e",
        "BACKEND=http://127.0.0.1:9",
        "-e",
        "SERVER_NAME=localhost",
        "-e",
        "PORT=8080",
        "-e",
        "MODSEC_RULE_ENGINE=On",
        "-e",
        "MODSEC_AUDIT_ENGINE=RelevantOnly",
        "-e",
        "MODSEC_STATUS_ENGINE=Off",
        *_montaje(conf, "/etc/modsecurity.d/owasp-crs/rules/REQUEST-100-HOSTIUM-SENSITIVE-FILES.conf"),
        imagen,
        timeout=120,
    )
    if alta.returncode != 0:
        pytest.fail(alta.stderr[-2000:])
    try:
        base = _publicar(nombre, "8080")
        _esperar(base + "/")
        _evaluar(base, nombre, "automatizada", "con-crs")
        version = _docker(
            "exec",
            nombre,
            "sh",
            "-c",
            "apachectl -v 2>&1; echo ---; (dpkg -l 'libapache2-mod-security*' 2>/dev/null || true); (rpm -q ea-apache24-mod_security2 2>/dev/null || true)",
        )
        (ROOT / "reports" / "crs-modsec-version.txt").write_text(version.stdout + version.stderr, encoding="utf-8")
        _marcar("ejecutada")
    finally:
        _docker("rm", "-f", nombre)
