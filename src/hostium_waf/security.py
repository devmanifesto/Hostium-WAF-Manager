"""Controles de rutas, secretos y URLs. No sustituyen una revisión humana."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from hostium_waf.errors import Issue

_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_AWS_ACCESS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_GITHUB_TOKEN = re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b")
_PASSWORD_FIELD = re.compile(r"(?im)^[ \t]*password\s*:\s*(\S+)\s*$")
_ALLOWED_PASSWORD = {"", "''", '""', "cambiar", "ejemplo", "null", "~", "camBIAR"}
_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,252}[A-Za-z0-9])?$")
_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
_NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_ENGINE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_RESERVED_HOST_SUFFIXES = (".invalid", ".example", ".localhost", ".test")


def es_semver(valor: str) -> bool:
    return bool(_SEMVER.fullmatch(valor))


def es_version_motor(valor: str) -> bool:
    return bool(_ENGINE.fullmatch(valor))


def host_reservado(host: str) -> bool:
    nombre = host.lower().rstrip(".")
    return any(nombre.endswith(sufijo) or nombre == sufijo.lstrip(".") for sufijo in _RESERVED_HOST_SUFFIXES)


def validar_host(host: str) -> str | None:
    if not _HOST.fullmatch(host):
        return "el host solo puede contener letras, dígitos, punto, guion y guion bajo"
    return None


def validar_usuario(usuario: str) -> str | None:
    if not _USER.fullmatch(usuario):
        return "el usuario SSH no es un token seguro"
    return None


def url_publicacion_valida(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "la URL debe usar HTTPS"
    if parsed.username or parsed.password:
        return "la URL no debe incluir credenciales"
    if not parsed.netloc or parsed.netloc.lower() == "localhost":
        return "la URL no tiene un host de publicación válido"
    if not parsed.path.endswith(".zip"):
        return "la URL debe apuntar a un archivo .zip"
    return None


def ruta_zip_insegura(nombre: str) -> str | None:
    if not nombre or nombre.strip() != nombre:
        return "nombre vacío o con espacios extremos"
    if "\x00" in nombre:
        return "nombre con byte nulo"
    if nombre.startswith("/") or nombre.startswith("\\"):
        return "ruta absoluta"
    if re.match(r"^[A-Za-z]:", nombre):
        return "ruta absoluta"
    partes = re.split(r"[\\/]", nombre)
    if any(parte == ".." for parte in partes):
        return "path traversal"
    return None


def regex_peligrosa(patron: str) -> bool:
    return bool(_NESTED_QUANTIFIER.search(patron))


def buscar_secretos(texto: str, origen: str) -> list[Issue]:
    issues: list[Issue] = []
    if _PRIVATE_KEY.search(texto):
        issues.append(Issue("secreto", "aparece un bloque de clave privada", origen))
    if _AWS_ACCESS_KEY.search(texto):
        issues.append(Issue("secreto", "aparece un access key id de AWS", origen))
    if _GITHUB_TOKEN.search(texto):
        issues.append(Issue("secreto", "aparece un token de GitHub", origen))
    for match in _PASSWORD_FIELD.finditer(texto):
        valor = match.group(1).strip().strip("\"'")
        if valor.lower() not in _ALLOWED_PASSWORD and valor.lower() != "cambiar":
            issues.append(Issue("secreto", "hay un campo password con valor", origen))
    return issues


def buscar_secretos_en_arbol(rutas: list[Path]) -> list[Issue]:
    issues: list[Issue] = []
    for ruta in rutas:
        if not ruta.is_file():
            continue
        if ruta.suffix.lower() not in {".yaml", ".yml", ".conf", ".example", ".env", ".txt", ".py", ".sh", ".json"}:
            continue
        try:
            texto = ruta.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            issues.append(Issue("secreto", "el archivo no es UTF-8", str(ruta)))
            continue
        issues.extend(buscar_secretos(texto, str(ruta)))
    return issues
