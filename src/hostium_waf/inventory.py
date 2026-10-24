"""Inventario de flota. Los hosts de ejemplo no son servidores reales."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hostium_waf.errors import HostiumError, Issue
from hostium_waf.models import Inventory, Server
from hostium_waf.security import validar_host, validar_usuario
from hostium_waf.settings import load_yaml
from hostium_waf.validation import ANILLOS

_ENTORNOS = {"production", "staging", "lab", "development"}
_CLAVES = {"name", "ssh_host", "ssh_user", "ring", "environment", "tags", "port"}


def resolver_inventario(root: Path, explicito: Path | None = None) -> Path:
    if explicito is not None:
        return explicito if explicito.is_absolute() else root / explicito
    local = root / "config" / "fleet.yaml"
    if local.is_file():
        return local
    return root / "config" / "fleet.example.yaml"


def validar_inventario(data: Any) -> list[Issue]:
    issues: list[Issue] = []
    if not isinstance(data, dict):
        return [Issue("tipo_invalido", "el inventario debe ser un mapa", "inventario")]
    if data.get("version_esquema") != 1:
        issues.append(Issue("version_esquema", "solo se admite la versión 1", "inventario.version_esquema"))
    if not isinstance(data.get("es_ejemplo"), bool):
        issues.append(Issue("campo_faltante", "es_ejemplo debe ser booleano", "inventario.es_ejemplo"))
    servers = data.get("servers")
    if not isinstance(servers, list):
        return issues + [Issue("campo_faltante", "falta servers", "inventario.servers")]
    nombres: set[str] = set()
    for i, crudo in enumerate(servers):
        issues.extend(_validar_server(crudo, f"inventario.servers[{i}]", nombres))
    return issues


def _validar_server(crudo: Any, ruta: str, nombres: set[str]) -> list[Issue]:
    if not isinstance(crudo, dict):
        return [Issue("tipo_invalido", "el servidor debe ser un mapa", ruta)]
    issues: list[Issue] = []
    for clave in sorted(set(crudo) - _CLAVES):
        issues.append(Issue("campo_desconocido", "campo no admitido en el inventario", f"{ruta}.{clave}"))
    for clave in ("name", "ssh_host", "ssh_user", "ring", "environment"):
        if clave not in crudo:
            issues.append(Issue("campo_faltante", "falta el campo", f"{ruta}.{clave}"))
    nombre = crudo.get("name")
    if isinstance(nombre, str):
        if nombre in nombres:
            issues.append(Issue("inventario", "nombre de servidor repetido", f"{ruta}.name"))
        nombres.add(nombre)
        if validar_host(nombre):
            issues.append(Issue("inventario", "el nombre no es un token seguro", f"{ruta}.name"))
    host = crudo.get("ssh_host")
    if isinstance(host, str):
        problema = validar_host(host)
        if problema:
            issues.append(Issue("inventario", problema, f"{ruta}.ssh_host"))
    usuario = crudo.get("ssh_user")
    if isinstance(usuario, str):
        problema = validar_usuario(usuario)
        if problema:
            issues.append(Issue("inventario", problema, f"{ruta}.ssh_user"))
    if crudo.get("ring") not in ANILLOS:
        issues.append(Issue("anillo", "el anillo debe ser lab, pilot, canary o production", f"{ruta}.ring"))
    if crudo.get("environment") not in _ENTORNOS:
        issues.append(Issue("entorno", "entorno no admitido", f"{ruta}.environment"))
    tags = crudo.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(item, str) for item in tags):
        issues.append(Issue("tipo_invalido", "tags debe ser una lista de textos", f"{ruta}.tags"))
    puerto = crudo.get("port", 22)
    if isinstance(puerto, bool) or not isinstance(puerto, int) or not 1 <= puerto <= 65535:
        issues.append(Issue("tipo_invalido", "port debe ser un entero entre 1 y 65535", f"{ruta}.port"))
    return issues


def load_inventory(path: Path) -> Inventory:
    data = load_yaml(path)
    issues = validar_inventario(data)
    if issues:
        raise HostiumError("El inventario no es válido", issues=issues)
    servers = [
        Server(
            name=item["name"],
            ssh_host=item["ssh_host"],
            ssh_user=item["ssh_user"],
            ring=item["ring"],
            environment=item["environment"],
            tags=list(item.get("tags", [])),
            port=int(item.get("port", 22)),
        )
        for item in data["servers"]
    ]
    return Inventory(servers=servers, origen=str(path), es_ejemplo=bool(data["es_ejemplo"]))
