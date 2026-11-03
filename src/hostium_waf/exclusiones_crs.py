"""Genera REQUEST-900 desde config/exclusions.yaml.

Un campo propio de la aplicación es SecAction de fase 1: el ctl nombra el
campo y corre en cada petición. Un campo genérico es una sola SecRule sobre
REQUEST_URI, sin cadena: el ctl corre solo si esa URI matchea. En los dos
casos el ctl queda en la transacción y alcanza una regla CRS de fase 2.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from hostium_waf.crs_vendor import ARCHIVO_EXCLUSIONES, VERSION_RULESET
from hostium_waf.metadata import descripcion_modulo

_VARIABLE = re.compile(r"^ARGS(?::[A-Za-z_][A-Za-z0-9_]*)?$")
_OBJETIVO_ID = re.compile(r"^\d+$")
_OBJETIVO_TAG = re.compile(r"^[A-Za-z0-9_-]+$")
_LOGIN = re.compile(r"(?:^|/)(?:wp-)?login(?:\.php)?(?:/|$)", re.I)
_ADMIN = re.compile(r"(?:^|/)admin(?:[A-Za-z0-9_-]*)(?:/|$)", re.I)


def render_exclusiones(data: dict[str, Any]) -> str:
    items = data["exclusiones"]
    bloques = [_bloque(item) for item in sorted(items, key=lambda item: int(item["id"]))]
    cabecera = "\n".join(
        [
            f"# {descripcion_modulo(VERSION_RULESET)}",
            "# Exclusiones de objetivo. Fase 1, pass, nolog.",
            "# El campo propio de la aplicación no lleva URI: el ctl nombra ese campo.",
            "# El campo genérico lleva una sola regla de REQUEST_URI, sin cadena.",
            "# El ctl queda en la transacción y alcanza una regla CRS de fase 2.",
            "# No quita la regla. No abre la petición. No exceptúa login ni un admin.",
            "",
        ]
    )
    return cabecera + "\n\n".join(bloques) + "\n"


def escribir_exclusiones(root: Path) -> Path:
    origen = root / "config" / "exclusions.yaml"
    data = yaml.safe_load(origen.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config/exclusions.yaml no es un mapa")
    destino = root / ARCHIVO_EXCLUSIONES
    destino.write_text(render_exclusiones(data), encoding="utf-8", newline="\n")
    return destino


def _bloque(item: dict[str, Any]) -> str:
    identificador = int(item["id"])
    ctls = _lineas_ctl(item["controles"])
    ticket = item.get("ticket")
    nota_ticket = f" Ticket {ticket}." if isinstance(ticket, str) and ticket.strip() else ""
    comentario = (
        f"# {identificador} {item['motivo']} "
        f"Owner {item['owner']}. Revisión {item['fecha_revision']}.{nota_ticket}"
    )
    acciones = (
        f'"id:{identificador},\\\n'
        f"phase:1,\\\n"
        f"pass,\\\n"
        f"nolog,\\\n"
        f"t:none,\\\n"
        f"tag:'hostium-crs-exclusion',\\\n"
        f"ver:'hostium/{VERSION_RULESET}',\\\n"
        f'{ctls}"'
    )
    uri = item.get("uri")
    if isinstance(uri, dict):
        operador = str(uri["operador"])
        valor = str(uri["valor"])
        regla = f'SecRule REQUEST_URI "{operador} {valor}" \\\n    {acciones}'
    else:
        regla = f"SecAction \\\n    {acciones}"
    return f"{comentario}\n{regla}"


def _lineas_ctl(controles: list[dict[str, Any]]) -> str:
    lineas: list[str] = []
    for indice, control in enumerate(controles):
        texto = _ctl(control)
        if indice < len(controles) - 1:
            lineas.append(f"{texto},\\")
        else:
            lineas.append(texto)
    return "\n".join(lineas)


def _ctl(control: dict[str, Any]) -> str:
    tipo = str(control["tipo"])
    objetivo = str(control["objetivo"])
    variable = str(control["variable"])
    if not _VARIABLE.fullmatch(variable):
        raise ValueError(f"variable no admitida: {variable}")
    if tipo == "ruleRemoveTargetById" and not _OBJETIVO_ID.fullmatch(objetivo):
        raise ValueError(f"objetivo de id inválido: {objetivo}")
    if tipo == "ruleRemoveTargetByTag" and not _OBJETIVO_TAG.fullmatch(objetivo):
        raise ValueError(f"objetivo de tag inválido: {objetivo}")
    if tipo not in {"ruleRemoveTargetById", "ruleRemoveTargetByTag"}:
        raise ValueError(f"ctl no admitido: {tipo}")
    return f"ctl:{tipo}={objetivo};{variable}"


def uri_prohibida(valor: str) -> bool:
    if _LOGIN.search(valor):
        return True
    if _ADMIN.search(valor):
        return True
    if "configgeneral" in valor.lower():
        return True
    if "REMOTE_ADDR" in valor.upper():
        return True
    return bool(re.search(r"(?:^|[^0-9])(?:\d{1,3}\.){3}\d{1,3}(?:[^0-9]|$)", valor))
