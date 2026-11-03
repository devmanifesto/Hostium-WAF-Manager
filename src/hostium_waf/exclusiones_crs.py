"""Exclusiones runtime acotadas. El ctl solo corre al completar la cadena."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from hostium_waf.crs_vendor import ARCHIVO_EXCLUSIONES, VERSION_RULESET
from hostium_waf.metadata import descripcion_modulo

_VARIABLE = re.compile(r"^ARGS:[A-Za-z_][A-Za-z0-9_]*$")
_OBJETIVO_ID = re.compile(r"^\d+$")
_OBJETIVO_TAG = re.compile(r"^[A-Za-z0-9_-]+$")


def render_exclusiones(data: dict[str, Any]) -> str:
    # Importación diferida: validation también compara este render con el conf.
    from hostium_waf.validation import validar_exclusiones

    issues = validar_exclusiones(data)
    if issues:
        raise ValueError("Catálogo inválido: " + "; ".join(i.formato() for i in issues))
    cabecera = [
        f"# {descripcion_modulo(VERSION_RULESET)}",
        "# Runtime fase 1. Dominio exacto, ruta sin query y método; ctl al final de la cadena.",
        "# Una entrada deshabilitada conserva su id con una condición que nunca coincide.",
        "# No instalar esta candidata para corregir casos pendientes de alcance confirmado.",
        "",
    ]
    bloques = [_bloque(i) for i in sorted(data["exclusiones"], key=lambda i: int(i["id"]))]
    return "\n".join(cabecera) + "\n\n".join(bloques) + "\n"


def escribir_exclusiones(root: Path) -> Path:
    data = yaml.safe_load((root / "config/exclusions.yaml").read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config/exclusions.yaml no es un mapa")
    destino = root / ARCHIVO_EXCLUSIONES
    destino.write_text(render_exclusiones(data), encoding="utf-8", newline="\n")
    return destino


def _bloque(item: dict[str, Any]) -> str:
    identificador = int(item["id"])
    comentario = (
        f"# {identificador}: {item['motivo']} Owner {item['owner']}. "
        f"Revisión {item['fecha_revision']}. Ticket {item['ticket']}."
    )
    acciones = (
        f"id:{identificador},phase:1,pass,nolog,t:none,"
        f"tag:'hostium-crs-exclusion',ver:'hostium/{VERSION_RULESET}'"
    )
    if not item["habilitada"]:
        return (
            f"{comentario}\n# INACTIVA: {item['pendiente']}\n"
            f'SecRule REQUEST_URI "@rx (?!)" "{acciones}"'
        )
    dominios = "|".join(re.escape(d) for d in sorted(item["dominios"]))
    host = rf"(?i)\A(?:{dominios})(?::[0-9]{{1,5}})?\z"
    uri = item["uri"]
    ruta = f"{uri['operador']} {uri['valor']}"
    metodos = "|".join(sorted(item["metodos"]))
    ctls = ",".join(_ctl(c) for c in item["controles"])
    return (
        f"{comentario}\n"
        f'SecRule REQUEST_HEADERS:Host "@rx {host}" \\\n'
        f'    "{acciones},chain"\n'
        f'    SecRule REQUEST_FILENAME "{ruta}" "t:none,chain"\n'
        f'        SecRule REQUEST_METHOD "@rx \\A(?:{metodos})\\z" "t:none,{ctls}"'
    )


def _ctl(control: dict[str, Any]) -> str:
    tipo, objetivo, variable = (str(control[c]) for c in ("tipo", "objetivo", "variable"))
    if not _VARIABLE.fullmatch(variable):
        raise ValueError(f"variable no admitida: {variable}")
    if tipo == "ruleRemoveTargetById" and not _OBJETIVO_ID.fullmatch(objetivo):
        raise ValueError(f"objetivo de id inválido: {objetivo}")
    if tipo == "ruleRemoveTargetByTag" and not _OBJETIVO_TAG.fullmatch(objetivo):
        raise ValueError(f"objetivo de tag inválido: {objetivo}")
    if tipo not in {"ruleRemoveTargetById", "ruleRemoveTargetByTag"}:
        raise ValueError(f"ctl no admitido: {tipo}")
    return f"ctl:{tipo}={objetivo};{variable}"
