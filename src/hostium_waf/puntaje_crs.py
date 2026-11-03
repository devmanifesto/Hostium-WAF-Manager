"""Baja el anomaly score crítico de cinco archivos CRS 3.3.10.

SecRuleUpdateActionById agrega un setvar; no lo reemplaza. Cada directiva
resta el crítico y suma el warning. Neto 3. Una sola no llega al umbral 5.
Dos reglas de esos archivos suman 6 y 949110 sigue cortando.
"""

from __future__ import annotations

import re
from pathlib import Path

from hostium_waf.crs_vendor import ARCHIVO_PUNTAJE, ARCHIVOS_PUNTAJE, DIR_CRS, VERSION_TUNE
from hostium_waf.metadata import descripcion_modulo

_SETVAR = re.compile(
    r"setvar:'(tx\.anomaly_score_pl[1-4])=\+%\{tx\.critical_anomaly_score\}'"
)
_ID = re.compile(r"\bid:(\d+)\b")
_CHAIN = re.compile(r"(?:^|[,\s\"])chain(?:[,\s\"]|$)")


def objetivos_de_puntaje(root: Path) -> list[dict[str, object]]:
    encontrados: list[dict[str, object]] = []
    for nombre in ARCHIVOS_PUNTAJE:
        path = root / DIR_CRS / nombre
        texto = path.read_text(encoding="utf-8")
        for item in _reglas_con_critico(texto):
            item["archivo"] = nombre
            encontrados.append(item)
    encontrados.sort(key=lambda item: (int(item["id"]), int(item["offset"])))
    return encontrados


def render_puntaje(root: Path) -> str:
    lineas = [
        f"# {descripcion_modulo(VERSION_TUNE)}",
        "# Baja a warning el anomaly score crítico de cinco archivos CRS.",
        "# SecRuleUpdateActionById agrega setvar. Cada línea resta el crítico y suma el warning.",
        "# Neto 3. Dos reglas de estos archivos suman 6 y 949110 sigue cortando.",
        "# El resto de los archivos REQUEST no entra. rce_score y lfi_score tampoco.",
        "# Fuente: coreruleset tag v3.3.10. Id y offset coinciden con el tag v3.3.9.",
        "# El RPM ea-modsec2-rules-owasp-crs no se diffé.",
        "# Este archivo es el vendor hostium-tune y se lee después de OWASP3.",
        "# Si entra antes, httpd -t falla. No recargar.",
        "# La SecAction 5500910 es pass y nolog. No cambia el puntaje.",
        "# No se exceptúa un header multipart por URL.",
        "",
        _ancla(),
    ]
    for item in objetivos_de_puntaje(root):
        lineas.append(_directiva(item))
    lineas.append("")
    return "\n".join(lineas)


def escribir_puntaje(root: Path) -> Path:
    destino = root / ARCHIVO_PUNTAJE
    destino.write_text(render_puntaje(root), encoding="utf-8", newline="\n")
    return destino


def _ancla() -> str:
    return (
        "SecAction "
        f"\"id:5500910,phase:1,pass,nolog,t:none,tag:'hostium-crs-score',ver:'hostium/{VERSION_TUNE}'\""
    )


def _directiva(item: dict[str, object]) -> str:
    identificador = int(item["id"])
    offset = int(item["offset"])
    destino = str(identificador) if offset == 0 else f"{identificador}:{offset}"
    acciones: list[str] = []
    if item["chain"]:
        acciones.append("chain")
    variables = item["variables"]
    if not isinstance(variables, list):
        raise ValueError("variables inválidas")
    for variable in variables:
        acciones.append(f"setvar:{variable}=-%{{tx.critical_anomaly_score}}")
        acciones.append(f"setvar:{variable}=+%{{tx.warning_anomaly_score}}")
    return f'SecRuleUpdateActionById {destino} "{",".join(acciones)}"'


def _reglas_con_critico(texto: str) -> list[dict[str, object]]:
    plano = re.sub(r"\\\r?\n", " ", texto)
    partes = re.split(r"(?=^\s*SecRule\b)", plano, flags=re.M)
    actuales: list[dict[str, object]] = []
    current_id: int | None = None
    offset = 0
    espera = False
    for parte in partes:
        if not re.match(r"\s*SecRule\b", parte):
            continue
        limpio = "\n".join(linea for linea in parte.splitlines() if not linea.strip().startswith("#"))
        marca = _ID.search(limpio)
        if marca:
            current_id = int(marca.group(1))
            offset = 0
        elif current_id is not None and espera:
            offset += 1
        else:
            current_id = None
            offset = 0
        tiene_chain = bool(_CHAIN.search(limpio))
        variables: list[str] = []
        for variable in _SETVAR.findall(limpio):
            if variable not in variables:
                variables.append(variable)
        if variables and current_id is not None:
            actuales.append(
                {
                    "id": current_id,
                    "offset": offset,
                    "chain": tiene_chain,
                    "variables": variables,
                }
            )
        espera = tiene_chain
    return actuales
