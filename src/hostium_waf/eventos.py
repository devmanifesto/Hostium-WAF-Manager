"""Diagnóstico local de mensajes ModSecurity v2, sin copiar el contenido HTTP."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from hostium_waf.errors import HostiumError

_CAMPO = re.compile(r'\[(id|hostname|uri|unique_id|ver) "((?:[^"\\]|\\.)*)"\]')
_VARIABLE = re.compile(r"\b(?:at |within )((?:ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_HEADERS)(?::[A-Za-z_][A-Za-z0-9_.-]{0,80})?)(?:[ .:]|$)")
_DENEGADA = re.compile(r"Access denied with code ([1-5][0-9]{2})\b", re.I)
_EVALUADORES = {949110, 959100, 980130, 980140}
_FECHA = re.compile(r"^\[([A-Za-z]{3} [A-Za-z]{3} [ 0-9][0-9] [0-9:.]+ [0-9]{4})\]")
_LIMITE_LINEA = 1024 * 1024


def _alias(valor: str) -> str:
    return "sha256:" + hashlib.sha256(valor.encode()).hexdigest()[:24]


def analizar_eventos(path: Path, *, servidor: str, incluir_ubicaciones: bool = False) -> dict[str, Any]:
    """Acepta error log Apache y líneas Message: de la sección H del audit log.

    Agrupa por unique_id, sin deducir que un hit sea un bloqueo o un falso positivo.
    Sin unique_id cada mensaje queda independiente, marcado sin correlación.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", servidor):
        raise HostiumError("--server requiere un alias sin espacios ni datos sensibles")
    transacciones: dict[str, dict[str, Any]] = {}
    vistas: set[tuple[object, ...]] = set()
    omitidas = 0
    mensajes = 0
    fechas: list[str] = []
    try:
        with path.open(encoding="utf-8", errors="replace") as archivo:
            numero = 0
            while linea := archivo.readline(_LIMITE_LINEA + 1):
                numero += 1
                if len(linea) > _LIMITE_LINEA:
                    while linea and not linea.endswith("\n"):
                        linea = archivo.readline(_LIMITE_LINEA + 1)
                    omitidas += 1
                    continue
                if "ModSecurity:" not in linea and not linea.startswith("Message: "):
                    continue
                campos = dict(_CAMPO.findall(linea))
                if not re.fullmatch(r"[0-9]{1,9}", campos.get("id", "")):
                    omitidas += 1
                    continue
                marca_fecha = _FECHA.search(linea)
                if marca_fecha:
                    for formato in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
                        try:
                            fechas.append(datetime.strptime(marca_fecha.group(1), formato).isoformat())
                            break
                        except ValueError:
                            continue
                identificador = int(campos["id"])
                uid = campos.get("unique_id")
                clave = uid or f"sin-correlacion-{numero}"
                tx = transacciones.setdefault(clave, {"ubicaciones": set(), "hits": set(), "bloqueada": False, "status": set(), "correlacionada": bool(uid)})
                dominio = campos.get("hostname", "desconocido").lower()
                try:
                    ruta = urlsplit(campos.get("uri", "/")).path or "/"
                except ValueError:
                    ruta = "desconocida"
                # Aun con opt-in nunca se devuelven query, controles de terminal o HTML activo.
                if incluir_ubicaciones:
                    dominio = re.sub(r"[^A-Za-z0-9_.:-]", "_", dominio)[:253]
                    ruta = re.sub(r"[^A-Za-z0-9_./%:@+-]", "_", ruta)[:1024]
                else:
                    dominio, ruta = _alias(dominio), _alias(ruta)
                variable = _VARIABLE.search(linea)
                objetivo = variable.group(1).rstrip(".") if variable else "desconocida"
                version = campos.get("ver", "desconocida")
                if not re.fullmatch(r"[A-Za-z0-9_./-]{1,80}", version):
                    version = "desconocida"
                denegada = _DENEGADA.search(linea)
                if denegada:
                    tx["bloqueada"] = True
                    tx["status"].add(int(denegada.group(1)))
                tx["ubicaciones"].add((dominio, ruta))
                hit = (identificador, objetivo, version)
                huella = (clave, dominio, ruta, *hit, denegada.group(1) if denegada else None)
                if huella not in vistas:
                    vistas.add(huella)
                    mensajes += 1
                    tx["hits"].add(hit)
    except OSError as exc:
        raise HostiumError(f"No se pudo leer el archivo local: {exc}") from exc
    if not transacciones:
        raise HostiumError("No se encontraron mensajes ModSecurity reconocibles con ID. Se admite error log Apache o mensajes H del audit log v2; no JSON.")
    grupos: dict[tuple[object, ...], dict[str, Any]] = {}
    for tx in transacciones.values():
        # Un unique_id con ubicaciones contradictorias no se asigna a un dominio arbitrario.
        dominio, ruta = next(iter(tx["ubicaciones"])) if len(tx["ubicaciones"]) == 1 else ("ambiguo", "ambigua")
        for regla_id, variable, version in tx["hits"]:
            clave_grupo = (dominio, ruta, regla_id, variable, version)
            fuente = "Hostium" if 5500000 <= regla_id <= 5509999 else "OWASP_CRS" if 900000 <= regla_id <= 999999 else "desconocida"
            fila = grupos.setdefault(clave_grupo, {
                "dominio": dominio, "ruta": ruta, "regla_id": regla_id, "variable": variable, "version": version,
                "fuente": fuente, "evaluacion": regla_id in _EVALUADORES, "transacciones": 0,
                "con_bloqueo_observado": 0, "sin_correlacion": 0,
                "codigos_denegacion": [],
            })
            fila["transacciones"] += 1
            fila["con_bloqueo_observado"] += int(tx["bloqueada"])
            fila["sin_correlacion"] += int(not tx["correlacionada"])
            fila["codigos_denegacion"] = sorted(set(fila["codigos_denegacion"]) | tx["status"])
    ordenadas = sorted(
        grupos.values(),
        key=lambda f: (-f["con_bloqueo_observado"], -f["transacciones"], str(f["dominio"]), str(f["ruta"]), f["regla_id"], f["variable"], f["version"]),
    )
    return {
        "version_esquema": 1, "servidor": servidor, "ubicaciones_incluidas": incluir_ubicaciones,
        "mensajes_unicos": mensajes, "mensajes_omitidos": omitidas, "transacciones": len(transacciones),
        "con_bloqueo_observado": sum(int(t["bloqueada"]) for t in transacciones.values()),
        "sin_correlacion": sum(int(not t["correlacionada"]) for t in transacciones.values()),
        "primera_fecha_local": min(fechas) if fechas else None,
        "ultima_fecha_local": max(fechas) if fechas else None,
        "grupos": ordenadas,
        "limites": [
            "Un evento no confirma un falso positivo. Requiere revisión y reproducción de la operación legítima.",
            "Bloqueo observado exige Access denied with code; otros mensajes no prueban el estado HTTP final.",
            "Los conteos cubren solo el archivo recibido; no son tasas de tráfico ni mediciones completas del servidor.",
            "Las fechas Apache se conservan como hora local sin inferir zona horaria. La fuente se infiere por rango de ID.",
            "No incluye IP, request ID, cuerpos, cookies, mensajes ni valores de parámetros. Los alias SHA256 no son anonimización irreversible.",
        ],
    }


def comparar_eventos(actual: dict[str, Any], anterior: dict[str, Any]) -> list[dict[str, Any]]:
    if anterior.get("version_esquema") != 1 or not isinstance(anterior.get("grupos"), list):
        raise HostiumError("El informe base no tiene el esquema de logs analyze")
    if anterior.get("servidor") != actual["servidor"] or anterior.get("ubicaciones_incluidas") != actual["ubicaciones_incluidas"]:
        raise HostiumError("La base debe usar el mismo servidor y modo de ubicaciones")
    campos = ("dominio", "ruta", "regla_id", "variable")
    conteos: dict[tuple[Any, ...], list[int]] = defaultdict(lambda: [0, 0])
    for indice, informe in enumerate((anterior, actual)):
        for fila in informe["grupos"]:
            if not isinstance(fila, dict) or any(c not in fila for c in (*campos, "con_bloqueo_observado")):
                raise HostiumError("Grupo inválido en informe base")
            valor = fila["con_bloqueo_observado"]
            if type(valor) is not int or valor < 0 or any(not isinstance(fila[c], (str, int)) for c in campos):
                raise HostiumError("Conteo o dimensión inválida en informe base")
            conteos[tuple(fila[c] for c in campos)][indice] += valor
    return [dict(zip(campos, clave, strict=True), antes=valores[0], despues=valores[1], diferencia=valores[1] - valores[0])
            for clave, valores in sorted(conteos.items(), key=lambda i: str(i[0]))]


def markdown_eventos(datos: dict[str, Any]) -> str:
    lineas = [
        "# Diagnóstico local de ModSecurity", "",
        f"Servidor: {datos['servidor']}. Transacciones: {datos['transacciones']}. Con bloqueo observado: {datos['con_bloqueo_observado']}.",
        "", "| Dominio | Ruta | ID | Variable | Transacciones | Con bloqueo |", "| --- | --- | --- | --- | --- | --- |",
    ]
    for fila in datos["grupos"]:
        lineas.append(f"| {fila['dominio']} | {fila['ruta']} | {fila['regla_id']} | {fila['variable']} | {fila['transacciones']} | {fila['con_bloqueo_observado']} |")
    if "comparacion" in datos:
        lineas.extend(["", "Comparación de conteos (requiere ventanas y tráfico comparables):", ""])
        for fila in datos["comparacion"]:
            lineas.append(f"- {fila['dominio']} {fila['ruta']}, ID {fila['regla_id']}, {fila['variable']}: {fila['antes']} → {fila['despues']} ({fila['diferencia']:+d}).")
    lineas.extend(["", *[f"- {limite}" for limite in datos["limites"]], ""])
    return "\n".join(lineas)
