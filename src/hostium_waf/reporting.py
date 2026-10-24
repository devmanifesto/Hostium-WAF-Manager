"""Informes JSON y Markdown. No incluyen cuerpos de peticiones ni cookies."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from hostium_waf import __version__

_PERFILES_INTEGRACION = ("sin-crs", "con-crs", "laboratorio")
_CLAVES_CASO_SEGURO = ("id", "titulo", "path", "status", "id_en_log", "ms", "ok")


def cargar_evidencia_integracion(reports_dir: Path) -> dict[str, Any] | None:
    if not reports_dir.is_dir():
        return None
    estado_path = reports_dir / "integracion-estado.txt"
    modsec_path = reports_dir / "modsec-version.txt"
    crs_path = reports_dir / "crs-modsec-version.txt"
    archivos_perfil = {perfil: reports_dir / f"integracion-{perfil}.json" for perfil in _PERFILES_INTEGRACION}
    if not estado_path.is_file() and not modsec_path.is_file() and not crs_path.is_file() and not any(p.is_file() for p in archivos_perfil.values()):
        return None
    estado = estado_path.read_text(encoding="utf-8").strip() if estado_path.is_file() else "parcial"
    modsec_version = modsec_path.read_text(encoding="utf-8").strip() if modsec_path.is_file() else None
    crs_version = crs_path.read_text(encoding="utf-8").strip() if crs_path.is_file() else None
    perfiles: dict[str, dict[str, Any]] = {}
    for perfil, ruta in archivos_perfil.items():
        if not ruta.is_file():
            continue
        casos = _leer_casos_integracion(ruta)
        aprobados = sum(1 for item in casos if item.get("ok") is True)
        fallidos = len(casos) - aprobados
        perfiles[perfil] = {
            "total": len(casos),
            "aprobados": aprobados,
            "fallidos": fallidos,
            "casos": casos,
        }
    return {
        "estado": estado,
        "modsec_version": modsec_version,
        "crs_modsec_version": crs_version,
        "perfiles": perfiles,
        "advertencia": (
            "Pruebas ejecutadas en contenedor aislado; la sintaxis válida o el bloqueo en contenedor "
            "NO equivalen a protección efectiva en calcium ni en ningún cPanel real."
        ),
    }


def _leer_casos_integracion(path: Path) -> list[dict[str, Any]]:
    texto = path.read_text(encoding="utf-8")
    try:
        crudo = json.loads(texto)
    except json.JSONDecodeError:
        try:
            crudo = yaml.safe_load(texto)
        except yaml.YAMLError:
            return []
    if not isinstance(crudo, list):
        return []
    limpios: list[dict[str, Any]] = []
    for fila in crudo:
        if not isinstance(fila, dict):
            continue
        limpios.append({clave: fila.get(clave) for clave in _CLAVES_CASO_SEGURO if clave in fila})
    return limpios


def generar_informe(
    *,
    formato: str,
    validacion: list[str],
    artefacto: dict[str, Any] | None,
    auditoria: dict[str, Any] | None,
    integracion: dict[str, Any] | None = None,
) -> str:
    ahora = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    datos = {
        "herramienta": "hostium-waf",
        "version": __version__,
        "generado_en": ahora,
        "validacion": validacion,
        "artefacto": artefacto,
        "integracion": integracion,
        "auditoria": auditoria,
        "limites": [
            "Este informe no demuestra protección en calcium ni en ningún cPanel.",
            "La sintaxis válida de Apache o las pruebas en contenedor aislado no equivalen a protección en producción.",
            "No contiene cuerpos, cookies ni cabeceras de clientes.",
        ],
    }
    if formato == "json":
        return json.dumps(datos, ensure_ascii=False, indent=2) + "\n"
    if formato != "markdown":
        raise ValueError("el formato debe ser markdown o json")
    lineas = [
        "# Informe Hostium WAF Manager",
        "",
        f"- Herramienta: hostium-waf {__version__}",
        f"- Generado en: {ahora}",
        "",
        "## Validación",
        "",
    ]
    if validacion:
        lineas.extend(f"- {item}" for item in validacion)
    else:
        lineas.append("- Sin hallazgos estáticos.")
    lineas.extend(["", "## Artefacto", ""])
    if artefacto:
        for clave, valor in artefacto.items():
            lineas.append(f"- {clave}: {valor}")
    else:
        lineas.append("- No hay un ZIP local registrado en este informe.")
    lineas.extend(["", "## Integración local (contenedor)", ""])
    if integracion:
        lineas.append(f"- Estado: {integracion.get('estado')}")
        if integracion.get("modsec_version"):
            primera_modsec = str(integracion["modsec_version"]).splitlines()[0]
            lineas.append(f"- Versión ModSecurity contenedor local: {primera_modsec}")
        if integracion.get("crs_modsec_version"):
            primera_crs = str(integracion["crs_modsec_version"]).splitlines()[0]
            lineas.append(f"- Versión Apache/CRS contenedor: {primera_crs}")
        perfiles = integracion.get("perfiles") or {}
        for nombre_perfil, resumen in perfiles.items():
            lineas.append(
                f"- Perfil {nombre_perfil}: {resumen.get('aprobados', 0)}/{resumen.get('total', 0)} "
                f"casos aprobados (fallidos: {resumen.get('fallidos', 0)})"
            )
        if integracion.get("advertencia"):
            lineas.append(f"- Advertencia: {integracion['advertencia']}")
    else:
        lineas.append("- No hay evidencia de integración local en reports/.")
    lineas.extend(["", "## Auditoría", ""])
    if auditoria:
        lineas.append(f"- Fuente: {auditoria.get('fuente')}")
        lineas.append(f"- Ejecutado: {auditoria.get('ejecutado')}")
        lineas.append(f"- Nota: {auditoria.get('nota')}")
    else:
        lineas.append("- No se pidió auditoría de flota para este informe.")
    lineas.extend(["", "## Límites", ""])
    lineas.extend(f"- {item}" for item in datos["limites"])
    lineas.append("")
    return "\n".join(lineas)


def escribir_informe(path: Path, contenido: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contenido, encoding="utf-8", newline="\n")
