"""Comprobaciones locales. No abren SSH ni Docker salvo anotar si el binario existe."""

from __future__ import annotations

import shutil
import sys
import tomllib
from pathlib import Path

from hostium_waf import __version__
from hostium_waf.errors import Issue
from hostium_waf.inventory import validar_inventario
from hostium_waf.models import Settings
from hostium_waf.security import buscar_secretos_en_arbol
from hostium_waf.settings import load_yaml, ruta_dentro
from hostium_waf.validation import validar_exclusiones, validar_repositorio


def doctor_local(root: Path, settings: Settings) -> list[Issue]:
    issues: list[Issue] = []
    if sys.version_info < (3, 11):
        issues.append(Issue("entorno", f"hace falta Python 3.11 o superior, hay {sys.version}", "python"))
    pyproject = root / "pyproject.toml"
    with pyproject.open("rb") as fh:
        declarada = tomllib.load(fh)["project"]["version"]
    if declarada != __version__:
        issues.append(Issue("version", f"pyproject {declarada} y paquete {__version__} no coinciden", "pyproject.toml"))
    manifiesto = load_yaml(ruta_dentro(root, settings.manifiesto))
    politica = load_yaml(ruta_dentro(root, settings.politica))
    _, _, hallazgos = validar_repositorio(root, settings, manifiesto, politica)
    issues.extend(hallazgos)
    for nombre_exc in ("exclusions.example.yaml", "exclusions.yaml"):
        exclusiones = root / "config" / nombre_exc
        if exclusiones.is_file():
            issues.extend(validar_exclusiones(load_yaml(exclusiones)))
    for nombre_inv in ("fleet.example.yaml", "fleet.yaml"):
        inv_path = root / "config" / nombre_inv
        if inv_path.is_file():
            issues.extend(validar_inventario(load_yaml(inv_path)))
    scripts_dir = root / "scripts"
    if scripts_dir.is_dir():
        for script in sorted(scripts_dir.glob("*.sh")):
            crudo = script.read_bytes()
            if b"\r" in crudo:
                issues.append(Issue("fin_de_linea", "el script contiene CRLF; debe usar LF", f"scripts/{script.name}"))
    archivos = [path for path in (root / "rules").rglob("*") if path.is_file()]
    archivos.extend((root / "config").glob("*.yaml"))
    if scripts_dir.is_dir():
        archivos.extend(scripts_dir.glob("*.sh"))
    issues.extend(buscar_secretos_en_arbol(archivos))
    return issues


def capacidades_locales() -> dict[str, bool]:
    return {
        "docker": shutil.which("docker") is not None,
        "git": shutil.which("git") is not None,
        "ssh": shutil.which("ssh") is not None,
        "make": shutil.which("make") is not None,
    }


def inicializar(root: Path) -> list[str]:
    pares = [
        ("config/settings.example.yaml", "config/settings.yaml"),
        ("config/fleet.example.yaml", "config/fleet.yaml"),
        ("config/policy.example.yaml", "config/policy.yaml"),
        ("config/exclusions.example.yaml", "config/exclusions.yaml"),
    ]
    mensajes: list[str] = []
    for origen, destino in pares:
        fuente = root / origen
        final = root / destino
        if final.exists():
            mensajes.append(f"se conserva {destino}")
            continue
        texto = fuente.read_text(encoding="utf-8")
        if destino.endswith("settings.yaml"):
            texto = texto.replace("config/policy.example.yaml", "config/policy.yaml")
        final.write_text(texto, encoding="utf-8", newline="\n")
        mensajes.append(f"se creó {destino}")
    for carpeta in ("dist", "reports"):
        (root / carpeta).mkdir(exist_ok=True)
        mensajes.append(f"se aseguró {carpeta}/")
    return mensajes
