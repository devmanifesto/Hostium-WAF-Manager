"""Carga de configuración. Siempre usa yaml.safe_load."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from hostium_waf.errors import HostiumError, Issue
from hostium_waf.models import Settings
from hostium_waf.security import es_version_motor, url_publicacion_valida

_CLAVES_SETTINGS = {
    "version_esquema",
    "vendor_id",
    "nombre_visible",
    "descripcion",
    "vendor_url",
    "base_url",
    "motor_por_defecto",
    "canal_por_defecto",
    "manifiesto",
    "politica",
    "directorio_salida",
    "rango_ids",
}


def find_root(start: Path | None = None) -> Path:
    env = os.environ.get("HOSTIUM_WAF_ROOT")
    if env:
        raiz = Path(env).expanduser().resolve()
        if not (raiz / "pyproject.toml").is_file():
            raise HostiumError(f"HOSTIUM_WAF_ROOT no contiene pyproject.toml: {raiz}")
        return raiz
    actual = (start or Path.cwd()).resolve()
    for candidato in [actual, *actual.parents]:
        if (candidato / "pyproject.toml").is_file() and (candidato / "src" / "hostium_waf").is_dir():
            return candidato
    raise HostiumError("No se encontró la raíz del proyecto Hostium WAF Manager")


def load_yaml(path: Path) -> Any:
    if not path.is_file():
        raise HostiumError(f"No existe el archivo: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise HostiumError(f"YAML inválido en {path}: {exc}") from exc
    if data is None:
        raise HostiumError(f"El YAML está vacío: {path}")
    return data


def resolver_settings(root: Path, explicito: Path | None = None) -> Path:
    if explicito is not None:
        return explicito if explicito.is_absolute() else root / explicito
    local = root / "config" / "settings.yaml"
    if local.is_file():
        return local
    return root / "config" / "settings.example.yaml"


def _issues_settings(data: Any) -> list[Issue]:
    issues: list[Issue] = []
    if not isinstance(data, dict):
        return [Issue("tipo_invalido", "la configuración debe ser un mapa", "settings")]
    desconocidas = sorted(set(data) - _CLAVES_SETTINGS)
    for clave in desconocidas:
        issues.append(Issue("campo_desconocido", "clave no admitida", f"settings.{clave}"))
    for clave in sorted(_CLAVES_SETTINGS - set(data)):
        issues.append(Issue("campo_faltante", "falta la clave", f"settings.{clave}"))
    if issues:
        return issues
    if data["version_esquema"] != 1:
        issues.append(Issue("version_esquema", "solo se admite la versión 1", "settings.version_esquema"))
    if data["vendor_id"] != "hostium":
        issues.append(
            Issue(
                "vendor_id",
                "el vendor_id debe ser hostium, derivado de meta_hostium.yaml",
                "settings.vendor_id",
            )
        )
    for clave in ("nombre_visible", "descripcion", "manifiesto", "politica", "directorio_salida"):
        if not isinstance(data[clave], str) or not data[clave].strip():
            issues.append(Issue("tipo_invalido", "debe ser un texto no vacío", f"settings.{clave}"))
    if data.get("canal_por_defecto") not in {"stable", "canary"}:
        issues.append(Issue("canal", "el canal debe ser stable o canary", "settings.canal_por_defecto"))
    for clave in ("vendor_url", "base_url"):
        valor = data.get(clave)
        if not isinstance(valor, str) or not valor.startswith("https://"):
            issues.append(Issue("url_insegura", "debe ser una URL HTTPS", f"settings.{clave}"))
        elif urlparse_tiene_credenciales(valor):
            issues.append(Issue("url_insegura", "la URL no debe incluir credenciales", f"settings.{clave}"))
    motor = data.get("motor_por_defecto")
    if not isinstance(motor, str) or not es_version_motor(motor):
        issues.append(
            Issue(
                "motor",
                "la versión del motor debe ser un string SemVer de tres componentes, no la de Apache ni la del RPM de CRS",
                "settings.motor_por_defecto",
            )
        )
    rango = data.get("rango_ids")
    if not isinstance(rango, dict):
        issues.append(Issue("tipo_invalido", "rango_ids debe ser un mapa", "settings.rango_ids"))
    else:
        inicio = rango.get("inicio")
        fin = rango.get("fin")
        if isinstance(inicio, bool) or not isinstance(inicio, int):
            issues.append(Issue("tipo_invalido", "inicio debe ser un entero", "settings.rango_ids.inicio"))
        if isinstance(fin, bool) or not isinstance(fin, int):
            issues.append(Issue("tipo_invalido", "fin debe ser un entero", "settings.rango_ids.fin"))
        if isinstance(inicio, int) and isinstance(fin, int) and not isinstance(inicio, bool) and not isinstance(fin, bool):
            if inicio > fin:
                issues.append(Issue("rango_ids", "el inicio es mayor que el fin", "settings.rango_ids"))
    return issues


def urlparse_tiene_credenciales(url: str) -> bool:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return bool(parsed.username or parsed.password)


def load_settings(root: Path, explicito: Path | None = None) -> Settings:
    path = resolver_settings(root, explicito)
    data = load_yaml(path)
    issues = _issues_settings(data)
    if issues:
        raise HostiumError("La configuración no es válida", issues=issues)
    return Settings(
        version_esquema=data["version_esquema"],
        vendor_id=data["vendor_id"],
        nombre_visible=data["nombre_visible"],
        descripcion=data["descripcion"],
        vendor_url=data["vendor_url"].rstrip("/"),
        base_url=data["base_url"].rstrip("/"),
        motor_por_defecto=data["motor_por_defecto"],
        canal_por_defecto=data["canal_por_defecto"],
        manifiesto=data["manifiesto"],
        politica=data["politica"],
        directorio_salida=data["directorio_salida"],
        rango_inicio=data["rango_ids"]["inicio"],
        rango_fin=data["rango_ids"]["fin"],
        origen=str(path),
    )


def ruta_dentro(root: Path, relativa: str) -> Path:
    destino = (root / relativa).resolve()
    raiz = root.resolve()
    if destino != raiz and raiz not in destino.parents:
        raise HostiumError(f"La ruta sale del repositorio: {relativa}")
    return destino


def url_de_artefacto(settings: Settings, canal: str, version: str) -> str:
    if canal not in {"stable", "canary"}:
        raise HostiumError("El canal debe ser stable o canary")
    url = f"{settings.base_url}/{canal}/hostium-{version}.zip"
    problema = url_publicacion_valida(url)
    if problema:
        raise HostiumError(problema)
    return url
