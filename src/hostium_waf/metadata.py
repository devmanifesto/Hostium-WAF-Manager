"""Metadata meta_hostium.yaml. El emisor controla el formato: la clave de motor va citada."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from hostium_waf.errors import Issue
from hostium_waf.security import es_semver, es_version_motor, url_publicacion_valida

_HEX_MD5 = re.compile(r"^[0-9a-f]{32}$")
_HEX_SHA512 = re.compile(r"^[0-9a-f]{128}$")
_CLAVES_MOTOR = {"MD5", "SHA512", "distribution", "url"}
_CLAVES_ATRIBUTOS = {"name", "description", "vendor_url"}
FRASE_COMENTARIO_MODULO = "Reglas complementarias de seguridad administradas por Hostium"
_LINEA_COMENTARIO = re.compile(
    rf"^# {re.escape(FRASE_COMENTARIO_MODULO)} (0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"
)
_DESCRIPCION_COMENTARIO = re.compile(
    rf"^{re.escape(FRASE_COMENTARIO_MODULO)} (0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"
)


def descripcion_modulo(version: str) -> str:
    if not es_semver(version):
        raise ValueError("la versión del ruleset debe ser SemVer")
    return f"{FRASE_COMENTARIO_MODULO} {version}"


def aplicar_comentario_modulo(texto: str, version: str) -> str:
    """Deja la primera línea del módulo con la frase fija y la versión del paquete."""
    linea = f"# {descripcion_modulo(version)}"
    lineas = texto.split("\n")
    if lineas and _LINEA_COMENTARIO.fullmatch(lineas[0]):
        lineas[0] = linea
    else:
        lineas.insert(0, linea)
    return "\n".join(lineas)


def comentario_modulo_valido(texto: str) -> bool:
    primera = texto.splitlines()[0] if texto.splitlines() else ""
    return bool(_LINEA_COMENTARIO.fullmatch(primera))


def render_metadata(
    *,
    engine: str,
    md5: str,
    sha512: str,
    distribution: str,
    url: str,
    nombre: str,
    version: str,
    vendor_url: str,
    motores_extra: dict[str, dict[str, str]] | None = None,
) -> str:
    if not es_version_motor(engine):
        raise ValueError("versión de motor inválida")
    # Comillas simples para que PyYAML no interprete la clave como número.
    lineas = [
        "---",
        f"'{engine}':",
        f"  MD5: '{md5}'",
        f"  SHA512: '{sha512}'",
        f"  distribution: '{distribution}'",
        f"  url: '{url}'",
    ]
    if motores_extra:
        for motor_clave, bloque in motores_extra.items():
            if not es_version_motor(motor_clave):
                raise ValueError(f"versión de motor inválida: {motor_clave}")
            if motor_clave == engine:
                continue
            lineas.extend(
                [
                    f"'{motor_clave}':",
                    f"  MD5: '{bloque['MD5']}'",
                    f"  SHA512: '{bloque['SHA512']}'",
                    f"  distribution: '{bloque['distribution']}'",
                    f"  url: '{bloque['url']}'",
                ]
            )
    lineas.extend(
        [
            "attributes:",
            f"  name: '{_yaml_simple(nombre)}'",
            f"  description: '{_yaml_simple(descripcion_modulo(version))}'",
            f"  vendor_url: '{vendor_url}'",
            "",
        ]
    )
    return "\n".join(lineas)


def _yaml_simple(valor: str) -> str:
    if "'" in valor or "\n" in valor:
        raise ValueError("el texto de metadata contiene caracteres no admitidos en v1")
    return valor


def distribution_de(version: str) -> str:
    if not es_semver(version):
        raise ValueError("la versión del ruleset debe ser SemVer")
    return f"hostium-{version}"


def validar_metadata(data: Any) -> list[Issue]:
    issues: list[Issue] = []
    if not isinstance(data, dict):
        return [Issue("metadata", "el documento debe ser un mapa", "metadata")]
    if "report_url" in data.get("attributes", {}) if isinstance(data.get("attributes"), dict) else False:
        issues.append(
            Issue(
                "report_url",
                "v1 no declara report_url: no hay un receptor real provisionado",
                "metadata.attributes.report_url",
            )
        )
    atributos = data.get("attributes")
    if not isinstance(atributos, dict):
        issues.append(Issue("campo_faltante", "faltan attributes", "metadata.attributes"))
        atributos = {}
    else:
        desconocidas = sorted(set(atributos) - _CLAVES_ATRIBUTOS)
        for clave in desconocidas:
            issues.append(Issue("campo_desconocido", "atributo no admitido en v1", f"metadata.attributes.{clave}"))
        for clave in ("name", "description", "vendor_url"):
            valor = atributos.get(clave)
            if not isinstance(valor, str) or not valor.strip():
                issues.append(Issue("campo_faltante", "falta o está vacío", f"metadata.attributes.{clave}"))
        vendor = atributos.get("vendor_url")
        if isinstance(vendor, str) and not vendor.startswith("https://"):
            issues.append(Issue("url_insegura", "vendor_url debe ser HTTPS", "metadata.attributes.vendor_url"))
        descripcion = atributos.get("description")
        if isinstance(descripcion, str) and descripcion.strip() and not _DESCRIPCION_COMENTARIO.fullmatch(descripcion):
            issues.append(
                Issue(
                    "comentario",
                    "description debe ser la frase fija del módulo seguida de la versión SemVer del ruleset",
                    "metadata.attributes.description",
                )
            )
    motores = [clave for clave in data if clave != "attributes"]
    if not motores:
        issues.append(Issue("metadata", "falta la clave de versión del motor ModSecurity", "metadata"))
    for clave in motores:
        ruta = f"metadata.{clave!r}"
        if not isinstance(clave, str):
            issues.append(
                Issue(
                    "motor",
                    "la clave de motor se interpretó como número; debe ir citada como string",
                    ruta,
                )
            )
            continue
        if not es_version_motor(clave):
            issues.append(Issue("motor", "la clave debe ser la versión del motor, por ejemplo 2.9.15", ruta))
        bloque = data[clave]
        if not isinstance(bloque, dict):
            issues.append(Issue("tipo_invalido", "el bloque del motor debe ser un mapa", ruta))
            continue
        for necesaria in sorted(_CLAVES_MOTOR - set(bloque)):
            issues.append(Issue("campo_faltante", "falta el campo", f"{ruta}.{necesaria}"))
        for extra in sorted(set(bloque) - _CLAVES_MOTOR):
            issues.append(Issue("campo_desconocido", "campo no admitido", f"{ruta}.{extra}"))
        md5 = bloque.get("MD5")
        sha = bloque.get("SHA512")
        if not isinstance(md5, str) or not _HEX_MD5.fullmatch(md5):
            issues.append(Issue("hash", "MD5 debe ser 32 hexadecimales en minúscula", f"{ruta}.MD5"))
        if not isinstance(sha, str) or not _HEX_SHA512.fullmatch(sha):
            issues.append(Issue("hash", "SHA512 debe ser 128 hexadecimales en minúscula", f"{ruta}.SHA512"))
        dist = bloque.get("distribution")
        if not isinstance(dist, str) or not re.fullmatch(r"hostium-\d+\.\d+\.\d+", dist):
            issues.append(
                Issue(
                    "distribution",
                    "distribution debe ser hostium-<semver> y no el nombre del directorio del ZIP",
                    f"{ruta}.distribution",
                )
            )
        url = bloque.get("url")
        if not isinstance(url, str):
            issues.append(Issue("url_insegura", "url debe ser texto", f"{ruta}.url"))
        else:
            problema = url_publicacion_valida(url)
            if problema:
                issues.append(Issue("url_insegura", problema, f"{ruta}.url"))
    return issues


def load_metadata(path: Path) -> tuple[Any, list[Issue]]:
    if not path.is_file():
        return None, [Issue("metadata", "no existe el archivo de metadata", str(path))]
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return None, [Issue("metadata", f"no se pudo leer el YAML de metadata: {exc}", str(path))]
    return data, validar_metadata(data)
