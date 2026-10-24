"""Plan de publicación local. No abre conexiones ni sube artefactos."""

from __future__ import annotations

from pathlib import Path

from hostium_waf.errors import BlockedOperation
from hostium_waf.packaging import verify_package

_MOTIVO_REMOTO = (
    "La publicación HTTP está bloqueada. v1 solo describe el orden atómico. "
    "No se sube nada a waf.hostium.com ni a otro host."
)


def plan_publicacion(zip_path: Path, metadata_path: Path, version: str, canal: str) -> dict[str, object]:
    issues = []
    if zip_path.is_file() and metadata_path.is_file():
        issues = [item.formato() for item in verify_package(zip_path, metadata_path)]
    listo = zip_path.is_file() and metadata_path.is_file() and not issues
    return {
        "ok": listo,
        "accion": "publish plan",
        "ejecutado": False,
        "subio_artefactos": False,
        "listo": listo,
        "version": version,
        "canal": canal,
        "zip": str(zip_path),
        "metadata": str(metadata_path),
        "problemas": issues,
        "orden": [
            "Subir el ZIP al URL del canal y no publicar todavía la metadata.",
            "Descargar el ZIP desde esa URL y comparar MD5 y SHA512 con la metadata local.",
            "Solo si coinciden, publicar meta_hostium.yaml en el URL que WHM va a consultar.",
            "Si el proceso se corta, la metadata vieja sigue apuntando al ZIP anterior.",
            "Invalidar la caché del ZIP nuevo antes de cambiar la metadata, o usar un nombre de release inmutable.",
            "stable y canary son URLs distintas. WHM no tiene canales nativos: recuerda la URL desde la que se instaló el vendor.",
            "Una firma cosign, minisign o GPG queda fuera del mecanismo nativo. cPanel no la valida.",
        ],
        "nota": _MOTIVO_REMOTO,
    }


def apply_publicacion() -> None:
    raise BlockedOperation(_MOTIVO_REMOTO)
