"""Plan de publicación local. No abre conexiones ni sube artefactos."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from hostium_waf.errors import BlockedOperation, HostiumError
from hostium_waf.packaging import verify_package

_MOTIVO_REMOTO = (
    "La publicación HTTP está bloqueada. v1 solo describe el orden atómico. "
    "No se sube nada a GitHub ni a otro host."
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


def copiar_publicacion_local(zip_path: Path, metadata_path: Path, destino: Path) -> Path:
    """Prepara un directorio local stable; valida e impide reemplazar un ZIP distinto.

    No autentica ni publica el origen. La metadata se reemplaza atómicamente después
    de confirmar el archivo; requiere autorización del operador para servirla.
    """
    issues = verify_package(zip_path, metadata_path)
    if issues:
        raise HostiumError("No se copia un paquete inválido", issues=issues)
    raiz = destino.resolve()
    raiz.mkdir(parents=True, exist_ok=True)
    archivo = raiz / zip_path.name
    meta = raiz / "meta_hostium.yaml"
    if archivo.is_symlink() or meta.is_symlink():
        raise HostiumError("El destino no puede contener enlaces simbólicos de ZIP o metadata")
    payload = zip_path.read_bytes()
    if archivo.exists():
        if archivo.read_bytes() != payload:
            raise HostiumError("El ZIP de destino ya existe con otros bytes; no se sobrescribe")
    else:
        # xb evita sobrescribir incluso si otro proceso creó el nombre después del exists.
        with archivo.open("xb") as salida:
            salida.write(payload)
    if archivo.read_bytes() != payload:
        raise HostiumError("El ZIP copiado no coincide; la metadata no se cambia")
    temporal = None
    try:
        with tempfile.NamedTemporaryFile(dir=raiz, prefix=".meta-hostium-", delete=False) as salida:
            temporal = Path(salida.name)
            salida.write(metadata_path.read_bytes())
        os.replace(temporal, meta)
    finally:
        if temporal is not None:
            temporal.unlink(missing_ok=True)
    return archivo
