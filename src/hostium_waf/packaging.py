"""ZIP reproducible y verificación del contrato cPanel.

El directorio raíz del ZIP es hostium/, que es el vendor_id. No se usa hostium-<versión>/.
Los hashes se calculan releyendo el archivo escrito.
"""

from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

import yaml

from hostium_waf.errors import HostiumError, Issue
from hostium_waf.metadata import distribution_de, load_metadata, render_metadata
from hostium_waf.models import Politica, Settings
from hostium_waf.security import es_semver, es_version_motor, ruta_zip_insegura
from hostium_waf.settings import load_yaml, ruta_dentro, url_de_artefacto
from hostium_waf.validation import seleccionar_reglas, validar_repositorio

_EPOCH = (1980, 1, 1, 0, 0, 0)
_UNIX_SYMLINK = 0o120000
_UNIX_FILETYPE = 0o170000


@dataclass
class Artefacto:
    version: str
    engine: str
    canal: str
    distribution: str
    zip_path: Path
    metadata_path: Path
    md5: str
    sha512: str
    sha256: str
    archivos: list[str]
    url: str


def zip_bytes(members: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as zf:
        for nombre, payload in members:
            info = ZipInfo(filename=nombre, date_time=_EPOCH)
            es_directorio = nombre.endswith("/")
            info.compress_type = ZIP_STORED if es_directorio else ZIP_DEFLATED
            info.create_system = 3
            info.flag_bits = 0x800
            info.external_attr = (0o40755 << 16) | 0x10 if es_directorio else (0o100644 << 16)
            zf.writestr(info, payload, compresslevel=None if es_directorio else 9)
    return buffer.getvalue()


def inspect_zip(path: Path) -> list[Issue]:
    issues: list[Issue] = []
    try:
        with ZipFile(path) as zf:
            infos = zf.infolist()
            nombres = [info.filename for info in infos]
            if len(nombres) != len(set(nombres)):
                issues.append(Issue("zip_duplicado", "hay nombres de entrada repetidos", str(path)))
            vistos: set[str] = set()
            for info in infos:
                issues.extend(_revisar_entrada(info, vistos))
                vistos.add(info.filename)
            if not any(nombre == "hostium/" or nombre.startswith("hostium/") for nombre in nombres):
                issues.append(Issue("zip_raiz", "falta el directorio raíz hostium/", str(path)))
            archivos = [nombre for nombre in nombres if not nombre.endswith("/")]
            if not archivos:
                issues.append(Issue("paquete_vacio", "el ZIP no contiene reglas", str(path)))
    except Exception as exc:  # noqa: BLE001 - un ZIP ilegible es un fallo de validación
        issues.append(Issue("zip", f"no se pudo leer el ZIP: {exc}", str(path)))
    return issues


def _revisar_entrada(info: ZipInfo, vistos: set[str]) -> list[Issue]:
    issues: list[Issue] = []
    nombre = info.filename
    if nombre in vistos:
        issues.append(Issue("zip_duplicado", "nombre repetido", nombre))
    problema = ruta_zip_insegura(nombre)
    if problema:
        issues.append(Issue("zip_traversal", problema, nombre))
        return issues
    if info.flag_bits & 0x1:
        issues.append(Issue("zip", "el ZIP está cifrado", nombre))
    modo = (info.external_attr >> 16) & _UNIX_FILETYPE
    if modo == _UNIX_SYMLINK:
        issues.append(Issue("zip_symlink", "la entrada es un symlink", nombre))
    if not nombre.startswith("hostium/"):
        issues.append(Issue("zip_raiz", "hay una entrada fuera de hostium/", nombre))
        return issues
    relativo = nombre[len("hostium/") :]
    if not relativo:
        return issues
    if nombre.endswith("/"):
        issues.append(Issue("zip_raiz", "no se admiten subdirectorios", nombre))
        return issues
    if "/" in relativo or "\\" in relativo:
        issues.append(Issue("zip_raiz", "el archivo no está directamente bajo hostium/", nombre))
    if not relativo.endswith(".conf") or ".example" in relativo:
        issues.append(Issue("zip_extension", "solo se admiten .conf habilitados", nombre))
    if info.file_size == 0:
        issues.append(Issue("zip_vacio", "el archivo está vacío", nombre))
    posix = PurePosixPath(nombre)
    if posix.is_absolute() or ".." in posix.parts:
        issues.append(Issue("zip_traversal", "ruta normalizada insegura", nombre))
    return issues


def build_package(
    root: Path,
    settings: Settings,
    *,
    version: str,
    engine: str,
    canal: str | None = None,
    output: Path | None = None,
) -> Artefacto:
    if not es_semver(version):
        raise HostiumError("La versión del ruleset debe ser SemVer, distinta de la versión del motor")
    if not es_version_motor(engine):
        raise HostiumError("La versión del motor debe ser un string de tres componentes, por ejemplo 2.9.15")
    canal_final = canal or settings.canal_por_defecto
    manifiesto_data = load_yaml(ruta_dentro(root, settings.manifiesto))
    politica_data = load_yaml(ruta_dentro(root, settings.politica))
    manifiesto, politica, issues = validar_repositorio(root, settings, manifiesto_data, politica_data)
    from hostium_waf.security import buscar_secretos_en_arbol

    candidatos = [root / regla.archivo for regla in manifiesto.reglas]
    candidatos.append(Path(settings.origen))
    candidatos.append(ruta_dentro(root, settings.politica))
    issues.extend(buscar_secretos_en_arbol(candidatos))
    if issues:
        raise HostiumError("El repositorio no pasa la validación", issues=issues)
    elegidas = seleccionar_reglas(manifiesto, politica)
    maxima = _version_introduccion_maxima(elegidas)
    if maxima is not None and _tupla_semver(version) < _tupla_semver(maxima):
        raise HostiumError(
            f"No se construye hostium-{version}: el paquete incluye reglas introducidas en {maxima}. "
            "No se reutiliza una distribution ya publicada para otro contenido."
        )
    destino = (output if output is not None else root / settings.directorio_salida).resolve()
    return _empaquetar(
        settings,
        manifiesto_reglas(root, politica, manifiesto),
        version,
        engine,
        canal_final,
        destino,
    )


def _tupla_semver(valor: str) -> tuple[int, int, int]:
    mayor, menor, parche = (int(parte) for parte in valor.split("."))
    return mayor, menor, parche


def _version_introduccion_maxima(reglas: list[object]) -> str | None:
    from hostium_waf.models import Regla

    introducidas = [regla.version_de_introduccion for regla in reglas if isinstance(regla, Regla)]
    if not introducidas:
        return None
    return max(introducidas, key=_tupla_semver)


def manifiesto_reglas(root: Path, politica: Politica, manifiesto: object) -> list[tuple[str, bytes]]:
    from hostium_waf.models import Manifiesto

    if not isinstance(manifiesto, Manifiesto):
        raise HostiumError("Manifiesto inválido")
    elegidas = seleccionar_reglas(manifiesto, politica)
    if not elegidas:
        raise HostiumError("La política no habilita ninguna regla de producción")
    archivos: list[Path] = []
    vistos: set[Path] = set()
    for regla in elegidas:
        path = ruta_dentro(root, regla.archivo)
        if path not in vistos:
            vistos.add(path)
            archivos.append(path)
    miembros: list[tuple[str, bytes]] = [("hostium/", b"")]
    for path in sorted(archivos, key=lambda item: item.name):
        if path.name.endswith((".example", ".conf.example")) or not path.name.endswith(".conf"):
            raise HostiumError(f"Intento de empaquetar un archivo no permitido: {path.name}")
        texto = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
        if "INCOMPLETO" in texto:
            raise HostiumError(f"El archivo {path.name} está marcado INCOMPLETO")
        if "ver:'hostium/" not in texto:
            raise HostiumError(f"El archivo {path.name} no declara ver:hostium")
        miembros.append((f"hostium/{path.name}", texto.encode("utf-8")))
    return miembros


def _empaquetar(
    settings: Settings,
    miembros: list[tuple[str, bytes]],
    version: str,
    engine: str,
    canal: str,
    salida: Path,
) -> Artefacto:
    salida.mkdir(parents=True, exist_ok=True)
    payload = zip_bytes(miembros)
    distribution = distribution_de(version)
    zip_final = salida / f"{distribution}.zip"
    releases = salida / "releases"
    releases.mkdir(parents=True, exist_ok=True)
    release_zip = releases / f"{distribution}.zip"
    _exigir_inmutable(zip_final, payload)
    _exigir_inmutable(release_zip, payload)
    url = url_de_artefacto(settings, canal, version)
    # Los hashes se confirman después de escribir y releer. Se anticipan con el
    # payload para poder rechazar metadata incompatible antes de tocar el disco.
    md5 = hashlib.md5(payload).hexdigest()
    sha512 = hashlib.sha512(payload).hexdigest()
    sha256 = hashlib.sha256(payload).hexdigest()
    metadata = render_metadata(
        engine=engine,
        md5=md5,
        sha512=sha512,
        distribution=distribution,
        url=url,
        nombre=settings.nombre_visible,
        descripcion=settings.descripcion,
        vendor_url=settings.vendor_url,
    )
    metadata_path = salida / "meta_hostium.yaml"
    canal_dir = salida / "channels" / canal
    canal_dir.mkdir(parents=True, exist_ok=True)
    canal_meta = canal_dir / "meta_hostium.yaml"
    _exigir_metadata_inmutable(metadata_path, metadata, permitir_mismo_hash=True)
    _exigir_metadata_inmutable(canal_meta, metadata, permitir_mismo_hash=False)
    zip_final.write_bytes(payload)
    release_zip.write_bytes(payload)
    if zip_final.read_bytes() != payload:
        raise HostiumError("El ZIP releído no coincide con los bytes generados")
    metadata_path.write_text(metadata, encoding="utf-8", newline="\n")
    canal_meta.write_text(metadata, encoding="utf-8", newline="\n")
    (releases / f"{distribution}.sha256").write_text(sha256 + "\n", encoding="utf-8", newline="\n")
    estructura = inspect_zip(zip_final)
    if estructura:
        raise HostiumError("El ZIP generado no cumple el contrato", issues=estructura)
    return Artefacto(
        version=version,
        engine=engine,
        canal=canal,
        distribution=distribution,
        zip_path=zip_final,
        metadata_path=metadata_path,
        md5=md5,
        sha512=sha512,
        sha256=sha256,
        archivos=[nombre for nombre, _ in miembros if not nombre.endswith("/")],
        url=url,
    )


def _exigir_inmutable(path: Path, payload: bytes) -> None:
    if not path.exists():
        return
    if path.read_bytes() != payload:
        raise HostiumError(
            f"La versión ya existe con otros bytes y no se sobrescribe: {path}",
        )


def _huella(texto: str) -> tuple[tuple[object, ...], ...]:
    try:
        data = yaml.safe_load(texto)
    except yaml.YAMLError:
        return tuple()
    if not isinstance(data, dict):
        return tuple()
    pares = []
    for clave, bloque in data.items():
        if clave == "attributes" or not isinstance(bloque, dict):
            continue
        pares.append((bloque.get("distribution"), bloque.get("MD5"), bloque.get("SHA512")))
    return tuple(pares)


def _exigir_metadata_inmutable(path: Path, metadata: str, *, permitir_mismo_hash: bool) -> None:
    if not path.exists():
        return
    anterior = path.read_text(encoding="utf-8")
    if anterior == metadata:
        return
    if permitir_mismo_hash and _huella(anterior) == _huella(metadata):
        return
    raise HostiumError(f"Ya hay metadata distinta y no se sobrescribe: {path}")


def verify_package(zip_path: Path, metadata_path: Path) -> list[Issue]:
    issues = inspect_zip(zip_path)
    if not metadata_path.is_file():
        return issues + [Issue("metadata", "no existe la metadata", str(metadata_path))]
    data, meta_issues = load_metadata(metadata_path)
    issues.extend(meta_issues)
    if not isinstance(data, dict):
        return issues
    blob = zip_path.read_bytes()
    md5 = hashlib.md5(blob).hexdigest()
    sha512 = hashlib.sha512(blob).hexdigest()
    coincidencias = []
    for clave, bloque in data.items():
        if clave == "attributes" or not isinstance(bloque, dict):
            continue
        if bloque.get("MD5") == md5 and bloque.get("SHA512") == sha512:
            coincidencias.append(clave)
        elif bloque.get("MD5") == md5 or bloque.get("SHA512") == sha512:
            issues.append(Issue("hash", "MD5 y SHA512 no corresponden al mismo archivo", f"metadata.{clave}"))
    if not coincidencias and not any(item.codigo == "hash" for item in issues):
        issues.append(Issue("hash", "ningún bloque de motor coincide con los hashes del ZIP", "metadata"))
    nombre = zip_path.name
    match = re.fullmatch(r"(hostium-\d+\.\d+\.\d+)\.zip", nombre)
    if match and isinstance(data, dict):
        dist = match.group(1)
        for clave, bloque in data.items():
            if clave == "attributes" or not isinstance(bloque, dict):
                continue
            if bloque.get("distribution") != dist:
                issues.append(
                    Issue(
                        "distribution",
                        f"el ZIP se llama {nombre} pero distribution es {bloque.get('distribution')}",
                        f"metadata.{clave}.distribution",
                    )
                )
    return issues


def metadata_es_valida(texto: str) -> list[Issue]:
    from hostium_waf.metadata import validar_metadata

    try:
        data = yaml.safe_load(texto)
    except yaml.YAMLError as exc:
        return [Issue("metadata", f"YAML inválido: {exc}", "metadata")]
    return validar_metadata(data)
