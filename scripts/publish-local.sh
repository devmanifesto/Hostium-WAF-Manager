#!/bin/sh
# MODIFICA un directorio local. No publica por red ni instala un vendor.
# Uso: publish-local.sh VERSION DIRECTORIO_STABLE [DIRECTORIO_BUILD]
set -eu
version=${1:?falta la version SemVer}
destino=${2:?falta el directorio stable local}
case "$destino" in
    *://*) echo "rechazado: el destino no es una ruta local" >&2; exit 2 ;;
esac
raiz=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
origen=${3:-"$raiz/dist"}
python - "$version" "$destino" "$origen" <<'PY'
import sys
from pathlib import Path
from hostium_waf.errors import HostiumError
from hostium_waf.publishing import copiar_publicacion_local
from hostium_waf.security import es_semver

version, destino, origen = sys.argv[1:]
if not es_semver(version):
    raise SystemExit("version SemVer rechazada")
try:
    archivo = copiar_publicacion_local(
        Path(origen) / f"hostium-{version}.zip",
        Path(origen) / "meta_hostium.yaml",
        Path(destino),
    )
except (HostiumError, OSError) as exc:
    raise SystemExit(str(exc)) from exc
print(f"Copiado y verificado en {archivo}. No se publicó por HTTPS ni se instaló en cPanel.")
PY
