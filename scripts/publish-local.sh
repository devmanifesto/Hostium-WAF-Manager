#!/bin/sh
# Copia artefactos ya construidos a un directorio local. No usa la red.
set -eu

version=${1:?falta la version SemVer}
destino=${2:?falta el directorio destino}
case "$version" in
    *[!0-9.]*) echo "version rechazada" >&2; exit 2 ;;
esac
case "$destino" in
    *://*) echo "rechazado: el destino no es una ruta local" >&2; exit 2 ;;
esac

raiz=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
origen="$raiz/dist/hostium-$version.zip"
meta="$raiz/dist/meta_hostium.yaml"
test -f "$origen"
test -f "$meta"
mkdir -p -- "$destino/releases" "$destino/channels/stable"
cp -- "$origen" "$destino/releases/hostium-$version.zip"
cp -- "$meta" "$destino/channels/stable/meta_hostium.yaml"
echo "Copiado en $destino. No se publicó por HTTPS."
