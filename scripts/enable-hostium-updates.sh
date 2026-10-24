#!/bin/sh
# PRODUCCIÓN / MODIFICA. Activa las actualizaciones del vendor hostium.
# cPanel las consulta cuando corre /usr/local/cpanel/scripts/upcp,
# releyendo la metadata con la que se hizo modsec_vendor add.
# Grafía enable-updates: nombre del argumento en la documentación de cPanel
# del 8 de julio de 2026. El ejemplo de esa fila usa enable_updates.
# No se ejecutó en calcium desde este repositorio.
set -eu
/usr/local/cpanel/scripts/modsec_vendor enable-updates hostium
/usr/local/cpanel/scripts/modsec_vendor list
