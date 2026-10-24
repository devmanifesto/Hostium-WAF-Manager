#!/bin/sh
# SOLO LECTURA. Dice si el vendor hostium aparece en la lista. No lo instala.
set -eu

salida=$(/usr/local/cpanel/scripts/modsec_vendor list)
printf '%s\n' "$salida"
if printf '%s\n' "$salida" | grep -q hostium; then
    echo "hostium figura en la lista. Confirmá enabled e in_use en el texto de arriba."
    echo "Eso no demuestra que una URL esté bloqueada."
    exit 0
fi
echo "hostium no figura. El vendor no está instalado o la salida cambió de formato."
exit 2
