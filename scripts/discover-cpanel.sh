#!/bin/sh
# SOLO LECTURA. No reinicia servicios ni cambia configuración.
# Correr como root en un cPanel, o con un usuario que ya pueda leer estos comandos.
set -eu

echo "== hostname =="
hostname
echo "== os-release =="
cat /etc/os-release
echo "== cpanel =="
/usr/local/cpanel/cpanel -V
echo "== apache =="
httpd -v
httpd -M
echo "== rpm modsecurity =="
rpm -q ea-apache24-mod_security2
echo "== rpm owasp crs =="
rpm -q ea-modsec2-rules-owasp-crs
echo "== vendors =="
/usr/local/cpanel/scripts/modsec_vendor list
echo "== sintaxis =="
httpd -t
echo "== includes =="
httpd -t -D DUMP_INCLUDES
echo "== nginx rpm =="
rpm -q ea-nginx || true
echo "== engintron dir =="
if test -d /usr/local/src/engintron; then
    echo "directorio presente; esto no demuestra el camino del trafico"
else
    echo "directorio ausente; puede haber otro proxy"
fi
echo "Listo. Esta salida no demuestra un bloqueo efectivo."
