#!/bin/sh
# SOLO LECTURA. Comprueba que el módulo y el motor están declarados.
set -eu

httpd -M | grep security2_module
if grep -R -- "SecRuleEngine" /etc/apache2/conf.d/modsec/modsec2.cpanel.conf /etc/apache2/conf.d/modsec/modsec2.user.conf 2>/dev/null; then
    echo "Se encontró SecRuleEngine en la configuración global de ModSecurity."
else
    echo "No se encontró SecRuleEngine en las rutas habituales. Revisar includes antes de concluir."
fi
httpd -t
echo "Syntax OK solo habla de configuración. No es una prueba de bloqueo."
