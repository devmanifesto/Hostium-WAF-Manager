# Observabilidad y logs

## Objetivo

Definir qué se puede sacar de un evento sin copiar el cuerpo ni las cookies.

## Audiencia

Quien arme un tablero más adelante, y quien mire un incidente ahora.

## Prerrequisitos

Acceso al audit log del servidor. Ese archivo no se trae al repositorio.

## Evento mínimo

Host, timestamp, dominio, id de regla, categoría, acción, status HTTP, un identificador de petición si Apache ya lo tiene, versión del ruleset (`ver:hostium/x.y.z`) y la fuente Hostium u OWASP según el id. La IP de cliente solo si el header de proxy ya fue validado en ese servidor. Si no, se etiqueta como no verificada.

La regla productiva escribe `logdata` con el nombre de la variable, no con la URL. El audit log del servidor igual puede contener la petición completa: eso lo configura `SecAuditLogParts`, no este ZIP. En el contenedor de prueba las partes son `ABIJDEFHZ`. En producción hay que revisar las partes ya definidas por cPanel antes de ampliarlas.

## Métricas

Conteos de hits y de 403 por servidor, dominio, id y versión del ruleset. Comparar el día anterior al release con las horas siguientes. Un salto de 403 después del alta es una alerta para mirar, no una prueba de que el ataque aumentó.

Prometheus, Grafana, Alertmanager y Zabbix quedan fuera de la 1.0.0. El esquema de arriba es suficiente para alimentarlos después.

## Retención y acceso

Los logs viven en el servidor, con el mismo control de acceso que el resto de los logs de root. No se copian a CI ni a git. Un informe generado por `report generate` no incluye cuerpos.

## Verificación

En una prueba autorizada, el id 5500100 aparece una vez por la petición de `/.env` y no aparece en `/environment`.

## Deshacer

Volver `SecAuditEngine` a su valor anterior si alguien lo subió para diagnosticar. No dejes `SecAuditEngine On` con cuerpos completos más tiempo del incidente.

## Problemas frecuentes

Buscar la regla en el access log de Apache y no ver el id. El id está en el error log o en el audit log de ModSecurity, y en el Hits List de WHM.

## Referencias

Documentación de ModSecurity Tools de cPanel.

## Limitaciones

No hay extractor implementado en la CLI. `fleet audit` no descarga logs de peticiones.
