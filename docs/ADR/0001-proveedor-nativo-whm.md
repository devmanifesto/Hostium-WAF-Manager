# ADR 0001 — Proveedor nativo de WHM

## Estado

Aceptado el 23 de octubre de 2026.

## Contexto

Hay que distribuir reglas propias a varios cPanel sin editar el ruleset OWASP que instala EasyApache y sin un plugin de WHM que habría que mantener aparte.

## Decisión

Publicar un vendor ModSecurity cuyo `vendor_id` es `hostium`, con metadata `meta_hostium.yaml` y un ZIP que extrae solo el directorio `hostium/`.

## Por qué no las alternativas

Editar los `.conf` de OWASP los pisa el próximo `rpm` update. Un plugin de WHM agrega superficie y no es necesario para incluir reglas. Copiar otro vendor comercial no es viable ni está permitido en este proyecto.

## Consecuencias

El orden respecto de CRS no queda garantizado por el alta del vendor. Las exclusiones `ctl:ruleRemoveById` y `SecRuleRemoveById` viven fuera del ZIP. La compatibilidad se declara solo para motores probados; hoy el generador escribe la versión que le pases, y la única que el piloto describió es 2.9.15.

## Enmienda del 2 de noviembre de 2026

`hostium-2.1.0` agrega dos archivos al mismo ZIP. El texto de octubre queda como estaba.

`REQUEST-900-CRS-EXCLUSIONS.conf` lleva `ctl:ruleRemoveTargetById` en fase 1, atado a una URI, en el eslabón final de la cadena. Ese `ctl` queda en la transacción y alcanza una regla CRS de fase 2 aunque WHM incluya hostium después de OWASP3. `ctl:ruleRemoveById` y `SecRuleRemoveById` siguen fuera del ZIP.

`REQUEST-910-CRS-ANOMALY-SCORE.conf` lleva `SecRuleUpdateActionById`. Esa directiva se resuelve al leer la configuración y solo aplica si el archivo se lee después de OWASP3. Si el id CRS todavía no existe, `httpd -t` falla y Apache no debe recargarse. Este repositorio no comprobó ese orden en un cPanel.

## Cómo se revierte esta decisión

Dejar de ofrecer la URL de metadata y deshabilitar el vendor. Los RPM de OWASP no se tocan en ese camino.
