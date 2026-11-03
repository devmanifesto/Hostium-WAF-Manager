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

El texto de octubre queda como estaba. `hostium-2.1.0` agrega `REQUEST-900-CRS-EXCLUSIONS.conf`. El ctl de objetivo es fase 1. Si el campo es propio de la aplicación, es un `SecAction` sin URI. Si el campo es genérico, es una sola `SecRule` sobre `REQUEST_URI`, sin cadena. El ctl queda en la transacción y alcanza una regla CRS de fase 2 aunque WHM incluya hostium después de OWASP3. `ctl:ruleRemoveById` y `SecRuleRemoveById` siguen fuera del ZIP.

`SecRuleUpdateActionById` no entra en ese ZIP. El orden del vendor hostium respecto de OWASP3 no está garantizado y un id desconocido hace fallar `httpd -t`. El conf de puntaje es el vendor `hostium-tune`, metadata `meta_hostium-tune.yaml`, raíz `hostium-tune/`. La distribution vigente es `hostium-tune-2.1.1`. srv-admin lo agrega después de OWASP3. Este repositorio no comprobó ese orden en un cPanel. El 2 de noviembre de 2026 WHM mostró Hostium Tune sin sets y Hostium en 2/2. No se releyó el servidor desde este árbol.

## Cómo se revierte esta decisión

Dejar de ofrecer la URL de metadata y deshabilitar el vendor. Los RPM de OWASP no se tocan en ese camino.
