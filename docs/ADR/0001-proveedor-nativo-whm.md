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

El texto de octubre queda como estaba. `hostium-2.1.1` conserva `REQUEST-900-CRS-EXCLUSIONS.conf`. `hostium-2.1.0` lo agregó. El ctl de objetivo es fase 1. Si el campo es propio de la aplicación, es un `SecAction` sin URI. Si el campo es genérico, es una sola `SecRule` sobre `REQUEST_URI`, sin cadena. El ctl queda en la transacción y alcanza una regla CRS de fase 2 aunque WHM incluya hostium después de OWASP3. `ctl:ruleRemoveById` y `SecRuleRemoveById` siguen fuera del ZIP.

`SecRuleUpdateActionById` no entra en ese ZIP. El puntaje no es un vendor. srv-admin lo mantiene en un archivo propio, leído después de `modsec2.conf`. `meta_hostium-tune.yaml` queda nombrando `hostium-tune-2.1.0.zip` para no devolver 404 a quien ya lo tiene. No se ofrece para instalar. El único meta de alta es `meta_hostium.yaml`, distribution `hostium-2.1.1`. Este repositorio no comprobó el orden de Include en un cPanel. El 2 de noviembre de 2026 WHM mostró Hostium Tune sin sets y Hostium en 2/2. No se releyó el servidor desde este árbol.

## Cómo se revierte esta decisión

Dejar de ofrecer la URL de metadata y deshabilitar el vendor. Los RPM de OWASP no se tocan en ese camino.
