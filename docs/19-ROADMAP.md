# Roadmap

## Objetivo

Ordenar lo que falta después del MVP sin presentarlo como hecho.

## Audiencia

Quien priorice el siguiente incremento.

## Prerrequisitos

La 1.0.0 descrita en el documento 03.

## P0 — para poder hablar de piloto

- Publicar de verdad un origen HTTPS y sustituir la URL de diseño.
- Correr `modsec_vendor add` en un laboratorio, no en calcium, y guardar `httpd -t` y `DUMP_INCLUDES`.
- El comando de actualizaciones es `modsec_vendor enable-updates hostium`. La documentación del 8 de julio de 2026 también muestra `enable_updates` en un ejemplo. `updates plan` emite la grafía con guion. `updates apply` no abre SSH y no se ejecutó en calcium.
- Ver un 403 con id 5500100 en un dominio de prueba autorizado, y la ausencia de ese id en `/environment`.
- La versión del contenedor Debian ya está anotada en `docs/11`: `modsecurity 2.9.7-1+deb12u2`, distinta del RPM `2.9.15` del piloto. Eso no cierra el P0.

## P1 — para una flota chica

- `deploy apply` solo cuando haya captura del estado previo, apply ensayado, verificación y rollback ensayado. Hasta entonces el código 3 se queda.
- Usuario SSH de solo lectura, en lugar de root, cuando el sudoers exista.
- Firma externa verificada por este pipeline, sin decir que cPanel la usa.
- Excepciones de WordPress con casos de login, REST y checkout, todavía en borrador hasta tener esa evidencia.

## P2 — después

- CRS 4 y ModSecurity 3, cada uno con su clave de motor y sus pruebas.
- Panel, RBAC y métricas en Prometheus.
- Virtual patch de un CVE probado en el motor del piloto. La 1.1.0 trae expresiones para CVE-2026-109618 y CVE-2026-109619, con aproximación en Python y sin corrida de ModSecurity. El id 5500400 sigue vacío. Actualizar PHP sigue siendo el arreglo.

## Criterio para subir de fase

P0 no se marca cumplido con una suite unitaria verde. Hace falta la salida del servidor, guardada fuera del git, y un id observado.

## Deshacer

Cada ítem se puede no hacer. El vendor se deshabilita con el documento 14.

## Problemas frecuentes

Anotar un P2 como compromiso de fecha. Esta lista no tiene fechas.

## Referencias

`docs/ESPECIFICACION_MAESTRA.md`, sección 19 del propio roadmap de la especificación, y este archivo.

## Limitaciones

No hay estimación de esfuerzo.
