# Requerimientos

## Objetivo

Trazar lo que la 1.0.0 cumple y lo que queda explícitamente bloqueado.

## Audiencia

Quien acepte o rechace el MVP.

## Prerrequisitos

La especificación maestra del 23 de octubre de 2026.

## Funcionales

| Id | Requerimiento | Prioridad | Estado en el repo |
| --- | --- | --- | --- |
| F1 | CLI instalable | P0 | Cumplido con `pyproject.toml` |
| F2 | Regla original de archivos secretos con casos | P0 | 5500100 y 5500101 |
| F3 | Selftest fuera del ZIP estable | P0 | `.example`, id 5500000 |
| F4 | ZIP con raíz `hostium/` y metadata con MD5 y SHA512 | P0 | `package build` / `verify` |
| F5 | Rechazo de ZIP peligroso y metadata rota | P0 | `inspect_zip` y `validar_metadata` |
| F6 | Auditoría de flota sin escritura | P1 | `fleet audit`, SSH solo con backend explícito |
| F7 | Apply de deploy, rollback y publicación | P1 | Bloqueado, código 3 |
| F8 | Prueba HTTP con el id en el log | P1 | Implementada; corre si Docker está en marcha |

## No funcionales

- Operación remota modificadora en dry-run y, en v1, ni siquiera habilitada con `--approve`.
- Sin secretos en el árbol. El inventario no tiene campo de contraseña.
- Documentación en español.
- Builds repetidos del mismo contenido producen el mismo ZIP.

## Trazabilidad

Cada regla del manifiesto apunta a un archivo, un id y casos. El empaquetador solo incluye las que están en producción, en un módulo habilitado y en un `.conf` que no sea example.

## Verificación

`python -m pytest` y `python -m ruff check src tests`. El resultado de la corrida de cierre está en `docs/11-PRUEBAS-Y-VALIDACION.md`.

## Deshacer

Revertir el commit. No hay migración de datos.

## Problemas frecuentes

Confundir la versión del motor (`2.9.15`) con la del ruleset (`1.0.0`) o con la del RPM de CRS (`3.3.10` en el piloto, según la línea base de la especificación).

## Referencias

`docs/ESPECIFICACION_MAESTRA.md`, secciones 9 y 17.

## Limitaciones

F8 no se declara cumplido en calcium. F7 no se va a simular.
