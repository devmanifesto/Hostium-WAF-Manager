# Seguridad y modelo de amenazas

## Objetivo

Nombrar cómo se puede envenenar el ruleset o la flota, y qué hace la 1.0.0 frente a eso.

## Audiencia

Quien revise el pipeline antes de apuntar un cPanel a una URL.

## Prerrequisitos

El contrato del documento 07 y el de publicación del 08.

## Amenazas

| Amenaza | Qué pasaría | Qué hay hoy |
| --- | --- | --- |
| ZIP con `../` o symlink | Escribe fuera del directorio del vendor al extraer | `inspect_zip` lo rechaza antes de dar el paquete por bueno |
| Metadata que no coincide con el ZIP | WHM instala otro contenido del que creemos | `package verify` compara MD5 y SHA512 del archivo releído |
| MITM o publicador comprometido | El hash viaja en la misma metadata | No hay firma que WHM compruebe. La URL tiene que ser HTTPS. La confianza es el control del host de publicación |
| CI con un secreto | Filtración | No hay secretos en el workflow. El release solo sube un artefacto a la corrida de GitHub Actions |
| SSH con host key ignorada | Suplantación del servidor | `StrictHostKeyChecking=yes` fijo. Los `.invalid` no se marcan |
| Comando armado desde el inventario | Ejecución arbitraria | La lista de comandos es constante. Un campo extra en el YAML falla la validación |
| Regla `allow` amplia | Se abre CRS | El `.conf` empaquetable no puede contener esa acción |
| Log de auditoría en git | Datos de clientes | `report generate` no los copia. `.gitignore` deja fuera `reports/` |

## Verificación

`tests/unit/test_seguridad.py` y `tests/unit/test_empaquetado.py`. Buscá en el árbol versionado `AKIA` seguido de 16 caracteres y bloques `BEGIN PRIVATE KEY`. No tienen que aparecer.

## Deshacer

Si un artefacto malo se llegó a publicar, rollback del documento 14 y rotación de la credencial que escribió en el origen. Si una clave SSH se usó desde una máquina dudosa, sacala de `authorized_keys` en la ventana de operación, no desde esta CLI.

## Problemas frecuentes

Confiar en el MD5 de la metadata como si fuera una firma. No lo es.

## Referencias

Tutorial de vendor y `SECURITY.md`.

## Limitaciones

No hay modelo formal más allá de esta tabla. No se simuló un WHM bajando un ZIP malicioso: el rechazo es local, sobre el archivo, antes de ofrecerlo.
