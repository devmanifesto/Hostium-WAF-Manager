# Publicación HTTPS

## Objetivo

Dejar escrito el orden de una publicación para que una metadata rota no apunte a un ZIP distinto.

## Audiencia

Quien administre el origen desde el que WHM descarga el vendor.

## Prerrequisitos

Un ZIP que ya pasó `package verify`. El origen es `publish/` en este repositorio, servido por `raw.githubusercontent.com`. El repositorio es público.

## Estado real

`publish plan` describe los pasos y no sube nada. `publish apply` sale con código 3. `scripts/publish-local.sh` solo copia a un directorio local.

El origen es el propio repositorio, en `publish/stable/`. Las URL que WHM tiene que poder bajar sin usuario son:

- `https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml`
- `https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/hostium-1.0.0.zip`

El repositorio `devmanifesto/Hostium-WAF-Manager` es público desde el 23 de octubre de 2026. Un GET sin sesión de las dos URL devolvió 200. El ZIP bajado coincide con el del repositorio: 877 bytes, MD5 `3aea69ba720a6508b54999ca5aa42038`. El MD5 y el SHA512 los compara cPanel después de bajar el archivo. Si el repo volviera a privado, `modsec_vendor` recibiría 404: no envía `Authorization`.

## Orden, cuando alguien publique de verdad

1. Subir el ZIP al URL del canal. MODIFICA el origen de archivos, no el cPanel.
2. SOLO LECTURA: bajar ese ZIP y comparar MD5 y SHA512 con la metadata local.
3. Recién entonces publicar `meta_hostium.yaml` en el URL que WHM consulta.
4. Si el proceso se corta antes del paso 3, la metadata anterior sigue apuntando al ZIP anterior.
5. El nombre `hostium-<semver>.zip` es inmutable. No reutilices el nombre con otros bytes. Una caché intermedia tiene que respetar eso o invalidarse antes de cambiar la metadata.

## Canales

`.../main/publish/stable/meta_hostium.yaml` y `.../main/publish/canary/meta_hostium.yaml` serían dos altas distintas en WHM. No es una función nativa de canales. El canary todavía no tiene archivos.

## Firma

MD5 y SHA512 viajan junto con la metadata, así que no prueban quién la escribió. Una firma cosign, minisign o GPG puede verificarse en este pipeline. cPanel no la valida. No digas que WHM la comprueba.

## Backups

Conservá `dist/releases/` o el equivalente en el origen: ZIP, metadata y el `.sha256` propio.

## Verificación

`publish plan --version 1.0.0` con el artefacto presente termina en 0 y dice que no subió archivos. Sin artefacto termina en 1.

## Deshacer

Volver a publicar la metadata de la release anterior, después de comprobar su ZIP. No borres el ZIP viejo mientras algún servidor pueda estar a mitad de una actualización.

## Problemas frecuentes

Publicar la metadata primero. Un cPanel que actualice en ese hueco baja un ZIP que no coincide o un 404.

## Referencias

Tutorial de vendor. El script `update` de `modsec_vendor` usa la URL con la que se instaló el vendor.

## Limitaciones

GitHub pone el certificado. No hay allowlist de las IP de los cPanel. El archivo en `publish/stable/` no debe reescribirse con otros bytes para el mismo nombre `hostium-1.0.0.zip`. Cuentas de clientes de cPanel no tienen que poder cambiar ese archivo.
