# Publicación HTTPS

## Objetivo

Dejar escrito el orden de una publicación para que una metadata rota no apunte a un ZIP distinto.

## Audiencia

Quien administre el origen desde el que WHM descarga el vendor.

## Prerrequisitos

Un ZIP que ya pasó `package verify`. Un host HTTPS que este repositorio no crea. Certificado vigente, acceso de escritura acotado y, si se puede, allowlist de las IP de los cPanel.

## Estado real

`publish plan` describe los pasos y no sube nada. `publish apply` sale con código 3. `scripts/publish-local.sh` solo copia a un directorio local.

`waf.hostium.com` no está provisionado por este proyecto.

## Orden, cuando alguien publique de verdad

1. Subir el ZIP al URL del canal. MODIFICA el origen de archivos, no el cPanel.
2. SOLO LECTURA: bajar ese ZIP y comparar MD5 y SHA512 con la metadata local.
3. Recién entonces publicar `meta_hostium.yaml` en el URL que WHM consulta.
4. Si el proceso se corta antes del paso 3, la metadata anterior sigue apuntando al ZIP anterior.
5. El nombre `hostium-<semver>.zip` es inmutable. No reutilices el nombre con otros bytes. Una caché intermedia tiene que respetar eso o invalidarse antes de cambiar la metadata.

## Canales

`https://waf.hostium.com/stable/meta_hostium.yaml` y `https://waf.hostium.com/canary/meta_hostium.yaml` serían dos altas distintas en WHM. No es una función nativa de canales.

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

No hay allowlist, certificado ni log de acceso del publicador porque el host no existe en este repositorio. El endpoint no debe quedar escribible por cuentas de clientes de cPanel; eso se diseña en el servidor de archivos, no en el ZIP.
