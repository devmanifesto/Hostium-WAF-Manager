# Rollback y recuperación

## Objetivo

Salir de una release mala sin apagar OWASP CRS.

## Audiencia

Quien esté en la ventana del piloto o de la flota.

## Prerrequisitos

La salida de `modsec_vendor list` de antes del cambio, y el ZIP de la release anterior si la vía es versionada.

## Dos vías

### Rápida

1. SOLO LECTURA: `modsec_vendor list`.
2. PRODUCCIÓN / MODIFICA: `/usr/local/cpanel/scripts/modsec_vendor disable hostium`.
3. SOLO LECTURA: `httpd -t`. REINICIA Apache solo si el disable no recargó y la ventana lo permite.
4. SOLO LECTURA: OWASP3 sigue `enabled`. Si no, no fue un rollback de Hostium: repará CRS antes de seguir.

### Versionada

1. Elegí la release anterior cuyo ZIP y metadata ya verificaste. Para salir de la 1.1.0, el artefacto anterior es `publish/stable/hostium-1.0.0.zip`. No lo regeneres desde este árbol: `package build --version 1.0.0` está rechazado.
2. MODIFICA el origen: publicá primero ese ZIP, comprobá el hash bajándolo, y después la metadata. El orden está en el documento 08.
3. Antes de `enable` otra vez, confirmá que una actualización automática no vuelve a traer la versión que acabás de sacar.
4. La grafía `enable-updates` / `enable_updates` no se usa hasta leer la ayuda del binario en ese servidor.

`rollback apply` no hace ninguno de los dos. Termina con código 3.

## RTO

No hay un tiempo medido. No se publica una cifra.

## Verificación

`/.env` en el dominio de prueba deja de mostrar 5500100 después del disable, y un control que solo CRS cubriera sigue comportándose como antes. Si no tenés ese control anotado, no inventes el resultado.

## Deshacer el rollback

Volver a habilitar el vendor reaplica la metadata que WHM tenga como origen. Si esa metadata sigue apuntando a la release mala, la reintroducís. Cambiá la metadata antes, o desactivá las actualizaciones con el subcomando que ese servidor realmente acepte.

## Problemas frecuentes

`disable` deja el vendor instalado y una actualización posterior lo reactiva. Por eso la vía rápida y la versionada no son lo mismo.

## Referencias

Página del script `modsec_vendor`.

## Limitaciones

No se ensayó el disable en calcium. El plan es el procedimiento, no un ensayo registrado.
