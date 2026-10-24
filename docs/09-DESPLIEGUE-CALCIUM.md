# Despliegue en calcium

## Objetivo

Dejar el procedimiento para un piloto, sin haberlo ejecutado desde este repositorio.

## Audiencia

La persona con acceso root al piloto y aprobación para tocarlo.

## Prerrequisitos

- Artefacto publicado: `publish/stable/meta_hostium.yaml` apunta a `hostium-1.1.1.zip`. Ese ZIP trae dos sets, `REQUEST-100-SENSITIVE-FILES.conf` y `REQUEST-410-PHP-UPLOAD-PROGRESS.conf`. `hostium-1.0.0.zip` sigue en el directorio y no se reescribe.
- `package build --version 1.0.0` falla a propósito para no reescribir la distribution ya publicada. `hostium-1.1.0` no se publicó.
- Ventana acordada.
- Un dominio de prueba autorizado, no un sitio de cliente al azar.
- Copia de la salida de solo lectura de antes del cambio.

## Línea base que no revalidamos

La especificación dice que en calcium el motor era `ea-apache24-mod_security2-2.9.15-2.3.1.cpanel`, CRS `3.3.10-1.2.1.cpanel`, vendor OWASP3 enabled, COMODO instalado y deshabilitado, y `httpd -t` en Syntax OK. Esta herramienta no volvió a leer el servidor. Antes de cambiar nada, corré el descubrimiento y compará.

## Antes — solo lectura

En el servidor, no en tu notebook:

```sh
sh scripts/discover-cpanel.sh
sh scripts/check-apache-modsec.sh
```

Guardá la salida fuera del git. Anotá si `httpd -t -D DUMP_INCLUDES` muestra los 33 archivos de OWASP3 y si hay NGINX o Engintron. Si el tráfico no pasa por Apache, el vendor no protege esa URL.

## Alta — producción, modifica, y puede hacer falta recargar Apache

Solo con aprobación, y solo cuando la metadata sea alcanzable por HTTPS:

```sh
/usr/local/cpanel/scripts/modsec_vendor add 'https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml'
```

Esa URL es la metadata de stable. El alta instala el ZIP que esa metadata nombra, hoy `hostium-1.1.1.zip`. Un servidor que ya tiene el vendor no cambia solo por este commit: lo hace `upcp` si las actualizaciones del vendor están activas. Este runbook no ejecutó ese script.

Esa URL es pública. No uses un HTTP ni pegues un PAT en la URL. El alta modifica el piloto y no se ejecutó desde este repositorio.

Después, solo lectura:

```sh
/usr/local/cpanel/scripts/modsec_vendor list
httpd -t
httpd -t -D DUMP_INCLUDES
```

No asumas que el alta recargó Apache. Si la configuración es válida y el include de `hostium` no aparece en el dump, un graceful es un reinicio de servicio y necesita la misma aprobación. No lo dispares desde esta CLI: `deploy apply` está bloqueado.

## Comprobación en un dominio autorizado

1. SOLO LECTURA del estado por dominio en cPanel: ModSecurity puede estar apagado en ese dominio aunque el motor global esté On.
2. Pedí `https://<dominio-de-prueba>/.env`.
3. Esperá 403 y el id `5500100` en el Hits List o en el audit log.
4. Pedí `https://<dominio-de-prueba>/environment`. No tiene que aparecer `5500100`.
5. Un 403 sin ese id no cuenta como éxito de esta regla. Puede ser CRS, NGINX o una regla de la cuenta.

No actives el selftest en este piloto. El archivo no está en el ZIP. Si alguien lo copia a mano, lo saca al terminar y recarga.

## Actualizaciones automáticas

Con el vendor ya instalado, en el servidor, como root:

```sh
/usr/local/cpanel/scripts/modsec_vendor enable-updates hostium
```

Eso modifica el servidor: deja el flag de updates en On. La descarga nueva ocurre cuando corre `/usr/local/cpanel/scripts/upcp`, que relee la metadata del `add`. En la interfaz es la columna Updates del vendor `hostium`, en WHM » Security Center » ModSecurity Vendors.

La página del script, al 8 de julio de 2026, nombra el argumento `enable-updates` y el ejemplo de esa fila usa `enable_updates`. El comando de arriba sigue el nombre del argumento. No se ejecutó en calcium. `hostium-waf updates apply` termina con código 3 y no abre SSH. El mismo texto está en `scripts/enable-hostium-updates.sh`.

Para apagar solo el flag, sin desinstalar el vendor: `modsec_vendor disable-updates hostium`.

## Rollback

`docs/14-ROLLBACK-Y-RECUPERACION.md`. La vía rápida es `modsec_vendor disable hostium`. OWASP3 tiene que seguir enabled. Comprobalo con `list` después.

## Problemas frecuentes

- `vendor add` falla por certificado o por HTTP. No lo reintentes en bucle.
- `duplicate rule id`: hay un choque con un id ya cargado. No fuerces el reload.
- El dominio responde 200 a `/.env` y el include existe: puede haber un proxy cacheando, o ModSecurity desactivado en esa cuenta, o la URL no llega a Apache.

## Referencias

Páginas de `modsec_vendor` y de ModSecurity por dominio, en `docs/REFERENCIAS.md`.

## Limitaciones

Este documento no es una bitácora de un cambio hecho. No hay salida real de calcium adjunta. El inventario `config/fleet.example.yaml` usa `calcium.example.invalid` y no resuelve al piloto. El contraste entre la metadata publicada y la 1.1.0 local está en `docs/21-QA-CPANEL.md`.
