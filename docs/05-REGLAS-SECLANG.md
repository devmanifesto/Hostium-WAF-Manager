# Reglas SecLang

## Objetivo

Explicar cómo está escrita la regla productiva y qué no hay que copiar de los borradores.

## Audiencia

Quien edite un `.conf`.

## Prerrequisitos

Manual de ModSecurity 2.x enlazado en `docs/REFERENCIAS.md`. El piloto descrito usa la serie 2.9, no libmodsecurity 3.

## Conceptos que usamos

- La primera línea de cada módulo es `# Reglas complementarias de seguridad administradas por Hostium` y una versión SemVer. En el ZIP, esa versión es la del paquete, no la del motor.
- Fase 1: corre con los encabezados y la ruta, antes del cuerpo. Alcanza para un archivo pedido por URL.
- `t:none` borra las transformaciones por defecto. Las que siguen se aplican en orden: dos `urlDecodeUni`, `htmlEntityDecode`, `lowercase`, `normalizePath`, `removeNulls`.
- `deny,status:403` interrumpe. No es lo mismo que `SecRuleEngine DetectionOnly`, que afecta al motor entero y deja pasar.
- `log-only` en el manifiesto significa `pass` o `log` sin `deny`. Los borradores están en ese modo y, además, no tienen una `SecRule` activa.
- Cada id es una regla, para poder verla sola en el log. La excepción es `5500601`, que usa `chain` porque las dos cabeceras tienen que coincidir juntas.
- El operador es una expresión lineal. No hay cuantificadores anidados del estilo `(a+)+`.

## Regla 5500100

Inspecciona `REQUEST_FILENAME` y `REQUEST_BASENAME`. Coincide con un segmento `.env` o `.env.algo`. No coincide con `/environment`, `/.environment` ni `/my.env`. No mira el query string: `/?next=/.env` queda fuera a propósito para no negar un parámetro legítimo. Ese hueco hay que conocerlo; no está cubierto por esta regla.

## Regla 5500101

Coincide con `/.git/config` y con sufijos como `.git/config.bak`. No coincide con `/.gitignore` ni con `/git/config`.

## Selftest 5500000

`@streq` sobre una cabecera, sin transformaciones. Si el archivo se carga, cualquiera que mande la cabecera obtiene 403. Por eso no va al ZIP.

## Solapamiento con CRS

CRS puede tener controles parecidos. Estas reglas existen para gobernarlas con id propios. No afirmamos que CRS no bloqueara el mismo camino.

## Ejemplo de log que sí cuenta

Un 403 junto con el id `5500100` en el audit log. Un 403 solo no identifica la regla.

## Riesgos

`normalizePath` no convierte `\` en `/` como lo haría `normalizePathWin`. El piloto es Linux. Una barra invertida en la URI queda como limitación documentada, no como un patrón más amplio que genere falsos positivos.

## Verificación

Los casos están en el manifiesto con `ejecucion: automatizada`. La aproximación en Python vive en `tests/unit/test_rutas.py` y no reemplaza al motor.

## Deshacer

Sacá el módulo de la política y publicá una versión nueva. En un servidor ya instalado, deshabilitá el config del vendor o el vendor entero. No edites el archivo dentro de `/etc/apache2/conf.d/modsec_vendor_configs` a mano si WHM lo vuelve a escribir.

## Problemas frecuentes

Un id repetido hace fallar `httpd -t` con duplicate rule id. `rules check-ids` lo busca en el repo. No compara contra los id ya cargados en calcium salvo que le pases un archivo `--installed-ids`.

## Referencias

Manual v2.x y la guía de excepciones de CRS.

## Módulo 1.1.0, PHP upload progress

Ids `5500600`–`5500626`. Los de pedido están en `REQUEST-410-PHP-UPLOAD-PROGRESS.conf` y entran al ZIP 1.1.1. Los de `RESPONSE_BODY` están en el example 411 y no entran. Cubren vectores publicados de CVE-2026-109618 y CVE-2026-109619. No cubren CVE-2026-115560 y no reemplazan PHP 8.2.35, 8.3.36, 8.4.27 u 8.5.12.

Mientras el parche no esté, el aviso de PHP pide `session.upload_progress.enabled=0` en `php.ini` o en el pool, y reiniciar los workers. `ini_set` y `.user.ini` no alcanzan: el parseo ocurre antes.

Decisiones respecto del borrador que llegó con ids `1006101`–`1006126`:

- Esos ids están fuera de `5500000`–`5509999`. No se usan.
- `deny,status:403` en lugar de `block` o `406`, para no depender de `SecDefaultAction`.
- `5500601` es la única `chain`: Content-Type multipart y Transfer-Encoding `chunked` tienen que coincidir juntos.
- `5500600` hace `ctl:forceRequestBodyVariable=On` en multipart. Sin eso `REQUEST_BODY` no se llena y las reglas de cuerpo no ven el ataque. Duplica el cuerpo hasta `SecRequestBodyLimit`. Ese límite no se sube.
- `SecRequestBodyAccess On` está en el conf empaquetado. `SecResponseBodyAccess` no. En cPanel el include del vendor vale para todo el servidor y bufferizar cada respuesta queda fuera del ZIP.
- Las reglas `5500620`, `5500623`, `5500624` y `5500626` están en `REQUEST-411-PHP-UPLOAD-PROGRESS-RESPONSE.conf.example`. No se empaquetan. `RESPONSE_BODY` es fase 4 y no corre si el administrador no enciende el acceso al cuerpo fuera del vendor.
- `5500614` (`<?php` en cualquier cuerpo) hace `pass`. Negarla rompe uploads de PHP, editores y tickets. `5500611` y `5500612` siguen negando los carriers concretos.
- La cookie `PHPSESSID` acepta hasta 256 caracteres, el máximo de `session.sid_length`. El borrador cortaba en 128.
- `5500616` acepta `|O:` además de `|o:`. `O:` es un objeto serializado.

`SecRequestBodyAccess On` está en el `.conf` empaquetado. Si un include posterior lo apaga, las reglas de fase 2 quedan ciegas. Supuesto: el vendor se incluye en la config de Apache.

Señales que no son un crash de PHP, según la taxonomía que acompañaba el borrador: 400, 403, 411, 413, 414, 417, 422, 429 y 431. Un 403 de estas reglas es el WAF, no el worker. 502, 503 o 504 delante de PHP-FPM, o un 500 vacío en mod_php, son otra cosa y estas reglas no los clasifican.

## Limitaciones

No hay regla de WordPress ni de escáneres. Esos archivos siguen marcados INCOMPLETO. El id `5500400` sigue vacío. `apache2ctl configtest` aceptó los dos `.conf` empaquetados en la imagen local `hostium-waf-apache:local`, paquete `modsecurity 2.9.7-1+deb12u2`, Apache/2.4.68 (Debian). No es el RPM de cPanel. Eso es sintaxis. El bloqueo HTTP de los ids PHP no se observó. La aproximación de las expresiones es `tests/unit/test_php_upload_progress.py`. El informe está en `docs/21-QA-CPANEL.md`.
