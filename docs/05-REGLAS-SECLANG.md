# Reglas SecLang

## Objetivo

Explicar cómo está escrita la regla productiva y qué no hay que copiar de los borradores.

## Audiencia

Quien edite un `.conf`.

## Prerrequisitos

Manual de ModSecurity 2.x enlazado en `docs/REFERENCIAS.md`. El piloto descrito usa la serie 2.9, no libmodsecurity 3.

## Conceptos que usamos

- Fase 1: corre con los encabezados y la ruta, antes del cuerpo. Alcanza para un archivo pedido por URL.
- `t:none` borra las transformaciones por defecto. Las que siguen se aplican en orden: dos `urlDecodeUni`, `htmlEntityDecode`, `lowercase`, `normalizePath`, `removeNulls`.
- `deny,status:403` interrumpe. No es lo mismo que `SecRuleEngine DetectionOnly`, que afecta al motor entero y deja pasar.
- `log-only` en el manifiesto significa `pass` o `log` sin `deny`. Los borradores están en ese modo y, además, no tienen una `SecRule` activa.
- No usamos `chain`. Cada id es una regla, para poder verla sola en el log.
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

## Limitaciones

No hay regla de cuerpo, ni de WordPress, ni de CVE. Esos archivos son comentarios marcados INCOMPLETO.
