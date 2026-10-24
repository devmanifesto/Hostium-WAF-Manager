# Pruebas y validación

## Objetivo

Decir qué se corrió, qué se omitió y qué no prueba protección en un cPanel.

## Audiencia

Quien lea el estado de la 1.0.0.

## Prerrequisitos

El entorno de `docs/04-INSTALACION-DESARROLLO.md`.

## Cómo correrlas

```powershell
python -m ruff check src tests
python -m pytest
python -m pytest -m integration --override-ini="addopts=" -rs
python -m hostium_waf package build --version 1.1.1 --engine 2.9.15
python -m hostium_waf package verify --zip dist/hostium-1.1.1.zip --metadata dist/meta_hostium.yaml
```

`package build --version 1.0.0` en este árbol termina en error. La 1.0.0 publicada no se reconstruye.

La primera línea es lint. La segunda es la suite unitaria y excluye la marca `integration`. La tercera construye Apache si el demonio de Docker responde.

## Qué cubre cada nivel

- Unitarias: esquema, ids, ZIP malicioso, hashes, determinismo, CLI, flota de ejemplo sin SSH.
- `tests/unit/test_rutas.py`: aproximación Python de la expresión. No es ModSecurity.
- `tests/ftw/sensitive-files.yaml`: casos en un formato parecido a go-ftw. El runner no es el binario go-ftw.
- Integración: Apache con el paquete Debian de ModSecurity, y un segundo caso con la imagen `owasp/modsecurity-crs:3.3.10-apache-202610180210-lts` si descarga. En un positivo, el id de Hostium tiene que aparecer asociado a esa URI. En un negativo, ese id no puede aparecer en esa URI; un 403 de otra regla no falla el caso.

## Reglas 5500600–5500626

La corrida de abajo es la de los ids `5500100` y `5500101`. Los ids de PHP upload progress no están en esa tabla. Los de fase 4 no entran al ZIP. Su control automático es `tests/unit/test_php_upload_progress.py`, que aplica las expresiones en Python. El `configtest` del conf empaquetado está en `tests/integration/test_http.py` y se omite si Docker no está. No hubo un POST de prueba ni un 403 observado para esos ids, y `ultima_validacion` sigue vacía. El informe de cPanel está en `docs/21-QA-CPANEL.md`.

## Resultado de la corrida de cierre

Corrida en esta máquina el 23 de octubre de 2026. La bitácora UTC del contenedor CRS de una corrida anterior cayó ya en el 24. Si esta sección y una corrida nueva no coinciden, manda la salida nueva.

Herramientas impresas por los comandos: Python 3.14.4, ruff 0.17.2, pytest 9.1.1. Docker Server 29.4.2.

```text
python -m ruff check src tests
All checks passed!

python -m pytest --tb=line -q
31 passed, 3 deselected, 1 warning in 0.70s
```

El aviso es de `zipfile`: el caso que arma un ZIP con dos entradas del mismo nombre imprime `Duplicate name: 'hostium/doble.conf'`. La prueba igual rechaza ese ZIP.

```text
python -m pytest -m integration --override-ini="addopts=" -rs --tb=line -q
3 passed, 31 deselected in 27.66s
```

`reports/integracion-estado.txt` quedó en `ejecutada`. Los informes de esa corrida son `reports/integracion-sin-crs.json`, `reports/integracion-laboratorio.json` y `reports/integracion-con-crs.json`. Esos archivos están en `.gitignore`; los números de abajo son la copia de esa salida.

Perfil sin CRS, imagen local `hostium-waf-apache:local` construida desde `debian:bookworm-slim`. `reports/modsec-version.txt`:

```text
modsecurity 2.9.7-1+deb12u2
Server version: Apache/2.4.68 (Debian)
Server built:   2026-06-12T05:08:45
```

Eso no es el RPM `ea-apache24-mod_security2-2.9.15-2.3.1.cpanel`. Los positivos devolvieron 403 y el log asoció el id a esa URI. Los negativos devolvieron 404 y el id no apareció en esa URI.

| Regla | Ruta | HTTP | Id en el log de esa URI | ms |
| --- | --- | ---: | --- | ---: |
| 5500100 | `/.env` | 403 | sí | 2.0 |
| 5500100 | `/.env.local` | 403 | sí | 15.7 |
| 5500100 | `/app/.env` | 403 | sí | 2.2 |
| 5500100 | `/.ENV` | 403 | sí | 1.8 |
| 5500100 | `/foo/../.env` | 403 | sí | 2.8 |
| 5500100 | `/environment` | 404 | no | 26.6 |
| 5500100 | `/.environment` | 404 | no | 22.3 |
| 5500100 | `/assets/env.js` | 404 | no | 19.1 |
| 5500100 | `/my.env` | 404 | no | 2.0 |
| 5500100 | `/wp-login.php` | 404 | no | 1.9 |
| 5500101 | `/.git/config` | 403 | sí | 2.3 |
| 5500101 | `/.git/config.bak` | 403 | sí | 2.0 |
| 5500101 | `/app/.git/config` | 403 | sí | 23.0 |
| 5500101 | `/git/config` | 404 | no | 2.0 |
| 5500101 | `/.gitignore` | 404 | no | 2.0 |
| 5500101 | `/blog/post` | 404 | no | 22.9 |

Selftest, solo con el ejemplo montado a mano en ese mismo Apache. Sin el archivo, la cabecera `X-Hostium-Selftest` no produjo el id 5500000. Con el archivo cargado:

| Caso | HTTP | Id 5500000 en esa URI | ms |
| --- | ---: | --- | ---: |
| cabecera de laboratorio | 403 | sí | 2.8 |
| sin cabecera | 200 | no | 2.1 |

Perfil CRS. Imagen `owasp/modsecurity-crs:3.3.10-apache-202610180210-lts` con digest `sha256:98fb77754c674c235b05ed7883974d7dea6f1ab9ff4ae0f08fd40456ba9d2aec`, fijado en `docker/crs-image.txt` y en `docker/compose.yaml`. `apachectl -v` imprimió `Apache/2.4.69 (Unix)`, compilado el 6 de octubre de 2026. `dpkg` y `rpm` no imprimieron un paquete. En `/usr/local/apache2/modules/mod_security2.so` aparecen las cadenas `ModSecurity-2.9.15/apache2` y también `2.9.14`. No es el RPM de cPanel. El backend de la imagen apunta a `127.0.0.1:9`, así que una petición que nadie bloquea termina en 503.

Los positivos volvieron a ser 403 con el id de Hostium. `/.environment` y `/.gitignore` fueron 403 sin los ids 5500100 ni 5500101: el criterio de la prueba es la ausencia de nuestro id, no que CRS deje pasar el punto-archivo. El informe exitoso no guarda qué id de CRS escribió ese 403.

| Regla | Ruta | HTTP | Id de Hostium en esa URI | ms |
| --- | --- | ---: | --- | ---: |
| 5500100 | `/.env` | 403 | sí | 2.1 |
| 5500100 | `/.env.local` | 403 | sí | 2.6 |
| 5500100 | `/app/.env` | 403 | sí | 2.0 |
| 5500100 | `/.ENV` | 403 | sí | 2.0 |
| 5500100 | `/foo/../.env` | 403 | sí | 1.9 |
| 5500100 | `/environment` | 503 | no | 4.6 |
| 5500100 | `/.environment` | 403 | no | 3.1 |
| 5500100 | `/assets/env.js` | 503 | no | 4.8 |
| 5500100 | `/my.env` | 503 | no | 22.7 |
| 5500100 | `/wp-login.php` | 503 | no | 3.4 |
| 5500101 | `/.git/config` | 403 | sí | 20.8 |
| 5500101 | `/.git/config.bak` | 403 | sí | 2.0 |
| 5500101 | `/app/.git/config` | 403 | sí | 2.0 |
| 5500101 | `/git/config` | 503 | no | 28.0 |
| 5500101 | `/.gitignore` | 403 | no | 15.7 |
| 5500101 | `/blog/post` | 503 | no | 4.0 |

Dos `package build --version 1.0.0 --engine 2.9.15` seguidos escribieron el mismo ZIP de 877 bytes y `package verify` respondió `ok: true`. Hashes releídos del archivo:

- MD5 `3aea69ba720a6508b54999ca5aa42038`
- SHA-512 `fdd1aafb8c37953451561f83a8f13a229b6ba62252a5774261e70fe0f9314f48da3afdb501003bd1bcdef23820c141e51168836359f2fa4285f686b29fae7d56`
- SHA-256 `657ad987ae9cf236ced5d31825ebc4870acd316472e47e80aa9581c2bc076012`

En esa corrida la URL del metadata era `https://waf.hostium.com/stable/hostium-1.0.0.zip`, de diseño y sin host. El único archivo dentro del ZIP es `hostium/REQUEST-100-SENSITIVE-FILES.conf`. Después, el 23 de octubre de 2026, la URL pasó al raw de `devmanifesto/Hostium-WAF-Manager` sin cambiar los bytes del ZIP.

Barrido del árbol versionado: no apareció un bloque `BEGIN PRIVATE KEY` ni una clave `AKIA` de 16 caracteres. La cadena `StrictHostKeyChecking=no` solo está en la prohibición de la documentación, en la especificación y en las pruebas que exigen que el cliente SSH no la use. `ultima_validacion` de las reglas sigue en null.

Pasada de QA posterior, el mismo 23 de octubre de 2026: `python -m ruff check src tests` sin hallazgos, `python -m pytest` 35 pasadas y 3 deseleccionadas en 0,68 s, e integración otra vez 3 pasadas en 27,46 s. Los informes `reports/integracion-*.json` de esa corrida son JSON. El ZIP no cambió de bytes: mismos MD5 y SHA-256 de arriba. Las tablas de milisegundos corresponden a la corrida anterior del mismo día, no a esta repetición.

## Qué no está probado en cPanel

- `modsec_vendor add` y el orden real de `DUMP_INCLUDES`.
- La grafía de updates automáticos.
- Un 403 con id 5500100 contra un dominio del piloto.
- Que NGINX o un CDN no sirvan `/.env` sin pasar por Apache.
- Que el ModSecurity de Debian sea idéntico al RPM 2.9.15 de EasyApache. La imagen local imprime su versión de paquete en `reports/modsec-version.txt` solo si el contenedor arrancó.

## Verificación de un falso éxito

Si la integración dice `skipped` o `omitida`, no la cuentes como bloqueo comprobado. `reports/integracion-estado.txt` guarda `omitida` o `ejecutada`.

## Deshacer

Las pruebas escriben en `dist/` solo si llamás al build, y en `reports/` al informar. Esos directorios están en `.gitignore`.

## Problemas frecuentes

Docker Desktop instalado y el comando `docker info` en error: la integración se omite en un segundo. Arrancá el demonio y repetí. No rellenes el resultado a mano.

## Referencias

`docs/11` es este archivo. La matriz de la especificación está en su sección 12.

## Limitaciones

No hay porcentaje de cobertura. No se inventa.
