# QA en tres pasadas

## Objetivo

Contrastar el artefacto que WHM instalaría, leer las reglas como ataque y como sitio legítimo, y copiar lo que esta máquina ejecutó.

## Audiencia

Quien ya leyó `docs/21-QA-CPANEL.md` y quiere la corrida del 24 de octubre de 2026.

## Fecha

24 de octubre de 2026. No se tocó calcium. No se reescribió `publish/stable/hostium-1.1.1.zip` ni `hostium-1.0.0.zip`. `ultima_validacion` sigue vacía.

## Pasada 1 — contrato

Método: hashes y texto del ZIP publicado, sin reconstruirlo.

| Dato | Valor |
| --- | --- |
| Bytes | 3801 |
| MD5 | `2152c044ed3130af11ad0c6cd69c7ea4` |
| SHA-512 | `9df106145e7c9935ae509de686af31fd64b68bbe7f733ec71c892db53cf47fa7c123e342188824c54370d2898ea7fff07e3bd4490873d22f78ef034c359da050`, igual al de la metadata |
| SHA-256 | `a4b6565087fcd76348c9b025f1a2547744f072de0caaa968ba98702be6e35caa`, igual al sidecar `hostium-1.1.1.sha256` |
| `distribution` | `hostium-1.1.1` |
| URL | `https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/hostium-1.1.1.zip` |
| `attributes.description` | `Reglas complementarias de seguridad administradas por Hostium 1.1.1` |

Entradas del ZIP: `hostium/`, `hostium/REQUEST-100-SENSITIVE-FILES.conf`, `hostium/REQUEST-410-PHP-UPLOAD-PROGRESS.conf`. La primera línea de los dos `.conf` es la frase de `attributes.description` con `#`. El cuerpo de cada archivo, de la segunda línea en adelante, es igual al del árbol. En el árbol la primera línea dice `1.0.0` y `1.1.0`: el build la reescribe al empaquetar.

`config/policy.example.yaml` habilita `REQUEST-100-SENSITIVE-FILES` y `REQUEST-410-PHP-UPLOAD-PROGRESS`. Esos dos módulos son los dos `.conf`. Hay 20 reglas con `incluir_en_paquete: true`. Las 20 están en el ZIP, con la misma fase y la misma acción que el manifiesto. Ningún id de los `.example` está en el ZIP.

Fuera del paquete: `5500000`, `5500200`, `5500300`, `5500400`, `5500500`, `5500620`, `5500623`, `5500624`, `5500626`.

`hostium-1.0.0.zip` sigue en 877 bytes, MD5 `3aea69ba720a6508b54999ca5aa42038`, SHA-256 `657ad987ae9cf236ced5d31825ebc4870acd316472e47e80aa9581c2bc076012`.

`publish/stable/hostium-1.1.0.zip` está en el directorio (3737 bytes). La metadata no lo nombra. Su primera línea no es la frase fija del módulo. `SecResponseBodyAccess` aparece en un comentario. No hay `phase:4` ni los ids `5500620` y `5500626`.

El validador exige que el id esté en el archivo y que la palabra `deny` aparezca en algún lado si el modo es deny. No compara el `phase:` de cada bloque con `fase` del manifiesto. En esta lectura las 20 coincidieron igual.

`python -m hostium_waf version` imprime `hostium-waf 1.0.0`. Es la versión de la herramienta, la que ya declara `docs/17-API-CLI-Y-CONFIGURACION.md`. El ruleset de stable es `1.1.1`.

## Pasada 2 — adversario

Método: la expresión del ZIP, aplicada en Python, y la variable que la regla declara. Python no es ModSecurity. Los cinco riesgos ya escritos en el documento 21 (`5500601`, `5500613`, `5500614`, `5500617`, `5500600`) no se reescriben acá.

Huecos que la expresión deja pasar, y que el test de unidad no fija:

- `5500602` no coincide con saltos solo `\n`, ni con un valor de 257 caracteres, ni con un espacio antes de los dos puntos. El test manda `\r\n` y un valor corto.
- `5500603` no cuenta un corchete cuyo interior mide 33 caracteres, ni un nombre base de 65 caracteres. El test usa `[0]`.
- `5500611` no coincide con una cadena serializada de PHP `s:1:"abc";` ni con `C:8:"stdClass":0:{}`. El test da por bueno `s:1:{`, que no es una cadena de PHP.
- `5500612` no ve `<?php` si hay 513 caracteres entre `filename="` y la carga. El test la pone al inicio.
- `5500613` es `@streq PHPSESSID`. `PHPSESSID[0]` no es ese texto. El test compara strings de Python, no el nombre que arma ModSecurity.
- `5500615` exige `form-data;` pegado. `form-data ;` quinientas veces no coincide.
- `5500622` coincide con `/tmp/sess_` seguido de 6 caracteres en cualquier parte del argumento. Un texto de soporte que pegue esa ruta cae. El test solo mira rutas enteras.
- `5500625` es `@contains` con esa grafía. `P2S_8512_SHELL.PHP` no está en el test.
- `tests/unit/test_rutas.py` saca el byte nulo antes de normalizar. En el `.conf` el orden es al revés, y el test no elige entre `REQUEST_FILENAME`, `REQUEST_BASENAME` y `PATH_INFO`.

Esas expresiones no se cambiaron. Un cambio de expresión, fase o acción sería otra distribution.

## Pasada 3 — caja negra

Herramientas: Python 3.14.4, ruff 0.17.2, pytest 9.1.1. Docker Server 29.4.2.

```text
python -m ruff check src tests
All checks passed!

python -m pytest --tb=line -q
66 passed, 4 deselected, 1 warning in 1.85s
```

El aviso es el de `zipfile` en `test_rechaza_traversal_symlink_y_raiz`: `Duplicate name: 'hostium/doble.conf'`. La prueba igual rechaza ese ZIP. Los 4 deseleccionados son la marca `integration`. Esa suite no se corrió en esta pasada.

```text
python -m hostium_waf package verify --zip publish/stable/hostium-1.1.1.zip --metadata publish/stable/meta_hostium.yaml
paquete verificado

python -m hostium_waf rules check-ids
IDs dentro de 5500000-5509999. Colisión con instalados: no_comprobado.

python -m hostium_waf doctor --local
doctor local: sin hallazgos
herramientas: docker=sí, git=sí, ssh=no, make=no

python -m hostium_waf package build --version 1.0.0 --engine 2.9.15
No se construye hostium-1.0.0: el paquete incluye reglas introducidas en 1.1.0. No se reutiliza una distribution ya publicada para otro contenido.
```

El build de `1.0.0` terminó con código 1. `verify`, `check-ids`, `doctor` y `version` no llaman a `fleet` por SSH. `doctor` además imprimió `ssh=no`.

`check-ids` no recibió `--installed-ids`. El choque con OWASP3 o COMODO del servidor sigue sin comprobar.

Apache de la imagen `hostium-waf-apache:local`, ya construida. `cat /etc/hostium-modsec-version.txt`:

```text
modsecurity 2.9.7-1+deb12u2
Server version: Apache/2.4.68 (Debian)
Server built:   2026-06-12T05:08:45
```

El arranque también imprimió `ModSecurity for Apache/2.9.7` y `PCRE2` `10.42`. El comentario de `5500618` supone PCRE1. No se envió un filename de 65535 caracteres. Este Apache no es el RPM `ea-apache24-mod_security2` de cPanel.

Los dos `.conf` salieron del ZIP 1.1.1 y se montaron solo lectura. `apache2ctl configtest` imprimió `Syntax OK` y código 0. El example de fase 4 no se montó. El contenedor se borró al terminar.

La imagen deja `SecRequestBodyAccess Off` y después incluye esos `.conf`, que lo encienden. Un POST con campo `PHPSESSID` llegó a fase 2, así que el cuerpo se parseó.

| Pedido | HTTP | Qué escribió el log de esa petición |
| --- | ---: | --- |
| `GET /.env` | 403 | `5500100` en fase 1, sobre `REQUEST_FILENAME` |
| `GET` sin cookie | 404 | ningún id |
| `GET` con `Cookie: PHPSESSID=_` | 403 | `5500621` en fase 1 |
| `POST` multipart, campo `PHPSESSID` | 403 | `5500613` en fase 2, `ARGS_NAMES:PHPSESSID` |
| `POST` multipart, campo `PHPSESSID[0]` | 404 | ningún id |
| `POST` multipart, campo `titulo` | 404 | ningún id |
| `POST` multipart con `<?php` en el valor | 404 | ningún id, tampoco `5500614` |
| `POST` con 100 líneas `\r\nX-Pad: a` | 404 | ningún id, tampoco `5500602` |
| `POST` con 100 líneas `\nX-Pad: a` | 404 | ningún id |
| `POST /p2s_8512_shell.php` con `Content-Length: 0` | 403 | `5500625` en fase 2, sobre `REQUEST_URI` |
| `POST /P2S_8512_SHELL.PHP` con `Content-Length: 0` | 404 | ningún id |
| `POST` multipart con `Transfer-Encoding: chunked` | 403 | fase 1, el patrón `chunked` de la cadena de `5500601` sobre `REQUEST_HEADERS` |

Una regla temporal, fuera del ZIP y borrada con el contenedor, vio el header `multipart/form-data; boundary=----hostiumqa` y coincidió con la misma expresión de `5500600`. Otra, `id:19`, fase 2, `@rx .` sobre `REQUEST_BODY`, no escribió. En este Apache `REQUEST_BODY` llegó vacío a fase 2. Las reglas que solo miran esa variable no tuvieron blanco. Las que miran `ARGS` sí.

No se envió tráfico de `5500101`, `5500603`, `5500604`, `5500605`, `5500611`, `5500612`, `5500615`, `5500616`, `5500617`, `5500618`, `5500619` ni `5500622`. No hubo `Set-Cookie` de PHP que pudiera disparar `5500617`.

## Cruce

- El ZIP, la metadata, la política y el manifiesto coinciden. La deriva estaba en los docs: `docs/11` decía 31 pasadas y un lector de la 1.0.0; `docs/21` decía 59 pasadas. Esta corrida imprimió 66 pasadas y 4 deseleccionadas.
- `5500613` y `5500625` fallan por un nombre distinto del texto exacto. La expresión ya lo decía. Este Apache lo confirmó con 404 y sin id.
- `5500621` no corre si la cookie no viene. El test de Python trata la cadena vacía como inválida. Este Apache, sin cookie, respondió 404.
- `5500602` y `5500614` dependen de `REQUEST_BODY`. La expresión Python coincide con el caso CRLF y con `<?php`. Este Apache no escribió esas reglas. El comentario de `5500600` dice que el `ctl` llena `REQUEST_BODY`. Acá el header multipart coincidió y la variable siguió vacía.
- `5500601` sí negó el chunked en este Apache. La hipótesis de que Apache siempre borra `Transfer-Encoding` antes de fase 1 no se cumplió en esta imagen.

## Qué se corrigió

Docs que esta corrida dejaba atrás: la audiencia y el conteo de `docs/11-PRUEBAS-Y-VALIDACION.md`, la frase de `hostium-1.1.0` en `docs/09-DESPLIEGUE-CALCIUM.md`, la release de salida en `docs/14-ROLLBACK-Y-RECUPERACION.md`, la frase de pedidos PHP en `docs/16-COMPATIBILIDAD-Y-MATRIZ.md` y el enlace desde `docs/21-QA-CPANEL.md`. No cambió ningún `SecRule`, ni la fase, ni la acción, ni un id empaquetado.

## Qué queda anotado

Un arreglo de `REQUEST_BODY`, de `PHPSESSID[0]`, de la grafía del webshell o de las expresiones de arriba sería `1.1.2` o mayor. Este informe no empaqueta eso.

Sigue sin hacerse en cPanel: `modsec_vendor`, `httpd -t`, `DUMP_INCLUDES`, Hits List, choque de ids contra el OWASP3 instalado, `upcp`, `enable-updates`, `deploy apply` y `rollback apply`.

## Referencias

`docs/21-QA-CPANEL.md`, `docs/11-PRUEBAS-Y-VALIDACION.md`, `docs/05-REGLAS-SECLANG.md`.
