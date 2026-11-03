# Changelog

## 2.1.0 — 2026-11-02

`hostium-2.1.0` suma `REQUEST-900-CRS-EXCLUSIONS.conf`. Los ids de `REQUEST-410` conservan id, fase y acción. `5500900`, `5500901` y `5500902` son `SecAction` de fase 1, sin URI: sacan `ARGS:firmadatos` de 941130 y 941170, `ARGS:vseleccionados` de 942100, y `ARGS:emailglobalheader` más `ARGS:emailglobalfooter` de los tags `attack-xss` y `attack-rce`. `5500903` saca `ARGS` de 941160 cuando la URI contiene `/sell/catalog/`. `5500904` saca `ARGS:datos` de 933170 en el turnero. No hay `/login` ni directorio de admin.

El bajado de puntaje es el vendor `hostium-tune`, distribution `hostium-tune-2.1.0`. Cada `SecRuleUpdateActionById` resta el anomaly score crítico y suma el warning de 911, 922, 932, 934 y 944. Neto 3. Una 922130 no llega a 5. Dos reglas de esos archivos suman 6. El RPM de cPanel no se diffé. Si `hostium-tune` se incluye antes de OWASP3, `httpd -t` falla.

`publish/stable/meta_hostium.yaml` pasa a `hostium-2.1.0`. `meta_hostium-tune.yaml` apunta al ZIP de puntaje. No se reescribe `hostium-2.0.0.zip`. `ultima_validacion` sigue vacía. No se ejecutó `upcp`, `modsec_vendor` ni `httpd -t`. WHM cuenta dos sets en hostium.

## 2.0.0 — 2026-11-02

Sale del ZIP `REQUEST-100-SENSITIVE-FILES.conf`. `5500100` y `5500101` quedan en el repo con estado retirado. CRS 3.3.10, regla `930130`, PL1, ya pone score crítico 5 sobre las frases `/.env` y `/.git/` de `restricted-files.data`, y el umbral de `949110` es 5. El cruce es contra el tag upstream `v3.3.10`. No se releyó el `restricted-files.data` del RPM en un servidor.

`5500608` deja de contar cada `Content-Disposition: form-data`. Suma una parte sin `filename` y sin `name` no vacío. `5500615` sigue en fase 2, `deny,status:403`, corte `@ge 500` sobre ese contador. Un formulario de 800 campos con nombre no incrementa `TX:hostium_parts`. El 500 de `hostium-1.1.2` cortó un POST real de 723 campos el 2026-11-02. `5500611` deja de negar `<?php` y `<?=`: ese byte en `ARGS` lo suma `933100`. Quedan las semillas que `933170` no mata.

`publish/stable/meta_hostium.yaml` pasa a `hostium-2.0.0`. No se reescriben los ZIP anteriores. `ultima_validacion` sigue vacía. No se ejecutó `upcp` ni `modsec_vendor`. El ZIP trae un solo set, `REQUEST-410-PHP-UPLOAD-PROGRESS.conf`.

## 1.1.2 — 2026-10-24

En ModSecurity 2, `REQUEST_BODY` queda vacío cuando el procesador ya es MULTIPART. `5500600` se conserva y no niega. Entran `5500606`, `5500607` y `5500608`: cuentan cabeceras `X-` de parte, filenames vacíos y partes `form-data`. Siguen negando, con la misma fase, `5500602` (100), `5500604` (50) y `5500615` (500). `5500613` también niega `PHPSESSID[0]`. `5500625` pasa a minúsculas. `5500617` niega desde 257 caracteres. `5500612` mira `FILES` y `FILES_NAMES`. `5500622` exige que el argumento entero sea la ruta de sesión.

`publish/stable/meta_hostium.yaml` pasa a `hostium-1.1.2`. No se reescriben `hostium-1.1.1.zip` ni `hostium-1.0.0.zip`. `ultima_validacion` sigue vacía. No se ejecutó `upcp` ni `modsec_vendor`. En la imagen Debian `modsecurity 2.9.7-1+deb12u2`, `test_motor_ve_las_reglas_410` pasó. No es el RPM `2.9.15` de cPanel.

## 1.1.1 — 2026-10-24

Saca del ZIP las reglas de fase 4 (`5500620`, `5500623`, `5500624`, `5500626`). En cPanel no se enciende `SecResponseBodyAccess` para todas las cuentas. Quedan en `REQUEST-411-PHP-UPLOAD-PROGRESS-RESPONSE.conf.example`. `publish/stable/meta_hostium.yaml` pasa a `hostium-1.1.1`. El ZIP `hostium-1.0.0.zip` no se reescribe y `hostium-1.1.0` no se publicó. WHM cuenta dos sets: `REQUEST-100-SENSITIVE-FILES.conf` y `REQUEST-410-PHP-UPLOAD-PROGRESS.conf`.

No se ejecutó `modsec_vendor` ni `upcp` desde este repositorio. `ultima_validacion` sigue vacía.

## 1.1.0 — 2026-10-23

Módulo `REQUEST-410-PHP-UPLOAD-PROGRESS` para CVE-2026-109618 y CVE-2026-109619. No es el parche de PHP: la corrección sigue siendo 8.2.35, 8.3.36, 8.4.27 u 8.5.12. `package build --version 1.0.0` rechaza el árbol porque esa distribution no se reutiliza. La etiqueta `<?php` en cualquier cuerpo queda en `pass`, no en `deny`.

La aproximación de las expresiones está en `tests/unit/test_php_upload_progress.py`. No se ejecutó el motor ModSecurity contra estos ids. `ultima_validacion` sigue vacía.

`updates plan` emite `modsec_vendor enable-updates hostium`. `updates apply` sale con código 3 y no abre SSH.

## 1.0.0 — 2026-10-23

Primera versión usable en el repositorio: CLI, manifiesto, regla de archivos secretos, selftest fuera del ZIP, empaquetado reproducible y auditoría de flota en solo lectura.

No incluye instalación en cPanel ni `deploy apply`. La prueba HTTP depende de Docker y queda registrada aparte cuando se ejecutó. Una corrida unitaria verde no afirma protección en calcium.

La metadata de `1.0.0` apunta a `publish/stable/` en `https://github.com/devmanifesto/Hostium-WAF-Manager`. El repositorio es público y el raw de ese ZIP responde 200.
