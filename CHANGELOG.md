# Changelog

## 2.1.5 — 2026-11-03

Publicación estable autorizada por el operador. Nuevo id 5500906 en REQUEST-900, generado desde exclusions.yaml. Fase 1, pass, nolog. Solo el POST de capacitaciones.municipalidadsalta.gob.ar cuyo path empieza por /wp-admin/ quita 941100, 941160, 941200, 941310 y 941350 de ARGS:excerpt y ARGS:content. No quita ARGS entero ni 942190. Los controles de 5500900–5500905 no cambian. No entra REQUEST-910 ni se refresca hostium-tune. hostium-2.1.4.zip no se reescribe. ultima_validacion continúa null. Ver docs/26-RELEASE-2.1.5.md.

## 2.1.4 — 2026-11-02

Publicación estable autorizada por el operador. Nuevo id 5500905 en REQUEST-900, generado desde exclusions.yaml. Fase 1, pass, nolog. En GET, si REQUEST_FILENAME empieza por /pluginfile.php/, el ctl quita solo REQUEST_FILENAME de 933210. No lleva dominio, no toca ARGS ni desactiva la regla. Los controles de 5500900–5500904 no cambian. No entra REQUEST-910 ni se refresca hostium-tune. hostium-2.1.3.zip no se reescribe. ultima_validacion continúa null. Ver docs/25-RELEASE-2.1.4.md.

## 2.1.3 — 2026-11-02

Publicación estable autorizada por el operador; actualización de calcium a cargo suyo. WHMCS 5500902 ahora aplica solo en POST clientes.hostium.com/admin1911/configgeneral.php, excluyendo 921130 en emailglobalheader/emailglobalfooter además de las exclusiones XSS/RCE previas. No se excluye attack-protocol completo; 921120 y los demás argumentos siguen inspeccionados. Regresión HTTP de ambos campos y del selector real, sin 921130 ni 949110 en la plantilla de laboratorio.

Los otros cuatro casos conservan compatibilidad transitoria con el ZIP 2.1.1 fijado por SHA256, sin ampliaciones. 5500903 usa REQUEST_FILENAME para no activarse desde la query. No se toca puntaje global ni hostium-tune. Mismos IDs, fases y acciones; ver y encabezados 2.1.3. La candidata 2.1.2 permanece local e inmutable. ultima_validacion continúa null hasta un ensayo en cPanel real. Ver docs/24-RELEASE-2.1.3.md.


## 2.1.2 candidata local — 2026-11-02 (sin promover)

Exclusiones con dominio exacto, ruta sin query, método y parámetro; ctl al final de la cadena. Los cinco casos sin dominio confirmado quedan inactivos, conservando IDs, fase y pass. No se altera la estable 2.1.1: instalar la candidata sin completar el alcance puede restaurar los falsos positivos previos.

Nuevo logs analyze: lectura local de mensajes ModSecurity v2, deduplicación/correlación por transacción, agrupación de IDs detectores y evaluadores, privacidad por defecto y comparación de conteos. No clasifica automáticamente falsos positivos ni aplica excepciones.

El builder sincroniza ver con la distribución y comprueba archivos ya publicados aunque cambie el directorio de salida. Se validan vencimientos y alcance. build-tune queda bloqueado; render-score exige comparar una copia CRS y aceptar menor sensibilidad. CI usa la versión candidata y la release depende de lint, unitarias e integración estricta. Nuevos tests HTTP prueban las cinco exclusiones con CRS y conservación de protección fuera del alcance. Se corrigen comandos y se distinguen bitácoras históricas.

No se modificaron expresiones ni acciones de REQUEST-410, ZIP publicados o metadata estable. ultima_validacion continúa null. Ver docs/23-QA-TUNING.md para resultados realmente ejecutados.


## 2.1.1 — 2026-11-02

`hostium-2.1.1` repite los dos conf de `hostium-2.1.0`. Las `SecRule` de `REQUEST-410` no cambian. En `5500900`–`5500904` cambia solo `ver:'hostium/2.1.1'`. Ids, fase, `pass`, `nolog` y los ctl quedan. No entra `REQUEST-910` ni `SecRuleUpdateActionById`. `publish/stable/meta_hostium.yaml` apunta a `hostium-2.1.1.zip`. No se reescribe `hostium-2.1.0.zip`.

El puntaje de 911, 922, 932, 934 y 944 no es un vendor. `meta_hostium-tune.yaml` vuelve a nombrar `hostium-tune-2.1.0.zip`, que se conserva. Sale del árbol `hostium-tune-2.1.1.zip`. El único meta que stable ofrece para instalar es `meta_hostium.yaml`. `ultima_validacion` sigue vacía. No se ejecutó `upcp`, `modsec_vendor` ni `httpd -t`.

## 2.1.0 — 2026-11-02

`hostium-2.1.0` suma `REQUEST-900-CRS-EXCLUSIONS.conf`. Los ids de `REQUEST-410` conservan id, fase y acción. `5500900`, `5500901` y `5500902` son `SecAction` de fase 1, sin URI: sacan `ARGS:firmadatos` de 941130 y 941170, `ARGS:vseleccionados` de 942100, y `ARGS:emailglobalheader` más `ARGS:emailglobalfooter` de los tags `attack-xss` y `attack-rce`. `5500903` saca `ARGS` de 941160 cuando la URI contiene `/sell/catalog/`. `5500904` saca `ARGS:datos` de 933170 en el turnero. No hay `/login` ni directorio de admin.

En esa publicación el bajado de puntaje salió como vendor `hostium-tune`, distribution `hostium-tune-2.1.0`. La 2.1.1 dejó de ofrecerlo para instalar. Cada `SecRuleUpdateActionById` resta el anomaly score crítico y suma el warning de 911, 922, 932, 934 y 944. Neto 3. Una 922130 no llega a 5. Dos reglas de esos archivos suman 6. El RPM de cPanel no se diffé. Si `hostium-tune` se incluye antes de OWASP3, `httpd -t` falla.

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
