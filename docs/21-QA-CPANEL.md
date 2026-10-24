# QA para uso en cPanel

## Objetivo

Decir si el ruleset de este árbol se puede cargar como vendor de WHM, y qué no se comprobó en un cPanel.

## Audiencia

Quien vaya a correr `modsec_vendor add` o a publicar una 1.1.0.

## Fecha

23 de octubre de 2026. No se tocó calcium. No se reescribió `publish/stable/`.

## Lo que WHM instalaría hoy

`publish/stable/meta_hostium.yaml` apunta a `hostium-1.0.0.zip`. Esa distribution trae `REQUEST-100-SENSITIVE-FILES.conf`, ids `5500100` y `5500101`.

`modsec_vendor add` de la URL del runbook 09 instala esa 1.0.0. No instala el módulo PHP. La 1.1.0 existe en el árbol y se construye con `package build --version 1.1.0`. `package build --version 1.0.0` falla para no reutilizar la distribution publicada.

## Controles

| Control | Estado |
| --- | --- |
| ZIP 1.1.0 con raíz `hostium/` y solo los `.conf` de la política | Pasó en local. La suite espera `REQUEST-100-SENSITIVE-FILES.conf` y `REQUEST-410-PHP-UPLOAD-PROGRESS.conf` |
| `distribution: hostium-1.0.0` no se regenera | Pasó en local. El build de 1.0.0 termina en error |
| `SecResponseBodyAccess` fuera del ZIP | Corregido. El conf empaquetado no tiene la directiva activa. En cPanel el vendor aplica a todo el servidor |
| Reglas de fase 4 (`5500620`, `5500623`, `5500624`, `5500626`) | Fuera del paquete, en `REQUEST-411-PHP-UPLOAD-PROGRESS-RESPONSE.conf.example`, estado experimental |
| `SecRequestBodyAccess On` y `5500600` | Siguen en el ZIP. Duplican el cuerpo multipart hasta `SecRequestBodyLimit`. El límite no se sube |
| `apache2ctl configtest` de los dos conf empaquetados | Pasó en `hostium-waf-apache:local`, `modsecurity 2.9.7-1+deb12u2`, Apache/2.4.68 (Debian). No es el RPM `2.9.15` de cPanel |
| Aproximación Python de las expresiones | Pasó. No es el motor |
| `python -m ruff check src tests` | Pasó |
| `python -m pytest` | 59 passed, 4 deselected. Los deseleccionados son integración |
| `pytest -k test_sintaxis_del_conf_empaquetado` | 1 passed |
| POST real y 403 con id PHP en el log | No ejecutado |
| `modsec_vendor list`, `httpd -t` y `DUMP_INCLUDES` en cPanel | No ejecutado |
| Choque de ids con OWASP3 o COMODO en el servidor | No ejecutado. El rango del repo es 5500000–5509999 |
| Hits List de WHM | No ejecutado |
| `deploy apply` y `rollback apply` | Siguen bloqueados. No se habilitaron |
| `enable-updates` / `enable_updates` | No se ejecutó |
| `ultima_validacion` de las reglas | Sigue vacía |

## Riesgos que quedan con la 1.1.0 cargada

El vendor, cuando se publique y se habilite, vale para todas las cuentas.

- `5500601` niega un multipart con `Transfer-Encoding: chunked`. Una subida legítima por HTTP/1.1 con esa codificación cae. La excepción es el id, no apagar el vendor.
- `5500613` niega el campo de formulario `PHPSESSID`. Una aplicación con `session.use_only_cookies=0` cae.
- `5500614` registra `<?php` en el cuerpo y no niega. En el administrador de archivos y en subidas de plugins el audit log puede crecer.
- `5500617` niega un `Set-Cookie` cuyo `PHPSESSID` mide 200 caracteres o más. `session.sid_length` admite hasta 256. Un id válido de 200 a 256 caracteres dispara esta regla. La de pedido (`5500621`) acepta hasta 256.
- `5500600` guarda otra copia del multipart en memoria, hasta el límite que ya tenga el servidor. En un cPanel con OWASP3 ese límite suele ser el de CRS, no uno de este repo.

phpMyAdmin, webmail y el administrador de archivos no se ejercitaron. El repaso es de diseño, no de tráfico.

## Cómo salir

Si la 1.1.0 llegara a un servidor, `modsec_vendor disable hostium` la saca y OWASP3 tiene que seguir enabled. Volver a la metadata publicada reinstala la 1.0.0, no un parche del ZIP. No se reescribe `hostium-1.0.0.zip`.

## Referencias

`docs/09-DESPLIEGUE-CALCIUM.md`, `docs/05-REGLAS-SECLANG.md`, `docs/14-ROLLBACK-Y-RECUPERACION.md`.
