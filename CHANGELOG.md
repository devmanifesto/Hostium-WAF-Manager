# Changelog

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
