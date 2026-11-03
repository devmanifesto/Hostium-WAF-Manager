# QA de tuning: candidata local 2.1.2

> Bitácora de la candidata local 2.1.2, sin publicación. La estable posterior es 2.1.3; ver [QA de release](24-RELEASE-2.1.3.md).

## Fecha y alcance

2 de noviembre de 2026, fecha del operador (America/Buenos_Aires). Estable publicada: 2.1.1. No se promovió metadata, no se hizo push y no se contactaron servidores. Los tests HTTP usan contenedores locales. `ultima_validacion` de todas las reglas continúa null.

## Cambios comprobados

- Cinco IDs de exclusión conservados con fase 1 y pass. En el catálogo predeterminado no aplican ctl porque faltan dominios y alcance confirmado. Son condiciones imposibles, no ejemplos activos ni dominios inventados.
- El generador activo exige dominio exacto, ruta sin query, método y parámetro. El ctl va al final de la cadena. Se validan fechas vencidas, controles y caracteres de configuración. No se prohíbe una ruta administrativa por su nombre: se exige delimitarla.
- Integración sintética con CRS: ambos IDs de firma, SQLi de selección, XSS de ambos campos de plantilla, RCE de plantilla, HTML PrestaShop y serialización de turnero. Cada caso comprueba base sin exclusión, efecto dentro del alcance y conservación al cambiar dominio, ruta, método o parámetro. También query string, sufijo de endpoint y otra regla que sigue protegiendo el campo exceptuado.
- El conf de laboratorio se incluye después de CRS, ejecutando sus controles en fase 1 para objetivos fase 2. No se extrapola a objetivos fase 1 ni al orden del cPanel.
- El test de sintaxis extrae REQUEST-410 y REQUEST-900 del ZIP candidato construido; no carga un conjunto histórico en su lugar.
- El analizador de eventos verifica correlación por unique_id, deduplicación, privacidad, conteos, fechas Apache, entradas no soportadas, límites de línea y comparación. Sus pruebas son sintéticas; no se analizaron eventos reales.
- El builder actualiza todas las acciones ver y los encabezados al número del paquete. Comparación de REQUEST-410 con la estable: solo cambian versión y primera línea, no expresiones, IDs, fases ni acciones.
- El helper de copia local valida hashes, no reemplaza un ZIP diferente y cambia la metadata atómicamente después de releer el ZIP. Nuevos builds no admiten motores distintos de 2.9.15.

## Resultados ejecutados en esta máquina

Python 3.14.4, pytest 9.1.1, Docker Server 29.4.2.

```text
python -m pytest
103 passed, 15 deselected, 1 warning in 3.59s

python -m ruff check src tests
All checks passed!

HOSTIUM_REQUIRE_INTEGRATION=1 python -m pytest -m integration --override-ini="addopts=" -q
15 passed, 101 deselected in 59.04s
```

El último comando se muestra en sintaxis de shell POSIX. En PowerShell se ejecutó con `$env:HOSTIUM_REQUIRE_INTEGRATION='1'` antes de Python. Los dos tests unitarios agregados después de esa integración (fecha/línea excesiva y acción deny por bloque) están incluidos en las 103 pasadas locales; no cambian el HTTP ni el conjunto de integración. No hubo tests de integración omitidos. El warning de unidad es el ZIP duplicado fabricado deliberadamente para probar su rechazo.

También pasaron `doctor --local`, `rules validate`, `rules check-ids` y verificación del ZIP estable 2.1.1. Las colisiones con IDs instalados siguen **no comprobadas**: no se recibió inventario real de IDs.

Imagen CRS: `owasp/modsecurity-crs:3.3.10-apache-202610180210-lts@sha256:98fb77754c674c235b05ed7883974d7dea6f1ab9ff4ae0f08fd40456ba9d2aec`. La imagen se descargó por digest; los tests ya no reescriben docker/crs-image.txt. La imagen Apache Debian es la de docker/hostium-only, con su versión registrada en reports/modsec-version.txt; no es el RPM de cPanel.

## Artefacto candidato reproducible

```powershell
python -m hostium_waf package build --version 2.1.2 --engine 2.9.15 --output dist/candidata-2.1.2
python -m hostium_waf package verify --zip dist/candidata-2.1.2/hostium-2.1.2.zip --metadata dist/candidata-2.1.2/meta_hostium.yaml
python -m hostium_waf package build --version 2.1.2 --engine 2.9.15 --output dist/verificacion-2.1.2
```

Ambas construcciones produjeron los mismos 4248 bytes. SHA256: `c05de9b2d65a136699e24509ad60c23c11a781bd43d89d57e57f2059b0749d13`.

Raíz única hostium/, dos conf, ningún example ni puntaje. La URL de la metadata candidata es una ubicación prevista, no una publicación existente comprobada. El candidato queda en dist/, ignorado por Git.

Se compararon los **17 archivos versionados bajo publish/** contra HEAD, byte a byte: todos intactos, incluidos ZIP, sidecars y ambas metadata históricas. No se editó la distribution estable.

## CI y límites

CI toma la versión de crs_vendor.VERSION_RULESET. La release depende de los jobs de lint, pruebas, build e integración estricta. Docker ausente o fallo de construcción/descarga no se omiten bajo HOSTIUM_REQUIRE_INTEGRATION=1. Se comprobó la lectura de los workflows YAML; GitHub Actions no se ejecutó desde esta sesión.

El wrapper publish-local.sh no se ejecutó en Windows; sí se probaron sus operaciones Python en directorios temporales. No se activó puntaje global. No se probaron aplicaciones reales, autenticación, cPanel, rutas del proxy, recargas, despliegue ni rollback remoto.

## Antes de una promoción

Completar dominios, endpoints y parámetros de los cinco casos; para PrestaShop falta el nombre del parámetro. Revisar IDs mínimos y fase de cada objetivo sobre el RPM instalado. Reproducir las operaciones legítimas y ataques fuera del alcance en cPanel de laboratorio autorizado. Medir períodos comparables usando logs analyze. Solo entonces decidir publicación e instalación con autorización explícita.

Instalar esta candidata sin completar el catálogo puede restaurar los falsos positivos que exceptuaba 2.1.1. Rollback: ver documento 13; volver a la estable también restaura sus excepciones globales. Ningún ZIP histórico se reescribe.
