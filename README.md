# Hostium WAF Manager

Herramienta para mantener un ruleset ModSecurity propio, empaquetarlo como proveedor de cPanel/WHM y auditar una flota sin tocarla por defecto.

La versión 1.0.0 construye y verifica el ZIP en esta máquina. No instala nada en calcium y no trata una sintaxis válida como una prueba de bloqueo en producción.

## Requisitos

- Python 3.11 o superior. En el equipo de desarrollo se usó 3.14.4.
- Git.
- Docker, solo si vas a correr la prueba HTTP contra Apache y ModSecurity.

No hace falta cPanel en la máquina donde se desarrolla.

## Inicio

```powershell
python -m pip install -e ".[dev]"
python -m hostium_waf version
python -m hostium_waf doctor --local
python -m hostium_waf rules validate
python -m hostium_waf package build --version 1.0.0 --engine 2.9.15
python -m hostium_waf package verify --zip dist/hostium-1.0.0.zip --metadata dist/meta_hostium.yaml
```

`python -m pytest` corre la suite unitaria. `python -m pytest -m integration --override-ini="addopts="` levanta Apache. Si Docker no está en marcha, esa prueba se omite y el informe lo dice: una omisión no es un bloqueo comprobado.

## Qué entra al ZIP estable

Solo `rules/hostium/REQUEST-100-SENSITIVE-FILES.conf`, con los id `5500100` (`/.env`) y `5500101` (`/.git/config`). El selftest `5500000` vive en un `.example` y no se empaqueta. Los borradores de WordPress, PHP, CVE y escáneres tampoco.

El ZIP extrae un único directorio `hostium/`. La metadata se llama `meta_hostium.yaml`. La clave `'2.9.15'` es la versión del motor, no la del ruleset. `distribution: hostium-1.0.0` identifica la release.

La metadata apunta a `https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/`. El repositorio es público y esas URL se bajan sin sesión. Este repositorio no ejecuta el alta en calcium.

## Comandos que no actúan

`deploy apply`, `rollback apply` y `publish apply` terminan con código 3 aunque pases `--approve`. `fleet audit` sobre `*.example.invalid` no abre SSH. El inventario de ejemplo no es calcium.

## Documentación

El alcance está en [docs/ESPECIFICACION_MAESTRA.md](docs/ESPECIFICACION_MAESTRA.md). El plan ejecutado está en [docs/00-PLAN-DE-IMPLEMENTACION.md](docs/00-PLAN-DE-IMPLEMENTACION.md). El runbook de calcium, sin haberlo ejecutado, está en [docs/09-DESPLIEGUE-CALCIUM.md](docs/09-DESPLIEGUE-CALCIUM.md).

## Licencia

Apache 2.0. No incluye reglas de Imunify360 ni de Comodo. OWASP CRS sigue siendo el ruleset del RPM de cPanel y no se modifica.
