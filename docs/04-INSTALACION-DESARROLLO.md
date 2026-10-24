# Instalación de desarrollo

## Objetivo

Dejar la CLI usable en Windows o Linux sin cPanel.

## Audiencia

Quien clona el repositorio.

## Prerrequisitos

Python 3.11 o superior y `pip`. Docker es opcional. En Windows, PowerShell alcanza; `make` no es obligatorio.

## Pasos

1. Cloná el repositorio y entrá en la carpeta. Esto no toca servidores.
2. `python -m pip install -e ".[dev]"` instala la CLI en el entorno actual.
3. `python -m hostium_waf doctor --local` revisa el árbol. No abre SSH.
4. `python -m pytest` corre la suite unitaria.
5. `python -m ruff check src tests` corre el linter.

Si preferís el ejecutable y el directorio de scripts de Python está en el PATH, el comando es `hostium-waf`. Si no, usá `python -m hostium_waf`.

## Salida esperada de doctor

Un texto que termina en `doctor local: sin hallazgos` y una línea de herramientas. `docker=no` o un demonio apagado no fallan esta comprobación. Solo informa.

## Qué hace por dentro

Busca `pyproject.toml`, carga el manifiesto con `yaml.safe_load`, cruza los id del `.conf` y busca patrones de clave privada o access key. No lee el entorno para imprimirlo.

## Riesgos

Instalar con `--user` o en un Python distinto al que después invoca `pytest` deja la CLI invisible. Usá el mismo intérprete.

## Verificación

`python -m hostium_waf version` imprime `hostium-waf 1.0.0`.

## Deshacer

`python -m pip uninstall hostium-waf-manager`. El repositorio queda como estaba.

## Problemas frecuentes

- `No se encontró la raíz`: corré los comandos dentro del repositorio o definí `HOSTIUM_WAF_ROOT`.
- Docker instalado pero `docker info` falla: el servicio de Docker Desktop no está en marcha. La suite unitaria igual corre.

## Referencias

`docs/REFERENCIAS.md`.

## Limitaciones

No hay imagen de desarrollo que reemplace a cPanel. El contenedor de `docker/hostium-only` sirve para la prueba HTTP y usa el ModSecurity de Debian, no el RPM de EasyApache.
