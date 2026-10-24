# API, CLI y configuración

## Objetivo

Listar comandos, códigos y archivos de configuración.

## Audiencia

Quien automatice la CLI o la opere a mano.

## Prerrequisitos

Instalación del documento 04.

## Globales

`--json` escribe un objeto en stdout. `--verbose` agrega detalle y no imprime el entorno. `--dry-run` evita la ejecución remota. En `fleet audit` muestra el plan de comandos.

## Códigos de salida

| Código | Significado |
| --- | --- |
| 0 | La operación local terminó bien |
| 1 | Validación, artefacto ausente o diagnóstico con hallazgos |
| 2 | Uso incorrecto, lo informa Typer |
| 3 | Operación bloqueada: deploy apply, rollback apply, publish apply |

## Comandos

| Comando | Efecto |
| --- | --- |
| `version` | Imprime 1.0.0 |
| `init` | Copia los example a `config/*.yaml` si no existen |
| `doctor --local` | Valida el árbol |
| `rules list` / `validate` / `check-ids` | Manifiesto e ids. `--installed-ids` es un archivo local, no una consulta a WHM |
| `package build --version --engine` | ZIP y metadata |
| `package verify --zip --metadata` | Hashes y estructura |
| `metadata show --file` | YAML ya validado |
| `publish plan --version` | Plan. Falla si no hay artefacto |
| `publish apply` | Código 3 |
| `fleet list` / `fleet audit` | Inventario. `auto` no abre SSH |
| `deploy plan` / `deploy verify` | Plan, o existencia local del ZIP. `verify` dice `remoto: no_ejecutado` |
| `deploy apply` | Código 3 |
| `rollback plan` / `rollback apply` | Plan, o código 3 |
| `report generate --format markdown` | Informe sin cuerpos |

`deploy verify` sale en 1 si el ZIP local no está. Eso no significa que el servidor falló.

## Configuración

`config/settings.example.yaml` apunta al manifiesto y a la política de ejemplo, con `base_url: https://waf.hostium.com`. `init` copia settings y hace que la copia use `config/policy.yaml`.

Variables: `HOSTIUM_WAF_ROOT` fuerza la raíz. `HOSTIUM_REQUIRE_INTEGRATION=1` hace fallar la prueba si la imagen CRS no descarga, en lugar de omitirla.

## JSON

`hostium-waf --json version` devuelve `{"ok": true, "version": "1.0.0"}`. Un error incluye `codigo` y `hallazgos`.

## Verificación

`tests/unit/test_cli.py` cubre version, doctor, build, verify, los apply bloqueados y la flota de ejemplo.

## Deshacer

Los YAML creados por `init` están en `.gitignore`. Borrarlos vuelve a los example.

## Problemas frecuentes

`--json`, `--verbose` y `--dry-run` valen antes o después del subcomando: `hostium-waf --json rules list` y `hostium-waf rules list --json` escriben el mismo objeto.

## Referencias

`pyproject.toml` declara el entry point `hostium-waf`.

## Limitaciones

No hay API HTTP. La “API” de esta versión es la CLI.
