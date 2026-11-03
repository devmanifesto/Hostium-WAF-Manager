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
| 3 | Operación bloqueada: deploy apply, rollback apply, publish apply, updates apply, build-tune y render-score sin opt-in |

## Comandos

| Comando | Efecto |
| --- | --- |
| `version` | Imprime 1.0.0 |
| `init` | Copia settings, fleet y policy de ejemplo si no existen. No crea `config/exclusions.yaml`: ese catálogo está versionado |
| `doctor --local` | Valida el árbol |
| `rules list` / `validate` / `check-ids` | Manifiesto e ids. `--installed-ids` es un archivo local, no una consulta a WHM |
| `rules render-exclusions` | Escribe `REQUEST-900` desde `config/exclusions.yaml` |
| `rules render-score --crs-dir RUTA --acknowledge-reduced-sensitivity` | Compara una copia local de CRS; solo genera puntaje si coincide y se acepta su impacto |
| `package build --version --engine` | ZIP y metadata de hostium |
| `package build-tune --engine` | Retirado, código 3; el ZIP legado no se modifica |
| `package verify --zip --metadata` | Hashes y estructura |
| `metadata show --file` | YAML ya validado |
| `publish plan --version` | Plan. Falla si no hay artefacto |
| `publish apply` | Código 3 |
| `fleet list` / `fleet audit` | Inventario. `auto` no abre SSH |
| `deploy plan` / `deploy verify` | Plan, o existencia local del ZIP. `verify` dice `remoto: no_ejecutado` |
| `deploy apply` | Código 3 |
| `rollback plan` / `rollback apply` | Plan, o código 3 |
| `updates plan` | Comando `enable-updates hostium`. No se conecta. `--help-file` lee una ayuda local |
| `updates apply` | Código 3. No abre SSH |
| `report generate --format markdown` | Informe sin cuerpos |
| `logs analyze --input ARCHIVO --server ALIAS` | Analiza mensajes locales v2; JSON por defecto, sin escribir archivos ni contactar servidores |

`deploy verify` sale en 1 si el ZIP local no está. Eso no significa que el servidor falló.

## Configuración

`config/settings.example.yaml` apunta al manifiesto y a la política de ejemplo, con `base_url` en el raw de `devmanifesto/Hostium-WAF-Manager`, rama `main`, carpeta `publish`. `init` copia settings y hace que la copia use `config/policy.yaml`.

Variables: `HOSTIUM_WAF_ROOT` fuerza la raíz. `HOSTIUM_REQUIRE_INTEGRATION=1` hace fallar la integración si Docker no responde, la imagen no se construye o CRS no descarga. CI y release lo exigen. Los errores funcionales siempre fallan.

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

## Diagnóstico de eventos

`logs analyze` admite `--format json|markdown`, `--output RUTA`, `--include-locations` y `--baseline INFORME.json`. Sin output solo escribe stdout. `--json` global fuerza JSON. La base requiere mismo servidor y modo de ubicaciones. Se admite error log Apache y mensajes H del audit log v2; no audit JSON. El error por formato no soportado, entrada ausente o salida que pisaría el original es explícito. Ver documento 12.

El catálogo de exclusiones exige `habilitada`, `dominios`, `metodos`, ticket y fecha de revisión. Solo se activan rutas `@streq` o prefijos de directorio `@beginsWith` y controles de parámetros `ARGS:nombre`. Una entrada inactiva necesita motivo pendiente. Detalles y ejemplo completo en documento 13.
