# Instrucciones persistentes para Cursor — Hostium WAF Manager

- El documento fuente de verdad para el alcance del proyecto es `docs/ESPECIFICACION_MAESTRA.md`. Leelo entero antes de implementar componentes importantes.
- Tu misión es diseñar, implementar, probar y documentar el repositorio funcional, no solo redactar planes.
- Redactá toda la documentación y mensajes operativos en español. Entregá archivos completos, no fragmentos.
- Usá documentación oficial de cPanel/ModSecurity/OWASP CRS y señalá todo supuesto no confirmado.
- No copiés rulesets propietarios de Imunify360/Comodo. Protegé la compatibilidad de OWASP CRS.
- No toques producción ni ejecutes despliegues, reinicios o cambios remotos sin aprobación explícita.
- Las operaciones modificadoras remotas deben ser `dry-run` por defecto.
- El formato del paquete ZIP y el YAML de WHM debe respetar exactamente el contrato oficial indicado en la especificación.
- Toda regla necesita ID único, test positivo, test negativo, documentación y criterio de rollback.
- Los ejemplos o componentes incompletos deben identificarse como tal. Nunca inventes resultados de pruebas.
- Antes de cerrar una tarea, corré las validaciones locales disponibles y actualizá la documentación correspondiente.

## Definición de terminado

Una tarea está terminada cuando el comando que dice implementar existe, falla de forma explícita si todavía está bloqueado, y `python -m pytest` más `python -m ruff check src tests` se ejecutaron en esta máquina. Si una prueba no corrió, el mensaje final lo dice. No marques `ultima_validacion` en el manifiesto por una prueba de contenedor: ese campo queda vacío hasta un cPanel real.

## Cómo agregar una regla sin romper una release

1. Elegí un id libre con `hostium-waf rules check-ids`.
2. Agregá la entrada al manifiesto y el `SecRule` en un `.conf` nuevo, con `ver:'hostium/<semver nuevo>'`.
3. Dejala fuera de `config/policy.example.yaml` hasta tener casos automatizados.
4. Construí con un SemVer nuevo. Si `dist/releases/hostium-1.0.0.zip` ya existe con otros bytes, el build debe fallar.
5. No reutilices `distribution: hostium-1.0.0` para otro contenido.

## Cada serie de cambios

Al cerrar una serie, hacé un commit y subí el parche del ruleset: el tercer número SemVer (`1.1.0`, después `1.1.1`). La distribution nueva es `hostium-<semver>`. No reutilices el número anterior ni reescribas su ZIP. El build escribe esa versión en la primera línea de cada `.conf` empaquetado y en `attributes.description`.

## Qué no tocar

- Servidores reales, incluido calcium, sin un pedido explícito de esa operación.
- `enable-updates hostium` es el comando documentado para el flag de updates. `updates apply` no abre SSH. No lo corras en calcium sin un pedido explícito de esa operación.
- Archivos bajo el vendor OWASP3 instalado por RPM.
- `deploy apply` y `rollback apply`: siguen bloqueados hasta que haya captura de estado, idempotencia ensayada y rollback ensayado.
