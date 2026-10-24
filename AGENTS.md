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

Al cerrar una serie, hacé un commit. El número de ruleset se mira contra la distribution que nombra `publish/stable/meta_hostium.yaml`, hoy `hostium-1.1.1`. No reutilices ese número ni reescribas su ZIP. Si hay ZIP nuevo, el build escribe la versión en la primera línea de cada `.conf` empaquetado y en `attributes.description`.

El número es `mayor.sub.subsub` (`2.0.0`, `1.2.0`, `1.1.2`). Sube uno solo, el más alto que corresponda.

- **Mayor.** Un id que esa distribution ya instala cambia de `deny` a `pass`, de `pass` a `deny`, o de fase. Se saca del ZIP un `.conf` que esa distribution instala. Se reutiliza un id. Cambia `vendor_id`, la raíz `hostium/` o el contrato de la metadata.
- **Sub.** Entra un `.conf` nuevo o ids nuevos, y los ids ya instalados conservan id, fase y acción. En WHM, Sets Included sube. Así pasó de `1.0.0` (un set, `5500100` y `5500101`) a la línea `1.1` (el módulo `REQUEST-410`).
- **Sub-sub.** Mismos sets, mismos ids, misma fase y misma acción. Se ajusta una expresión y el caso documentado sigue cubierto. También docs, tests o CLI. La `1.1.1` es este caso sobre la `1.1.0`: salieron del ZIP reglas de fase 4 que la metadata de stable nunca había nombrado.

Si la serie no cambia reglas empaquetadas, el commit no crea otra distribution. Un ZIP igual haría que WHM lo baje sin reglas nuevas.

## Qué no tocar

- Servidores reales, incluido calcium, sin un pedido explícito de esa operación.
- `enable-updates hostium` es el comando documentado para el flag de updates. `updates apply` no abre SSH. No lo corras en calcium sin un pedido explícito de esa operación.
- Archivos bajo el vendor OWASP3 instalado por RPM.
- `deploy apply` y `rollback apply`: siguen bloqueados hasta que haya captura de estado, idempotencia ensayada y rollback ensayado.
