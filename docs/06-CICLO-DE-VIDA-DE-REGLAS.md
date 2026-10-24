# Ciclo de vida de una regla

## Objetivo

Pasar una idea a una release sin mezclarla con bytes ya publicados.

## Audiencia

Quien abre el cambio y quien lo revisa.

## Prerrequisitos

`CONTRIBUTING.md` y un id libre.

## Estados

`borrador`, `experimental`, `probado`, `piloto`, `produccion`, `retirado`.

Solo `produccion` con `incluir_en_paquete: true` entra al ZIP, y solo si la política nombra el módulo. Un `.example` no puede marcarse así: la validación lo rechaza.

## Pasos

1. SOLO LECTURA en el repo: `python -m hostium_waf rules check-ids`.
2. Agregá el manifiesto completo y el `.conf`. Si todavía no hay evidencia, el archivo termina en `.example`, el estado es `borrador` y los casos dicen `ejecucion: pendiente`.
3. Cuando los casos sean `automatizada`, el estado puede pasar a `produccion` y el módulo entra en la política. Eso es un cambio de archivo en git, no un cambio en un servidor.
4. Revisión humana si la acción es `deny`.
5. `package build` con un SemVer nuevo.
6. La persona que opera el piloto, en otra ventana y con aprobación, sigue `docs/09-DESPLIEGUE-CALCIUM.md`. Este ciclo no lo hace.

## Rollback de la regla

En el manifiesto, el registro de cambio explica cómo salir. Para las reglas actuales: deshabilitar el vendor `hostium` deja CRS como estaba. Quitar solo el `.conf` del paquete exige una release nueva, no un parche del ZIP 1.0.0.

## Verificación

`rules validate` en 0 y, si Docker está en marcha, la prueba de integración observa el id.

## Riesgos

Marcar `ultima_validacion` después de un contenedor hace creer que calcium ya pasó. El campo queda null hasta esa prueba.

## Problemas frecuentes

El build falla con “no se sobrescribe” porque cambiaste una regla y reusaste 1.0.0. Subí a 1.0.1.

## Referencias

`docs/07-PAQUETES-CPANEL-WHM.md`.

## Limitaciones

No hay un bot que impida el merge. La revisión humana es parte del proceso, no un check de GitHub en este repositorio más allá de la CI de lint y pytest.
