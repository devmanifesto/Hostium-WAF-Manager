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
5. `package build` con un SemVer nuevo, elegido contra la distribution que nombra la metadata de stable.
6. La persona que opera el piloto, en otra ventana y con aprobación, sigue `docs/09-DESPLIEGUE-CALCIUM.md`. Este ciclo no lo hace.

## Qué número sube

Se compara con el ZIP que `publish/stable/meta_hostium.yaml` nombra. Hoy es `hostium-1.1.2`. Cada release que se arme sube solo el sub-sub (`1.1.3` después de esta), salvo que quien opera pida sub o mayor. La tabla dice qué significa cada componente.

| Cambio respecto de esa distribution | Número | Ejemplo ya subido |
| --- | --- | --- |
| Un id publicado cambia de `deny` a `pass`, de `pass` a `deny` o de fase; se elimina un `.conf` que esa distribution instala; se reutiliza un id; cambia el contrato del vendor | mayor, `2.0.0` | Todavía no hubo |
| Entra un `.conf` o ids nuevos, y los ids ya instalados conservan id, fase y acción | sub, `1.2.0` | `1.0.0` tenía un set. La línea `1.1` agregó `REQUEST-410` |
| Mismos sets, mismos ids, misma fase y misma acción. O la regla nunca estuvo en la metadata de stable | sub-sub, `1.1.3` | `1.1.1` sacó del ZIP las reglas de fase 4. La `1.1.2` se publicó como sub-sub por pedido e incorpora los contadores `5500606`, `5500607` y `5500608` |

Docs, tests o CLI sin otro contenido de reglas no publican distribution nueva.

## Rollback de la regla

En el manifiesto, el registro de cambio explica cómo salir. Para las reglas actuales: deshabilitar el vendor `hostium` deja CRS como estaba. Quitar solo el `.conf` del paquete exige una release nueva, no un parche del ZIP 1.0.0.

## Verificación

`rules validate` en 0 y, si Docker está en marcha, la prueba de integración observa el id.

## Riesgos

Marcar `ultima_validacion` después de un contenedor hace creer que calcium ya pasó. El campo queda null hasta esa prueba.

## Problemas frecuentes

El build falla con “no se sobrescribe” porque cambiaste una regla y reusaste 1.0.0. También falla, con otro mensaje, si pedís 1.0.0 cuando el paquete ya incluye reglas introducidas en 1.1.0. La salida es un SemVer nuevo, no reescribir el ZIP viejo.

## Referencias

`docs/07-PAQUETES-CPANEL-WHM.md`.

## Limitaciones

No hay un bot que impida el merge. La revisión humana es parte del proceso, no un check de GitHub en este repositorio más allá de la CI de lint y pytest.
