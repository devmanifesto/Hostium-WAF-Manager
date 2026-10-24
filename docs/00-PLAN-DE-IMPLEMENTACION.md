# Plan de implementación

## Objetivo

Dejar un Hostium WAF Manager instalable en la máquina de desarrollo, con una regla original, un ZIP compatible con el proveedor ModSecurity de WHM y documentación para operar sin improvisar en producción.

## Audiencia

Quien retome el repositorio: desarrollo, seguridad de plataforma y la persona que más adelante ejecute el runbook en un laboratorio cPanel.

## Prerrequisitos

Python 3.11+, el árbol de este repositorio y, para la fase HTTP, Docker. No se usa un cPanel local.

## Alcance de lo construido

1. Contratos de manifiesto, política, metadata y ZIP.
2. CLI real para validar, empaquetar, listar la flota y emitir planes.
3. Regla de archivos secretos y selftest excluido.
4. Prueba HTTP opcional con Apache y, si la imagen descarga, con OWASP CRS 3.3.10.
5. `deploy apply`, `rollback apply` y la publicación HTTP quedan bloqueados con código de salida 3.

## Decisiones

- Python, Typer, Rich, PyYAML y pytest.
- Proveedor nativo `hostium`, directorio raíz del ZIP `hostium/`.
- IDs 5500000–5509999.
- Canales `stable` y `canary` como URLs distintas, no como una función de WHM.
- Hosts `*.example.invalid` no se contactan.

## Fases y criterio

| Fase | Criterio para darla por hecha |
| --- | --- |
| Contratos | `doctor --local` termina en 0 sobre el árbol de ejemplo |
| MVP | dos builds de 1.0.0 producen el mismo ZIP y `package verify` pasa |
| Integración | el contenedor observa el id, o el reporte dice que la prueba se omitió |
| Operación | los planes no abren SSH de escritura y los manuales distinguen solo lectura de producción |
| Cierre | pytest y ruff corridos, sin secretos en el árbol versionado |

## Riesgos

- La grafía `enable-updates` / `enable_updates` sigue sin comprobar en un `modsec_vendor` real.
- El contenedor Debian no es el RPM `ea-apache24-mod_security2` de cPanel. La versión que imprime la imagen es la de esa imagen, no la de calcium.
- NGINX o Engintron pueden servir una URL sin pasar por Apache. Este paquete no lo cubre.

## Rollback de una release de ruleset

No se publica sola. Si una release llegara a un piloto, la vía rápida es `modsec_vendor disable hostium` y la vía versionada es volver a la metadata de la release anterior. Las dos están descritas y ninguna está automatizada.

## Referencias

`docs/REFERENCIAS.md`, consultadas el 23 de octubre de 2026.

## Limitaciones

`ultima_validacion` de cada regla es null. La corrida de contenedor del 23 de octubre de 2026 está copiada en `docs/11-PRUEBAS-Y-VALIDACION.md`. No hubo prueba de extremo a extremo en calcium.
