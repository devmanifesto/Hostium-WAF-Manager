# Visión y alcance

## Objetivo

Hostium necesita un ruleset propio, versionado y reversible, que conviva con OWASP CRS en cPanel sin depender de Imunify360.

## Audiencia

Seguridad de plataforma, operación de cPanel y quien revise un falso positivo.

## Prerrequisitos

Conocer que ModSecurity en el piloto corre dentro de Apache y que un proxy previo puede no entregar el tráfico a ese Apache.

## Alcance de la 1.0.0

- Reglas originales en SecLang y un manifiesto YAML de auditoría.
- ZIP y `meta_hostium.yaml` para el alta manual de un vendor.
- Validación estática, CLI y planes de flota en solo lectura.
- Un runbook para calcium que este repositorio no ejecutó.

## Fuera de alcance

Panel web, RBAC, escáner de archivos en disco, virtual patches de CVE sin PoC, y cualquier promesa sobre tráfico que no pase por Apache.

## Escenarios

1. Un laboratorio construye `hostium-1.0.0.zip` y lo revisa con `package verify`.
2. Más adelante, con aprobación, un piloto agrega la URL de metadata. Eso no está automatizado.
3. Un falso positivo se documenta como exclusión con fecha de revisión, fuera del ZIP, en el orden que CRS exige.

## Qué puede salir mal

Activar el selftest en un sitio público: la cabecera no es un secreto. Dejar una exclusión sin vencimiento. Apagar OWASP al deshabilitar Hostium. Tratar un 403 sin id como prueba de nuestra regla.

## Verificación

`hostium-waf rules list` muestra 5500100 y 5500101 como las únicas que entran al paquete.

## Deshacer

Borrar `dist/` no toca ningún servidor. No hay un cambio remoto que revertir en esta versión.

## Problemas frecuentes

Si `doctor --local` falla, leé el hallazgo: suele ser un YAML o un id. No lo corrijas en el servidor.

## Referencias

`docs/REFERENCIAS.md`.

## Limitaciones

No hay evidencia de bloqueo en el piloto. La metadata de diseño apunta a un host que no está provisionado por este repositorio.
