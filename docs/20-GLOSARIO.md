# Glosario

## Objetivo

Alinear palabras entre soporte, operación y desarrollo.

## Audiencia

Quien lee un ticket o un informe y no mantiene el ruleset.

## Términos

| Término | Significado aquí |
| --- | --- |
| Motor | ModSecurity. En el piloto, la serie 2.9 embebida en Apache. La clave del YAML es esta versión |
| Ruleset | El conjunto Hostium, con su propio SemVer. No es el número del motor ni el de CRS |
| CRS / OWASP3 | El vendor que instala el RPM de cPanel. No lo editamos |
| Vendor | Un origen de reglas que WHM descarga con `modsec_vendor` |
| `vendor_id` | El nombre corto. El nuestro es `hostium` porque el archivo se llama `meta_hostium.yaml` |
| `distribution` | El identificador inmutable de una release. Stable nombra hoy `hostium-1.1.1` |
| Mayor, sub, sub-sub | Los tres números del ruleset. `2.0.0` rompe un id ya instalado. `1.2.0` agrega sets o ids. `1.1.2` no cambia ids, fase ni acción |
| DetectionOnly | Modo global del motor: las reglas no niegan. No es lo mismo que una regla escrita con `pass,log` |
| deny | La regla interrumpe con el status que declare, en la nuestra 403 |
| Id | El número de la regla. Los nuestros están entre 5500000 y 5509999 |
| Selftest | La regla 5500000, solo de laboratorio, fuera del ZIP |
| Anillo | lab, pilot, canary o production. Es nuestro orden de exposición, no un campo de WHM |
| Canal | `stable` o `canary`, implementados como URLs distintas |
| Dry-run | La CLI muestra el plan y no actúa |
| Código 3 | La operación existe en la ayuda y está bloqueada a propósito |
| Fixture | Texto de prueba. No es una captura de calcium |
| Include | Una línea de Apache que carga un `.conf`. El orden entre vendors se mira con `DUMP_INCLUDES` |
| Exclusión runtime | `ctl:ruleRemoveById`, antes de la regla que quiere anular |
| Exclusión configure-time | `SecRuleRemoveById`, después de incluir CRS |

## Verificación

Si un informe dice “el WAF está en DetectionOnly”, preguntá si es el motor o una regla. Son dos interruptores distintos.

## Deshacer

No aplica.

## Problemas frecuentes

Llamar “versión de OWASP” al texto descriptivo del vendor. La versión instalada sale de `rpm -q`.

## Referencias

El resto de `docs/`.

## Limitaciones

No traduce la interfaz de WHM pantalla por pantalla.
