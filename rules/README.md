# Hostium WAF Ruleset

Las reglas de producción viven en archivos `.conf`. Los `.conf.example` son borradores o
controles de laboratorio: el empaquetador no los incluye.

El manifiesto `manifests/rules.yaml` es la fuente de auditoría. ModSecurity lee los `.conf`,
no el YAML.

Rango de IDs: 5500000–5509999.

| ID | Archivo | Paquete estable |
| --- | --- | --- |
| 5500000 | REQUEST-000-SELFTEST.conf.example | no |
| 5500100, 5500101 | REQUEST-100-SENSITIVE-FILES.conf | sí, 1.0.0 y 1.1.0 |
| 5500200–5500500 | REQUEST-200 a REQUEST-500, `.example` | no |
| 5500600–5500619, 5500621, 5500622, 5500625 | REQUEST-410-PHP-UPLOAD-PROGRESS.conf | sí, desde 1.1.0 |
| 5500620, 5500623, 5500624, 5500626 | REQUEST-411-PHP-UPLOAD-PROGRESS-RESPONSE.conf.example | no |

OWASP CRS sigue siendo un ruleset aparte, instalado por el RPM de cPanel. Estas reglas no lo reemplazan ni lo editan.
