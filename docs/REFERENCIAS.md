# Referencias

Consulta del 23 de octubre de 2026. Si una página cambió, manda la página y no este resumen.

| Tema | URL | Qué se tomó |
| --- | --- | --- |
| Crear un vendor | https://api.docs.cpanel.net/guides/quickstart-development-guide/tutorial-create-a-modsecurity-vendor | YAML, `meta_`, `vendor_id`, ZIP con un directorio igual al id, MD5, SHA512, `distribution`, `url`, `attributes` |
| Vendors en WHM | https://docs.cpanel.net/whm/security-center/modsecurity-vendors/ | Alta, lista y habilitación desde la interfaz |
| Script `modsec_vendor` | https://docs.cpanel.net/whm/scripts/the-modsec_vendor-script/ | Argumentos `list`, `add`, `remove`, `update`, `enable`, `disable`, `enable-configs`, `disable-configs`. Última modificación de la página: 8 de julio de 2026 |
| Herramientas y hits | https://docs.cpanel.net/whm/security-center/modsecurity-tools/ | Dónde mirar un id disparado |
| ModSecurity por dominio | https://docs.cpanel.net/cpanel/security/modsecurity/ | Un dominio puede no estar cubierto aunque el motor global esté On |
| Excepciones CRS | https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/ | Runtime antes de CRS; configure-time después |
| Documentación CRS | https://coreruleset.org/docs/ | CRS es Apache 2.0 y es independiente de este ruleset |
| Manual ModSecurity | https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x) | Fases, transformaciones, acciones. La web `modsecurity.org/docs` redirige al manual del proyecto |
| Imagen CRS | https://github.com/coreruleset/modsecurity-crs-docker | Tags `3.3.10-apache-*`. El README del proyecto describe Apache con ModSecurity 2.9.x |
| CWE-538 | https://cwe.mitre.org/data/definitions/538.html | Archivos sensibles no referenciados |
| Virtual patching | https://owasp.org/www-community/Virtual_Patching_Best_Practices | Un borrador de CVE no es un parche |

## Hechos de la consulta, no supuestos del piloto

- El tutorial exige que el directorio del ZIP coincida con el `vendor_id`. El ejemplo de shell del mismo tutorial comprime una carpeta con el nombre de la distribución. Este proyecto sigue el requisito textual: raíz `hostium/`.
- La tabla de atributos incluye SHA512. El ejemplo de una sola versión del tutorial a veces muestra solo MD5. Generamos los dos.
- En la página del script, el argumento figura como `enable-updates` y un ejemplo usa `enable_updates`. El comando que emitimos es `enable-updates`. No se corrió en un cPanel.

## Línea base del piloto

La especificación repite lo que el operador observó en calcium: motor `ea-apache24-mod_security2-2.9.15-2.3.1.cpanel`, CRS RPM `3.3.10-1.2.1.cpanel`, vendor `OWASP3` enabled. Eso no fue releído por esta herramienta. No es una captura nueva.

## Licencias

Este repositorio es Apache 2.0. No redistribuye CRS. La imagen de prueba, si se descarga, trae CRS upstream con su propia licencia y no entra al ZIP de Hostium.
