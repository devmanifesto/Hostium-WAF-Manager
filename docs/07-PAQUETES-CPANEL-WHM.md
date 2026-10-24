# Paquetes cPanel y WHM

## Objetivo

Describir el ZIP y el YAML que WHM sabe bajar, y los casos que el validador rechaza.

## Audiencia

Quien construye la release y quien después la carga en un laboratorio.

## Prerrequisitos

Tutorial oficial de vendor, consultado el 23 de octubre de 2026.

## Contrato

- Archivo de metadata: `meta_hostium.yaml`. El `vendor_id` resultante es `hostium`.
- El ZIP se llama `hostium-<semver>.zip` y al extraerlo aparece un único directorio `hostium/` con los `.conf` habilitados.
- `distribution` es `hostium-<semver>`. No es el nombre de ese directorio.
- La clave de primer nivel es la versión del motor, citada: `'2.9.15'`.
- Bajo esa clave: `MD5`, `SHA512`, `distribution`, `url`.
- `attributes`: `name`, `description`, `vendor_url`. Sin `report_url`.

## Ejemplo de forma, con hashes reales solo después del build

```yaml
---
'2.9.15':
  MD5: '<32 hex>'
  SHA512: '<128 hex>'
  distribution: 'hostium-1.0.0'
  url: 'https://waf.hostium.com/stable/hostium-1.0.0.zip'
attributes:
  name: 'Hostium WAF Ruleset'
  description: 'Reglas complementarias de seguridad administradas por Hostium'
  vendor_url: 'https://hostium.com'
```

Esa URL es de diseño. `package verify` no la descarga.

## Comandos

```powershell
python -m hostium_waf package build --version 1.0.0 --engine 2.9.15
python -m hostium_waf package verify --zip dist/hostium-1.0.0.zip --metadata dist/meta_hostium.yaml
python -m hostium_waf metadata show --file dist/meta_hostium.yaml
```

Son locales. No modifican un servidor.

## Qué rechaza el validador

Ruta con `..`, ruta absoluta, symlink, nombre repetido, archivo vacío, raíz distinta de `hostium/`, subdirectorios, extensión que no sea `.conf`, `.example`, MD5 que no coincide con SHA512, clave de motor interpretada como número, `report_url`.

## Canales

`--channel stable` y `--channel canary` cambian el path de la URL y escriben `dist/channels/<canal>/meta_hostium.yaml`. WHM no tiene un selector de canal: recuerda la URL con la que se dio de alta el vendor.

## Verificación

Dos ejecuciones de `package build` con la misma versión y el mismo árbol dejan ZIPs idénticos. La prueba está en `tests/unit/test_empaquetado.py`.

## Deshacer un artefacto local

Borrar `dist/` si nadie publicó esa versión. Si ya se entregó el archivo, no lo regeneres: publicá otra versión.

## Problemas frecuentes

Incluir sin querer el selftest. El empaquetador ignora `*.example` y además falla si el texto empaquetado contiene `INCOMPLETO`.

## Referencias

`docs/REFERENCIAS.md`.

## Limitaciones

No se comprobó `modsec_vendor add` contra un WHM. El contrato se implementó según la documentación, con las tres discrepancias anotadas en las referencias.
