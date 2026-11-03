# Hostium WAF Manager

Herramienta para mantener un ruleset ModSecurity propio, empaquetarlo como proveedor de cPanel/WHM y auditar una flota sin tocarla por defecto.

La estable de este árbol es **2.1.7**. Suma `5500917`: en el POST bajo `/aplicacion_customs/MCP/`, quita cinco reglas XSS de ARGS entero. Conserva 5500900–5500916.

La publicación fue autorizada por el operador; la actualización de calcium queda a su cargo. No se ejecutó SSH ni se marcó ultima_validacion. El estado de esta release está en [QA de la release](docs/28-RELEASE-2.1.7.md). La anterior quedó en [2.1.6](docs/27-RELEASE-2.1.6.md).

## Requisitos

- Python 3.11 o superior. En el equipo de desarrollo se usó 3.14.4.
- Git.
- Docker, solo si vas a correr la prueba HTTP contra Apache y ModSecurity.

No hace falta cPanel en la máquina donde se desarrolla.

## Inicio

```powershell
python -m pip install -e ".[dev]"
python -m hostium_waf version
python -m hostium_waf doctor --local
python -m hostium_waf rules validate
python -m hostium_waf package build --version 2.1.7 --output dist/release-2.1.7 --engine 2.9.15
python -m hostium_waf package verify --zip dist/release-2.1.7/hostium-2.1.7.zip --metadata dist/release-2.1.7/meta_hostium.yaml
```

`python -m pytest` corre la suite unitaria. `python -m pytest -m integration --override-ini="addopts="` levanta Apache. Si Docker no está en marcha, esa prueba se omite y el informe lo dice: una omisión no es un bloqueo comprobado.

## Diagnosticar falsos positivos

```powershell
# SOLO LECTURA local. No abre SSH ni genera excepciones automáticamente.
python -m hostium_waf logs analyze --input C:/evidencias/error.log --server nodo-piloto
```

El analizador agrupa por transacción, ID, variable, dominio y ruta; oculta ubicaciones por defecto y elimina query, valores y cuerpos. `--include-locations` permite investigar las rutas explícitamente. Ver [observabilidad](docs/12-OBSERVABILIDAD-Y-LOGS.md).

Las nuevas exclusiones con dominio exigen dominio exacto, ruta sin query, método y parámetro. 5500905 es la excepción de path: sin dominio, solo GET y el prefijo `/pluginfile.php/`. 5500907–5500912 y 5500914–5500915 son rutas POST sin dominio. 5500913 y 5500916 son un nombre de campo, sin URI. ARGS entero está en 5500912 y, para cinco XSS, en 5500917. WHMCS ya tiene alcance confirmado. Las otras cuatro excepciones se conservan temporalmente desde la 2.1.1: son una deuda explícita de alcance. El modo heredado solo acepta los controles e IDs del ZIP base fijado por SHA256; no permite ampliarlos. PrestaShop selecciona path sin query.

La candidata local 2.1.2 no se publicó ni reescribió. [Guía de tuning](docs/13-FALSOS-POSITIVOS-Y-EXCEPCIONES.md).

## Contenido de la estable 2.1.7

Dos conf: REQUEST-410-PHP-UPLOAD-PROGRESS y REQUEST-900-CRS-EXCLUSIONS. Conserva IDs, fases y acciones de 2.1.1; REQUEST-410 solo actualiza trazabilidad ver y encabezado. No entra REQUEST-910, no se instala hostium-tune ni se cambia el puntaje global. No se empaquetan ejemplos o reglas de fase 4.

El ZIP extrae bajo hostium/. La metadata es meta_hostium.yaml y la clave 2.9.15 identifica el motor, no el ruleset. CI toma la versión del código y exige lint, unitarias e integración estricta antes de generar releases. Las distribuciones anteriores permanecen inmutables.

## Sumarlo en cPanel

La ruta que hay que dar de alta es la metadata. WHM lee ese YAML y baja el ZIP que figura adentro. Las dos URL son públicas y responden sin sesión:

- Metadata: `https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml`
- ZIP: `https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/hostium-2.1.7.zip`

Esa metadata instala `hostium-2.1.7`: dos sets, `REQUEST-410` y `REQUEST-900`. Es el único meta de instalación. Los ZIP anteriores, incluido `hostium-2.1.6.zip`, siguen en el mismo directorio y no se reescriben. Un cPanel que ya tiene el vendor hostium relee esta metadata cuando corre `upcp`, si las actualizaciones del vendor están activas. Un vendor deshabilitado no aplica las reglas aunque baje el ZIP. Este repositorio no ejecutó `upcp`, `modsec_vendor` ni `httpd -t`.

En el servidor, como root:

```sh
/usr/local/cpanel/scripts/modsec_vendor add 'https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml'
```

En la interfaz es el mismo dato: WHM » Security Center » ModSecurity Vendors, y la URL de configuración del vendor es la de la metadata.

Después, solo lectura:

```sh
/usr/local/cpanel/scripts/modsec_vendor list
httpd -t
httpd -t -D DUMP_INCLUDES
```

El `vendor_id` queda `hostium`. Después del alta, las actualizaciones automáticas se activan con:

```sh
/usr/local/cpanel/scripts/modsec_vendor enable-updates hostium
```

Ese flag no baja el ZIP en el momento. cPanel relee la metadata cuando corre `/usr/local/cpanel/scripts/upcp`. La documentación oficial nombra el argumento `enable-updates` y, en el ejemplo de la misma fila, escribe `enable_updates`. Usamos el nombre del argumento. `hostium-waf updates plan` imprime el comando. `updates apply` no abre SSH. Para retirarlo, `modsec_vendor disable hostium`. Si las actualizaciones quedaron activas y hay que frenar una release, `modsec_vendor disable-updates hostium`. OWASP3 tiene que seguir habilitado.

En un dominio de prueba, `https://<dominio>/.env` tiene que responder 403 con el id `930130` de CRS. `5500100` no tiene que aparecer: salió del ZIP en 2.0.0. `https://<dominio>/environment` no tiene que mostrar `930130` por la frase `/.env` si la ruta no la contiene. Un POST de laboratorio con cientos de campos `name=` no tiene que mostrar `5500615`.

Ese `modsec_vendor add` modifica el servidor. No se ejecutó desde este repositorio.

## Comandos que no actúan

`deploy apply`, `rollback apply` y `publish apply` terminan con código 3 aunque pases `--approve`. `fleet audit` sobre `*.example.invalid` no abre SSH. El inventario de ejemplo no es calcium.

## Documentación

El alcance está en [docs/ESPECIFICACION_MAESTRA.md](docs/ESPECIFICACION_MAESTRA.md). El plan ejecutado está en [docs/00-PLAN-DE-IMPLEMENTACION.md](docs/00-PLAN-DE-IMPLEMENTACION.md). El runbook de calcium, sin haberlo ejecutado, está en [docs/09-DESPLIEGUE-CALCIUM.md](docs/09-DESPLIEGUE-CALCIUM.md).

## Licencia

Apache 2.0. No incluye reglas de Imunify360 ni de Comodo. OWASP CRS sigue siendo el ruleset del RPM de cPanel y no se modifica.

## Actualizar el vendor ya instalado

El operador pidió ejecutar este paso por su cuenta en calcium:

```sh
# PRODUCCIÓN: ejecutar solo después de guardar estado previo y verificar la publicación.
/usr/local/cpanel/scripts/modsec_vendor update hostium
# SOLO LECTURA: comprobar versión 2.1.7, 2/2 sets e includes.
/usr/local/cpanel/scripts/modsec_vendor list
httpd -t
httpd -t -D DUMP_INCLUDES
```

Repetir el guardado legítimo en WHMCS y correlacionar su request ID: no deben aparecer 921130 ni 949110 para ese POST de plantilla. Un 404 aislado no demuestra el origen. No enviar payloads maliciosos ni sobrescribir opciones reales como prueba. Si hace falta una recarga, verificar primero la sintaxis y coordinarla; este repositorio no ejecutó servicios remotos.
