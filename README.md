# Hostium WAF Manager

Herramienta para mantener un ruleset ModSecurity propio, empaquetarlo como proveedor de cPanel/WHM y auditar una flota sin tocarla por defecto.

La versión de ruleset que construye este árbol es la 1.1.2. El ZIP `hostium-1.0.0.zip` publicado en `publish/stable/` no se regenera. `hostium-1.1.0` no se publicó. `hostium-1.1.1.zip` queda como estaba. No instala nada en calcium y no trata una sintaxis válida como una prueba de bloqueo en producción.

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
python -m hostium_waf package build --version 1.1.2 --engine 2.9.15
python -m hostium_waf package verify --zip dist/hostium-1.1.2.zip --metadata dist/meta_hostium.yaml
```

`python -m pytest` corre la suite unitaria. `python -m pytest -m integration --override-ini="addopts="` levanta Apache. Si Docker no está en marcha, esa prueba se omite y el informe lo dice: una omisión no es un bloqueo comprobado.

## Qué entra al ZIP estable

`hostium-1.1.2.zip` lleva dos `.conf`: `REQUEST-100-SENSITIVE-FILES.conf` (ids `5500100` y `5500101`) y `REQUEST-410-PHP-UPLOAD-PROGRESS.conf` (ids de pedido `5500600`–`5500619` y `5500621`, `5500622`, `5500625`, incluidos los contadores `5500606`, `5500607` y `5500608`). Las de fase 4 (`5500620`, `5500623`, `5500624`, `5500626`) quedan en un `.example` y no se empaquetan: en cPanel no se enciende `SecResponseBodyAccess` para todo el servidor. Esas reglas no reemplazan actualizar PHP. El selftest `5500000` vive en un `.example` y no se empaqueta. Los borradores de WordPress, PHP genérico, el id vacío `5500400` y los escáneres tampoco.

El ZIP extrae un único directorio `hostium/`. La metadata se llama `meta_hostium.yaml`. La clave `'2.9.15'` es la versión del motor, no la del ruleset. `distribution: hostium-1.1.2` identifica esta release. `hostium-1.0.0` y `hostium-1.1.1` siguen publicados y no se reescriben. `package build --version 1.0.0` falla a propósito.

## Sumarlo en cPanel

La ruta que hay que dar de alta es la metadata. WHM lee ese YAML y baja el ZIP que figura adentro. Las dos URL son públicas y responden sin sesión:

- Metadata: `https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml`
- ZIP: `https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/hostium-1.1.2.zip`

Esa metadata instala `hostium-1.1.2`: dos sets, `REQUEST-100-SENSITIVE-FILES.conf` y `REQUEST-410-PHP-UPLOAD-PROGRESS.conf`. Los ZIP `hostium-1.0.0.zip` y `hostium-1.1.1.zip` siguen en el mismo directorio y no se reescriben. Un cPanel que ya tiene el vendor relee esta metadata cuando corre `upcp`, si las actualizaciones del vendor están activas. Este repositorio no ejecutó `upcp` ni `modsec_vendor`.

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

En un dominio de prueba, `https://<dominio>/.env` tiene que responder 403 con el id `5500100` en el Hits List o en el audit log. `https://<dominio>/environment` no tiene que mostrar ese id. Un 403 sin `5500100` no cuenta como éxito de esta regla.

Ese `modsec_vendor add` modifica el servidor. No se ejecutó desde este repositorio.

## Comandos que no actúan

`deploy apply`, `rollback apply` y `publish apply` terminan con código 3 aunque pases `--approve`. `fleet audit` sobre `*.example.invalid` no abre SSH. El inventario de ejemplo no es calcium.

## Documentación

El alcance está en [docs/ESPECIFICACION_MAESTRA.md](docs/ESPECIFICACION_MAESTRA.md). El plan ejecutado está en [docs/00-PLAN-DE-IMPLEMENTACION.md](docs/00-PLAN-DE-IMPLEMENTACION.md). El runbook de calcium, sin haberlo ejecutado, está en [docs/09-DESPLIEGUE-CALCIUM.md](docs/09-DESPLIEGUE-CALCIUM.md).

## Licencia

Apache 2.0. No incluye reglas de Imunify360 ni de Comodo. OWASP CRS sigue siendo el ruleset del RPM de cPanel y no se modifica.
