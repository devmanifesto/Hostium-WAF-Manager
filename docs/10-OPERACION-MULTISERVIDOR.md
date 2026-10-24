# Operación multiservidor

## Objetivo

Inventariar y planificar por anillos sin escribir en los servidores.

## Audiencia

Operación de la flota.

## Prerrequisitos

`config/fleet.example.yaml` para practicar. Un inventario real, si existe, no se commitea con secretos y usa hosts que no terminen en `.invalid` solo cuando de verdad sean esos hosts.

## Anillos

`lab`, luego `pilot`, luego `canary`, luego `production`. No se salta un anillo con fallos abiertos. La promoción es humana. La CLI no la hace.

## Inventario

```yaml
servers:
  - name: calcium
    ssh_host: calcium.example.invalid
    ssh_user: root
    ring: pilot
    environment: production
    tags: [cpanel, cloudlinux, apache, possible-nginx]
```

Ese host es de documentación. `fleet audit` lo omite y no abre SSH.

## Comandos

```powershell
python -m hostium_waf fleet list --inventory config/fleet.example.yaml
python -m hostium_waf --dry-run fleet audit --inventory config/fleet.example.yaml
python -m hostium_waf fleet audit --inventory config/fleet.example.yaml --backend fixture
python -m hostium_waf deploy plan --ring pilot --version 1.0.0
python -m hostium_waf rollback plan --ring pilot
```

`deploy apply` y `rollback apply` terminan en código 3.

## SSH, si más adelante el backend es ssh

La lista de comandos está fija en `fleet.py`: `hostname`, `httpd -t`, `modsec_vendor list`, los `rpm -q` del motor y de CRS, y poco más. El inventario no puede agregar un comando. `StrictHostKeyChecking=yes`. No hay modo que lo apague. La identidad sale de `known_hosts` y la clave, del agente.

Hace falta un usuario que pueda leer esos comandos. El ejemplo usa `root` porque la especificación lo usó. Un usuario de solo lectura es preferible cuando exista el sudoers correspondiente. No está implementado un wrapper de sudo.

## Idempotencia

No hay apply idempotente. Por eso el apply no existe como éxito.

## Auditoría del plan

El JSON de `deploy plan` lleva `ejecutado: false` y `modifica_servidores: false`. Cuando exista un apply de verdad, el registro tendrá que sumar actor, fecha, commit, versión, hashes y código de salida. Hoy ese registro no se fabrica.

## Verificación

`fleet audit --backend auto` sobre el ejemplo deja cada servidor en `omitido_ejemplo`. La prueba unitaria falla si alguien llama a `subprocess.run` en ese camino.

## Deshacer

No hay cambio remoto. Borrar un inventario local no altera la flota.

## Problemas frecuentes

Tratar la fixture `Syntax OK (FIXTURE)` como una captura de calcium. El texto lo dice. La fuente del resultado es `fixture`.

## Referencias

`docs/09-DESPLIEGUE-CALCIUM.md` y `docs/15-SEGURIDAD-Y-MODELO-DE-AMENAZAS.md`.

## Limitaciones

No hay backend Ansible implementado. La interfaz es la lista de comandos y el transporte SSH directo. Un playbook puede envolver lo mismo más adelante, sin ampliar los comandos permitidos.
