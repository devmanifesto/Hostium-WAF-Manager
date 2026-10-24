"""Planes de despliegue. apply permanece bloqueado: no hay escritura SSH."""

from __future__ import annotations

from pathlib import Path

from hostium_waf.errors import BlockedOperation, UsageError
from hostium_waf.models import Inventory
from hostium_waf.security import es_semver
from hostium_waf.validation import ANILLOS

_MOTIVO = (
    "deploy apply está bloqueado. Faltan captura del estado anterior, ejecución idempotente ensayada, "
    "verificación posterior y rollback ensayado. El flag --approve no habilita esta operación."
)


def plan_despliegue(inventory: Inventory, ring: str, version: str, artefacto: Path | None) -> dict[str, object]:
    if ring not in ANILLOS:
        raise UsageError("El anillo debe ser lab, pilot, canary o production")
    if not es_semver(version):
        raise UsageError("La versión del ruleset debe ser SemVer")
    servidores = [server for server in inventory.servers if server.ring == ring]
    return {
        "ok": True,
        "accion": "deploy plan",
        "ejecutado": False,
        "modifica_servidores": False,
        "ring": ring,
        "version": version,
        "es_ejemplo": inventory.es_ejemplo,
        "artefacto_local": str(artefacto) if artefacto else None,
        "artefacto_presente": bool(artefacto and artefacto.is_file()),
        "servidores": [server.name for server in servidores],
        "pasos_humanos": [
            "SOLO LECTURA. En cada servidor del anillo, correr scripts/discover-cpanel.sh y guardar la salida fuera del repositorio.",
            "SOLO LECTURA. httpd -t -D DUMP_INCLUDES y anotar si OWASP3 está incluido y en qué orden respecto de hostium.",
            "PRODUCCIÓN / MODIFICA. Solo con aprobación explícita y en laboratorio o piloto: /usr/local/cpanel/scripts/modsec_vendor add <URL HTTPS de meta_hostium.yaml>.",
            "SOLO LECTURA. /usr/local/cpanel/scripts/modsec_vendor list y comprobar enabled e in_use del vendor hostium.",
            "MODIFICA / REINICIA. No asumir que el alta del vendor recarga Apache. Un graceful queda para la ventana aprobada.",
            "SOLO LECTURA. Smoke test en un dominio autorizado: pedir /.env, observar 403 y el id 5500100 en el log de auditoría. Un 403 sin ese id no cuenta.",
            "PRODUCCIÓN / MODIFICA. Con el vendor ya instalado: /usr/local/cpanel/scripts/modsec_vendor enable-updates hostium. upcp es el que después relee la metadata.",
        ],
        "bloqueos": [_MOTIVO],
    }


def apply_despliegue() -> None:
    raise BlockedOperation(_MOTIVO)


def verificar_despliegue_local(zip_path: Path, metadata_path: Path) -> dict[str, object]:
    zip_ok = zip_path.is_file()
    meta_ok = metadata_path.is_file()
    return {
        "ok": bool(zip_ok and meta_ok),
        "accion": "deploy verify",
        "remoto": "no_ejecutado",
        "modifica_servidores": False,
        "zip_presente": zip_ok,
        "metadata_presente": meta_ok,
        "nota": "La verificación remota no se ejecutó. Este resultado solo dice si el artefacto local está en disco.",
    }
