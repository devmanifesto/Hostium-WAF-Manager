"""Planes de rollback. apply permanece bloqueado."""

from __future__ import annotations

from hostium_waf.errors import BlockedOperation, UsageError
from hostium_waf.models import Inventory
from hostium_waf.validation import ANILLOS

_MOTIVO = (
    "rollback apply está bloqueado. No hay una captura previa ensayada ni una restauración "
    "idempotente. El flag --approve no habilita esta operación."
)


def plan_rollback(inventory: Inventory, ring: str) -> dict[str, object]:
    if ring not in ANILLOS:
        raise UsageError("El anillo debe ser lab, pilot, canary o production")
    servidores = [server.name for server in inventory.servers if server.ring == ring]
    return {
        "ok": True,
        "accion": "rollback plan",
        "ejecutado": False,
        "modifica_servidores": False,
        "ring": ring,
        "es_ejemplo": inventory.es_ejemplo,
        "servidores": servidores,
        "vias": [
            {
                "nombre": "rapida",
                "efecto": "deja de cargar el vendor hostium sin tocar los RPM de OWASP",
                "pasos": [
                    "SOLO LECTURA. modsec_vendor list y copiar la salida.",
                    "PRODUCCIÓN / MODIFICA. modsec_vendor disable hostium.",
                    "SOLO LECTURA. httpd -t. REINICIA solo si la operación no recargó Apache y hay una ventana aprobada.",
                    "Comprobar que OWASP3 sigue enabled. El rollback de Hostium no debe apagar CRS.",
                ],
            },
            {
                "nombre": "versionada",
                "efecto": "vuelve a la metadata y al ZIP de la release anterior",
                "pasos": [
                    "Elegir la release anterior ya verificada en dist/releases o en el canal de publicación.",
                    "PRODUCCIÓN / MODIFICA. Publicar primero el ZIP anterior, verificar el hash y después la metadata.",
                    "Antes de rehabilitar el vendor, confirmar que las actualizaciones automáticas no reintroducen la versión retirada.",
                    "Si el flag sigue activo, modsec_vendor disable-updates hostium.",
                    "O publicá antes la metadata de la release anterior: si no, upcp puede reinstalar la versión retirada.",
                ],
            },
        ],
        "bloqueos": [_MOTIVO],
    }


def apply_rollback() -> None:
    raise BlockedOperation(_MOTIVO)
