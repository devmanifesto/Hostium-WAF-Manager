"""Activación de las actualizaciones del vendor hostium.

cPanel las aplica cuando corre upcp: relee la metadata con la que se instaló
el vendor y, si el ZIP cambió, lo baja. Esta CLI no abre SSH.
"""

from __future__ import annotations

import re

from hostium_waf.errors import BlockedOperation, HostiumError, UsageError

SCRIPT = "/usr/local/cpanel/scripts/modsec_vendor"
VENDOR_ID = "hostium"
GRAFIA_DOCUMENTADA = "enable-updates"
_GRAFIAS = frozenset({GRAFIA_DOCUMENTADA, "enable_updates"})
_TOKEN = re.compile(r"\b(enable-updates|enable_updates)\b")

_NOTA_DOCUMENTADA = (
    "La tabla de argumentos de docs.cpanel.net, modificada el 8 de julio de 2026, "
    "nombra enable-updates. El ejemplo de esa misma fila escribe enable_updates. "
    "Este comando usa el nombre del argumento. No se ejecutó en un cPanel."
)


def url_metadata(base_url: str, canal: str) -> str:
    if canal not in {"stable", "canary"}:
        raise UsageError("El canal debe ser stable o canary")
    return f"{base_url.rstrip('/')}/{canal}/meta_hostium.yaml"


def grafia_desde_ayuda(texto: str) -> str:
    """Elige el subcomando que muestra la ayuda.

    Si aparecen las dos grafías, gana enable-updates: es el nombre del argumento
    en la documentación oficial. Una ayuda que solo dice enable_updates se respeta.
    """
    encontrados = set(_TOKEN.findall(texto))
    if not encontrados:
        raise HostiumError("La ayuda no menciona enable-updates ni enable_updates.")
    if encontrados == {"enable_updates"}:
        return "enable_updates"
    return GRAFIA_DOCUMENTADA


def argv_activacion(grafia: str) -> list[str]:
    if grafia not in _GRAFIAS:
        raise UsageError("La grafía de actualización no es enable-updates ni enable_updates")
    return [SCRIPT, grafia, VENDOR_ID]


def plan_activacion(url: str, ayuda: str | None = None) -> dict[str, object]:
    if ayuda is None:
        grafia = GRAFIA_DOCUMENTADA
        origen = "documentacion"
        ambas = False
    else:
        grafia = grafia_desde_ayuda(ayuda)
        origen = "ayuda"
        ambas = _TOKEN.findall(ayuda).count("enable-updates") > 0 and "enable_updates" in ayuda
    argv = argv_activacion(grafia)
    return {
        "ok": True,
        "accion": "updates plan",
        "ejecutado": False,
        "modifica_servidores": False,
        "vendor_id": VENDOR_ID,
        "grafia": grafia,
        "origen_grafia": origen,
        "ayuda_lista_las_dos": ambas,
        "comprobado_en_cpanel": False,
        "argv": argv,
        "comando": " ".join(argv),
        "url_metadata": url,
        "cuando_corre": (
            "cPanel busca metadata nueva cuando corre /usr/local/cpanel/scripts/upcp. "
            "enable-updates no descarga el ZIP en ese instante."
        ),
        "nota": _NOTA_DOCUMENTADA if origen == "documentacion" else "Grafía leída de un texto de ayuda local. No se abrió SSH.",
    }


def apply_activacion() -> None:
    comando = " ".join(argv_activacion(GRAFIA_DOCUMENTADA))
    raise BlockedOperation(
        "updates apply no abre SSH ni cambia el servidor. "
        f"En el cPanel, como root: {comando}"
    )
