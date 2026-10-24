from __future__ import annotations

from hostium_waf.errors import BlockedOperation, HostiumError
from hostium_waf.updates import apply_activacion, grafia_desde_ayuda, plan_activacion

URL = "https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml"


def test_plan_usa_el_argumento_documentado() -> None:
    plan = plan_activacion(URL)
    assert plan["ejecutado"] is False
    assert plan["modifica_servidores"] is False
    assert plan["comprobado_en_cpanel"] is False
    assert plan["grafia"] == "enable-updates"
    assert plan["argv"] == [
        "/usr/local/cpanel/scripts/modsec_vendor",
        "enable-updates",
        "hostium",
    ]
    assert plan["url_metadata"] == URL


def test_ayuda_con_las_dos_grafias_elige_el_argumento() -> None:
    texto = "enable-updates vendor_id\nExample: modsec_vendor enable_updates OWASP3\n"
    assert grafia_desde_ayuda(texto) == "enable-updates"
    plan = plan_activacion(URL, texto)
    assert plan["grafia"] == "enable-updates"
    assert plan["ayuda_lista_las_dos"] is True
    assert plan["origen_grafia"] == "ayuda"


def test_ayuda_solo_con_guion_bajo() -> None:
    assert grafia_desde_ayuda("usage: modsec_vendor enable_updates vendor_id\n") == "enable_updates"


def test_ayuda_sin_grafia_falla() -> None:
    try:
        grafia_desde_ayuda("list add remove update enable disable\n")
    except HostiumError as exc:
        assert "no menciona" in str(exc)
    else:
        raise AssertionError("debía rechazar una ayuda sin el subcomando")


def test_apply_no_abre_ssh() -> None:
    try:
        apply_activacion()
    except BlockedOperation as exc:
        assert exc.exit_code == 3
        assert "enable-updates hostium" in str(exc)
        assert "no abre SSH" in str(exc)
    else:
        raise AssertionError("apply debía quedar bloqueado")
