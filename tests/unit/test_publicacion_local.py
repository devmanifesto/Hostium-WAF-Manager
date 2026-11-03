from __future__ import annotations

from pathlib import Path

import pytest

from hostium_waf.crs_vendor import VERSION_RULESET
from hostium_waf.errors import HostiumError
from hostium_waf.packaging import build_package, verify_package
from hostium_waf.publishing import copiar_publicacion_local
from hostium_waf.settings import load_settings

ROOT = Path(__file__).resolve().parents[2]


def test_copia_idempotente_y_no_reemplaza_zip_distinto(tmp_path):
    artefacto = build_package(ROOT, load_settings(ROOT), version=VERSION_RULESET, engine="2.9.15", output=tmp_path / "build")
    destino = tmp_path / "stable"
    for _ in range(2):
        archivo = copiar_publicacion_local(artefacto.zip_path, artefacto.metadata_path, destino)
        assert verify_package(archivo, destino / "meta_hostium.yaml") == []
    metadata_antes = (destino / "meta_hostium.yaml").read_bytes()
    archivo.write_bytes(b"otra release")
    with pytest.raises(HostiumError, match="no se sobrescribe"):
        copiar_publicacion_local(artefacto.zip_path, artefacto.metadata_path, destino)
    assert (destino / "meta_hostium.yaml").read_bytes() == metadata_antes
    assert archivo.read_bytes() == b"otra release"


def test_zip_ausente_devuelve_hallazgo(tmp_path):
    assert verify_package(tmp_path / "ausente.zip", tmp_path / "meta_hostium.yaml")
