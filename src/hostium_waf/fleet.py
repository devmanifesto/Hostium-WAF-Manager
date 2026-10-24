"""Auditoría de solo lectura.

Los comandos remotos salen de una lista fija. El inventario no puede elegir el comando.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from hostium_waf.errors import UsageError
from hostium_waf.models import Inventory, Server
from hostium_waf.security import host_reservado

# Comandos fijos, sin metacaracteres de shell. SSH los ejecuta como un único argumento.
COMANDOS_SOLO_LECTURA: dict[str, str] = {
    "hostname": "hostname",
    "os_release": "cat /etc/os-release",
    "cpanel_version": "/usr/local/cpanel/cpanel -V",
    "apache_version": "httpd -v",
    "apache_modules": "httpd -M",
    "modsec_rpm": "rpm -q ea-apache24-mod_security2",
    "owasp_rpm": "rpm -q ea-modsec2-rules-owasp-crs",
    "vendor_list": "/usr/local/cpanel/scripts/modsec_vendor list",
    "httpd_syntax": "httpd -t",
    "httpd_includes": "httpd -t -D DUMP_INCLUDES",
    "nginx_rpm": "rpm -q ea-nginx",
    "engintron_dir": "test -d /usr/local/src/engintron",
}


@dataclass
class ResultadoComando:
    id: str
    comando: str
    ejecutado: bool
    codigo: int | None
    stdout: str
    stderr: str


@dataclass
class AuditoriaServidor:
    name: str
    ssh_host: str
    ring: str
    estado: str
    fuente: str
    comandos: list[ResultadoComando] = field(default_factory=list)
    inferencias: list[str] = field(default_factory=list)


@dataclass
class AuditoriaFlota:
    ejecutado: bool
    dry_run: bool
    fuente: str
    es_ejemplo: bool
    servidores: list[AuditoriaServidor]
    nota: str


def auditar(
    inventory: Inventory,
    *,
    dry_run: bool = False,
    backend: str = "auto",
    fixture_dir: Path | None = None,
) -> AuditoriaFlota:
    if backend not in {"auto", "ssh", "fixture"}:
        raise UsageError("backend debe ser auto, ssh o fixture")
    servidores: list[AuditoriaServidor] = []
    for server in inventory.servers:
        servidores.append(_auditar_servidor(server, dry_run=dry_run, backend=backend, fixture_dir=fixture_dir))
    fuente = "dry-run" if dry_run else backend
    return AuditoriaFlota(
        ejecutado=any(item.fuente == "ssh" for item in servidores),
        dry_run=dry_run,
        fuente=fuente,
        es_ejemplo=inventory.es_ejemplo,
        servidores=servidores,
        nota=(
            "Auditoría de solo lectura. No modifica configuración ni reinicia servicios. "
            "La sintaxis de Apache no demuestra protección efectiva. "
            "Los hosts .invalid no se contactan."
        ),
    )


def _auditar_servidor(
    server: Server,
    *,
    dry_run: bool,
    backend: str,
    fixture_dir: Path | None,
) -> AuditoriaServidor:
    if dry_run:
        return _plan(server, fuente="dry-run", estado="planificado")
    if host_reservado(server.ssh_host):
        if backend == "fixture":
            return _desde_fixture(server, fixture_dir)
        return AuditoriaServidor(
            name=server.name,
            ssh_host=server.ssh_host,
            ring=server.ring,
            estado="omitido_ejemplo",
            fuente="reserva",
            inferencias=["Host de documentación (.invalid/.example/.test/.localhost). No se abrió SSH."],
        )
    if backend == "fixture":
        return _desde_fixture(server, fixture_dir)
    if backend == "auto":
        return AuditoriaServidor(
            name=server.name,
            ssh_host=server.ssh_host,
            ring=server.ring,
            estado="no_ejecutado",
            fuente="auto",
            inferencias=[
                "backend auto no abre SSH. Repetí la auditoría con --backend ssh si el host es real y la llave ya está autorizada."
            ],
        )
    return _por_ssh(server)


def _plan(server: Server, *, fuente: str, estado: str) -> AuditoriaServidor:
    comandos = [
        ResultadoComando(id=clave, comando=valor, ejecutado=False, codigo=None, stdout="", stderr="")
        for clave, valor in COMANDOS_SOLO_LECTURA.items()
    ]
    return AuditoriaServidor(
        name=server.name,
        ssh_host=server.ssh_host,
        ring=server.ring,
        estado=estado,
        fuente=fuente,
        comandos=comandos,
        inferencias=["Dry-run: no se ejecutó ningún comando."],
    )


def _desde_fixture(server: Server, fixture_dir: Path | None) -> AuditoriaServidor:
    base = fixture_dir or Path("tests/fixtures/fleet")
    comandos: list[ResultadoComando] = []
    for clave, comando in COMANDOS_SOLO_LECTURA.items():
        archivo = base / server.name / f"{clave}.txt"
        if not archivo.is_file():
            comandos.append(
                ResultadoComando(clave, comando, True, 127, "", f"sin fixture {archivo.name}")
            )
            continue
        comandos.append(ResultadoComando(clave, comando, True, 0, archivo.read_text(encoding="utf-8"), ""))
    auditoria = AuditoriaServidor(
        name=server.name,
        ssh_host=server.ssh_host,
        ring=server.ring,
        estado="fixture",
        fuente="fixture",
        comandos=comandos,
    )
    auditoria.inferencias = _inferir(comandos) + ["Fuente fixture: no es una captura de un servidor real."]
    return auditoria


def _por_ssh(server: Server) -> AuditoriaServidor:
    comandos: list[ResultadoComando] = []
    fallo_conexion = False
    for clave, comando in COMANDOS_SOLO_LECTURA.items():
        argv = _argv_ssh(server, comando)
        try:
            completado = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=20,
                shell=False,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            fallo_conexion = True
            comandos.append(ResultadoComando(clave, comando, False, None, "", str(exc)))
            break
        comandos.append(
            ResultadoComando(
                clave,
                comando,
                True,
                completado.returncode,
                completado.stdout,
                completado.stderr,
            )
        )
        if completado.returncode == 255:
            fallo_conexion = True
            break
    estado = "error_conexion" if fallo_conexion else "leido"
    auditoria = AuditoriaServidor(
        name=server.name,
        ssh_host=server.ssh_host,
        ring=server.ring,
        estado=estado,
        fuente="ssh",
        comandos=comandos,
    )
    auditoria.inferencias = _inferir(comandos)
    return auditoria


def _argv_ssh(server: Server, comando: str) -> list[str]:
    if comando not in COMANDOS_SOLO_LECTURA.values():
        raise ValueError("comando fuera de la lista de solo lectura")
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=8",
        "-p",
        str(server.port),
        "--",
        f"{server.ssh_user}@{server.ssh_host}",
        comando,
    ]


def _inferir(comandos: list[ResultadoComando]) -> list[str]:
    por_id = {item.id: item.stdout for item in comandos}
    notas = [
        "La presencia de un vendor o Syntax OK no demuestra un bloqueo de extremo a extremo.",
        "Esta auditoría no ejecuta enable-updates. El alta de actualizaciones es un comando aparte y modifica el servidor.",
    ]
    vendor = por_id.get("vendor_list", "")
    if "hostium" in vendor.lower():
        notas.append("La salida menciona hostium. Confirmá enabled e in_use en el servidor; esto no instala nada.")
    elif vendor:
        notas.append("La salida de vendors no menciona hostium.")
    nginx = por_id.get("nginx_rpm", "")
    if "not installed" in nginx.lower() or "no está instalado" in nginx.lower():
        notas.append("rpm no muestra ea-nginx. Puede existir otro proxy: la ausencia de ese RPM no cierra el tema.")
    elif nginx.strip():
        notas.append("rpm devolvió texto para ea-nginx. Tratá el dato como inferencia hasta leer la versión.")
    return notas
