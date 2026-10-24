"""CLI hostium-waf. La salida JSON va a stdout; el texto humano también, salvo los errores."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer

from hostium_waf import __version__
from hostium_waf.deployment import apply_despliegue, plan_despliegue, verificar_despliegue_local
from hostium_waf.doctor import capacidades_locales, doctor_local, inicializar
from hostium_waf.errors import EXIT_ERROR, HostiumError, Issue
from hostium_waf.fleet import auditar
from hostium_waf.inventory import load_inventory, resolver_inventario
from hostium_waf.metadata import load_metadata
from hostium_waf.models import Settings
from hostium_waf.packaging import build_package, verify_package
from hostium_waf.publishing import apply_publicacion, plan_publicacion
from hostium_waf.reporting import cargar_evidencia_integracion, escribir_informe, generar_informe
from hostium_waf.rollback import apply_rollback, plan_rollback
from hostium_waf.settings import find_root, load_settings, load_yaml, ruta_dentro
from hostium_waf.validation import validar_repositorio


class _BanderasAlFinal(typer.core.TyperGroup):
    """Acepta --json, --verbose y --dry-run también después del subcomando."""

    _banderas = frozenset({"--json", "--verbose", "--dry-run"})

    def parse_args(self, ctx: typer.Context, args: list[str]) -> list[str]:
        adelantadas = [item for item in args if item in self._banderas]
        resto = [item for item in args if item not in self._banderas]
        return super().parse_args(ctx, [*adelantadas, *resto])


app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False, add_completion=False, cls=_BanderasAlFinal)
rules_app = typer.Typer(no_args_is_help=True, help="Inspecciona el manifiesto y los archivos SecLang.")
package_app = typer.Typer(no_args_is_help=True, help="Construye y verifica el ZIP del vendor.")
metadata_app = typer.Typer(no_args_is_help=True, help="Muestra meta_hostium.yaml.")
publish_app = typer.Typer(no_args_is_help=True, help="Describe la publicación. No sube archivos.")
fleet_app = typer.Typer(no_args_is_help=True, help="Inventario y auditoría de solo lectura.")
deploy_app = typer.Typer(no_args_is_help=True, help="Planes de despliegue. apply está bloqueado.")
rollback_app = typer.Typer(no_args_is_help=True, help="Planes de rollback. apply está bloqueado.")
report_app = typer.Typer(no_args_is_help=True, help="Genera informes locales.")

app.add_typer(rules_app, name="rules")
app.add_typer(package_app, name="package")
app.add_typer(metadata_app, name="metadata")
app.add_typer(publish_app, name="publish")
app.add_typer(fleet_app, name="fleet")
app.add_typer(deploy_app, name="deploy")
app.add_typer(rollback_app, name="rollback")
app.add_typer(report_app, name="report")


@app.callback()
def principal(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json", help="Escribe el resultado en JSON por stdout."),
    verbose: bool = typer.Option(False, "--verbose", help="Más detalle. No imprime variables de entorno."),
    dry_run: bool = typer.Option(False, "--dry-run", help="No ejecuta acciones remotas. Es el modo seguro."),
) -> None:
    """Hostium WAF Manager: ruleset, paquetes cPanel y operación de flota."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = json_output
    ctx.obj["verbose"] = verbose
    ctx.obj["dry_run"] = dry_run


def _estado(ctx: typer.Context) -> dict[str, Any]:
    actual: typer.Context | None = ctx
    while actual is not None:
        if actual.obj:
            return actual.obj
        actual = actual.parent
    return {"json": False, "verbose": False, "dry_run": False}


def _emitir(ctx: typer.Context, datos: dict[str, Any], texto: str) -> None:
    if _estado(ctx).get("json"):
        sys.stdout.write(json.dumps(datos, ensure_ascii=False, indent=2) + "\n")
        return
    sys.stdout.write(texto.rstrip() + "\n")


def _ejecutar(ctx: typer.Context, accion: Any) -> None:
    try:
        accion()
    except HostiumError as exc:
        payload = {
            "ok": False,
            "codigo": exc.exit_code,
            "error": str(exc),
            "hallazgos": [item.formato() for item in exc.issues],
        }
        if _estado(ctx).get("json"):
            sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        else:
            sys.stderr.write(str(exc) + "\n")
            for item in exc.issues:
                sys.stderr.write(item.formato() + "\n")
            if _estado(ctx).get("verbose"):
                sys.stderr.write("Revisá los hallazgos. Este modo no vuelca el entorno.\n")
        raise typer.Exit(code=exc.exit_code) from exc


def _raiz() -> Path:
    return find_root()


def _settings(root: Path, settings: Path | None) -> Settings:
    return load_settings(root, settings)


def _validar(root: Path, settings: Settings) -> tuple[list[Issue], Any]:
    manifiesto = load_yaml(ruta_dentro(root, settings.manifiesto))
    politica = load_yaml(ruta_dentro(root, settings.politica))
    modelo, _, issues = validar_repositorio(root, settings, manifiesto, politica)
    return issues, modelo


@app.command("version")
def version(ctx: typer.Context) -> None:
    """Muestra la versión de la herramienta."""
    _emitir(ctx, {"ok": True, "version": __version__}, f"hostium-waf {__version__}")


@app.command("init")
def init(ctx: typer.Context) -> None:
    """Copia la configuración de ejemplo si todavía no existe."""

    def accion() -> None:
        mensajes = inicializar(_raiz())
        _emitir(ctx, {"ok": True, "mensajes": mensajes}, "\n".join(mensajes))

    _ejecutar(ctx, accion)


@app.command("doctor")
def doctor(
    ctx: typer.Context,
    local: bool = typer.Option(False, "--local", help="Revisa el repositorio en esta máquina."),
    settings: Path | None = typer.Option(None, "--settings", help="YAML de configuración."),
) -> None:
    """Diagnóstico local. No contacta servidores."""
    if not local:
        _emitir(
            ctx,
            {"ok": False, "error": "Indicá --local. No hay un diagnóstico remoto en v1."},
            "Indicá --local. doctor no abre conexiones.",
        )
        raise typer.Exit(code=EXIT_ERROR)

    def accion() -> None:
        root = _raiz()
        cfg = _settings(root, settings)
        issues = doctor_local(root, cfg)
        capacidades = capacidades_locales()
        datos = {
            "ok": not issues,
            "hallazgos": [item.formato() for item in issues],
            "capacidades": capacidades,
            "settings": cfg.origen,
        }
        texto = "doctor local: " + ("sin hallazgos" if not issues else f"{len(issues)} hallazgos")
        if not _estado(ctx).get("json"):
            lineas = [texto, f"configuración: {cfg.origen}"]
            lineas.extend(item.formato() for item in issues)
            lineas.append(
                "herramientas: "
                + ", ".join(f"{nombre}={'sí' if valor else 'no'}" for nombre, valor in capacidades.items())
            )
            if not capacidades["docker"]:
                lineas.append("Docker no está en PATH. Las pruebas de integración no se pueden correr aquí.")
            texto = "\n".join(lineas)
        _emitir(ctx, datos, texto)
        if issues:
            raise HostiumError("doctor encontró hallazgos", issues=issues)

    _ejecutar(ctx, accion)


@rules_app.command("list")
def rules_list(
    ctx: typer.Context,
    settings: Path | None = typer.Option(None, "--settings"),
) -> None:
    """Lista las reglas del manifiesto."""

    def accion() -> None:
        root = _raiz()
        cfg = _settings(root, settings)
        issues, modelo = _validar(root, cfg)
        if issues:
            raise HostiumError("El manifiesto no es válido", issues=issues)
        filas = [
            {
                "id": regla.id,
                "modulo": regla.modulo,
                "estado": regla.estado,
                "incluir_en_paquete": regla.incluir_en_paquete,
                "archivo": regla.archivo,
            }
            for regla in modelo.reglas
        ]
        texto = "\n".join(
            f"{fila['id']}  {fila['estado']:<12}  paquete={'sí' if fila['incluir_en_paquete'] else 'no'}  {fila['modulo']}"
            for fila in filas
        )
        _emitir(ctx, {"ok": True, "reglas": filas}, texto)

    _ejecutar(ctx, accion)


@rules_app.command("validate")
def rules_validate(
    ctx: typer.Context,
    settings: Path | None = typer.Option(None, "--settings"),
) -> None:
    """Valida el manifiesto, la política y los .conf."""

    def accion() -> None:
        root = _raiz()
        cfg = _settings(root, settings)
        issues, _ = _validar(root, cfg)
        if issues:
            raise HostiumError("La validación falló", issues=issues)
        _emitir(ctx, {"ok": True, "hallazgos": []}, "validación estática correcta")

    _ejecutar(ctx, accion)


@rules_app.command("check-ids")
def rules_check_ids(
    ctx: typer.Context,
    settings: Path | None = typer.Option(None, "--settings"),
    installed_ids: Path | None = typer.Option(None, "--installed-ids", help="Un id por línea, obtenido fuera de esta herramienta."),
) -> None:
    """Comprueba unicidad y rango. No consulta cPanel si no le pasás un archivo."""

    def accion() -> None:
        root = _raiz()
        cfg = _settings(root, settings)
        issues, modelo = _validar(root, cfg)
        colision = "no_comprobado"
        if installed_ids is not None:
            externos = _leer_ids(installed_ids)
            propios = {regla.id for regla in modelo.reglas}
            choque = sorted(propios & externos)
            colision = "sin_choque" if not choque else "choque"
            for valor in choque:
                issues.append(Issue("id_duplicado", f"el id {valor} ya figura en el archivo externo", "installed-ids"))
        datos = {
            "ok": not issues,
            "rango": [cfg.rango_inicio, cfg.rango_fin],
            "colision_con_instalados": colision,
            "hallazgos": [item.formato() for item in issues],
        }
        if issues:
            raise HostiumError("hay problemas de IDs", issues=issues)
        _emitir(ctx, datos, f"IDs dentro de {cfg.rango_inicio}-{cfg.rango_fin}. Colisión con instalados: {colision}.")

    _ejecutar(ctx, accion)


def _leer_ids(path: Path) -> set[int]:
    encontrados: set[int] = set()
    for linea in path.read_text(encoding="utf-8").splitlines():
        pelada = linea.strip()
        if not pelada or pelada.startswith("#"):
            continue
        encontrados.add(int(pelada))
    return encontrados


@package_app.command("build")
def package_build(
    ctx: typer.Context,
    version: str = typer.Option(..., "--version", help="SemVer del ruleset."),
    engine: str = typer.Option(..., "--engine", help="Versión del motor ModSecurity, por ejemplo 2.9.15."),
    channel: str | None = typer.Option(None, "--channel", help="stable o canary."),
    output: Path | None = typer.Option(None, "--output", help="Directorio de artefactos."),
    settings: Path | None = typer.Option(None, "--settings"),
) -> None:
    """Construye un ZIP reproducible y meta_hostium.yaml."""

    def accion() -> None:
        root = _raiz()
        cfg = _settings(root, settings)
        artefacto = build_package(root, cfg, version=version, engine=engine, canal=channel, output=output)
        datos = {
            "ok": True,
            "version": artefacto.version,
            "engine": artefacto.engine,
            "canal": artefacto.canal,
            "distribution": artefacto.distribution,
            "zip": str(artefacto.zip_path),
            "metadata": str(artefacto.metadata_path),
            "md5": artefacto.md5,
            "sha512": artefacto.sha512,
            "sha256": artefacto.sha256,
            "archivos": artefacto.archivos,
            "url": artefacto.url,
            "url_provisionada": False,
        }
        texto = (
            f"ZIP {artefacto.zip_path}\n"
            f"metadata {artefacto.metadata_path}\n"
            f"MD5 {artefacto.md5}\n"
            f"SHA512 {artefacto.sha512}\n"
            f"URL {artefacto.url} (raw público; este comando no llama a WHM)"
        )
        _emitir(ctx, datos, texto)

    _ejecutar(ctx, accion)


@package_app.command("verify")
def package_verify(
    ctx: typer.Context,
    zip_path: Path = typer.Option(..., "--zip"),
    metadata: Path = typer.Option(..., "--metadata"),
) -> None:
    """Recalcula los hashes y revisa la estructura del ZIP."""

    def accion() -> None:
        issues = verify_package(zip_path, metadata)
        if issues:
            raise HostiumError("el paquete no verifica", issues=issues)
        _emitir(ctx, {"ok": True, "zip": str(zip_path), "metadata": str(metadata)}, "paquete verificado")

    _ejecutar(ctx, accion)


@metadata_app.command("show")
def metadata_show(
    ctx: typer.Context,
    file: Path = typer.Option(..., "--file"),
) -> None:
    """Muestra y valida un meta_hostium.yaml."""

    def accion() -> None:
        data, issues = load_metadata(file)
        if issues:
            raise HostiumError("metadata inválida", issues=issues)
        texto = file.read_text(encoding="utf-8")
        if _estado(ctx).get("json"):
            _emitir(ctx, {"ok": True, "metadata": data}, texto)
        else:
            sys.stdout.write(texto if texto.endswith("\n") else texto + "\n")

    _ejecutar(ctx, accion)


@publish_app.command("plan")
def publish_plan(
    ctx: typer.Context,
    version: str = typer.Option(..., "--version"),
    channel: str = typer.Option("stable", "--channel"),
    output: Path | None = typer.Option(None, "--output"),
    settings: Path | None = typer.Option(None, "--settings"),
) -> None:
    """Arma el plan de publicación atómica. No envía datos por la red."""

    def accion() -> None:
        root = _raiz()
        cfg = _settings(root, settings)
        salida = (output if output is not None else root / cfg.directorio_salida).resolve()
        zip_path = salida / f"hostium-{version}.zip"
        metadata = salida / "channels" / channel / "meta_hostium.yaml"
        if not metadata.is_file():
            metadata = salida / "meta_hostium.yaml"
        plan = plan_publicacion(zip_path, metadata, version, channel)
        lineas = [f"publish plan {version} canal {channel}", f"listo: {plan['listo']}", "No se subió ningún archivo."]
        lineas.extend(f"- {paso}" for paso in plan["orden"])
        if plan["problemas"]:
            lineas.extend(plan["problemas"])
        _emitir(ctx, plan, "\n".join(lineas))
        if not plan["listo"]:
            raise HostiumError("el plan no está listo: falta el artefacto o no verifica")

    _ejecutar(ctx, accion)


@publish_app.command("apply")
def publish_apply(ctx: typer.Context) -> None:
    """Bloqueado. No publica por HTTP."""

    def accion() -> None:
        apply_publicacion()

    _ejecutar(ctx, accion)


@fleet_app.command("list")
def fleet_list(
    ctx: typer.Context,
    inventory: Path | None = typer.Option(None, "--inventory"),
) -> None:
    """Lista el inventario. Si es el de ejemplo, lo dice."""

    def accion() -> None:
        root = _raiz()
        path = resolver_inventario(root, inventory)
        inventario = load_inventory(path)
        filas = [
            {
                "name": server.name,
                "ssh_host": server.ssh_host,
                "ring": server.ring,
                "environment": server.environment,
                "tags": server.tags,
            }
            for server in inventario.servers
        ]
        datos = {"ok": True, "es_ejemplo": inventario.es_ejemplo, "origen": inventario.origen, "servers": filas}
        aviso = "INVENTARIO DE EJEMPLO. Estos hosts no son servidores reales." if inventario.es_ejemplo else "Inventario local."
        texto = aviso + "\n" + "\n".join(f"{fila['name']}  {fila['ring']}  {fila['ssh_host']}" for fila in filas)
        _emitir(ctx, datos, texto)

    _ejecutar(ctx, accion)


@fleet_app.command("audit")
def fleet_audit(
    ctx: typer.Context,
    inventory: Path | None = typer.Option(None, "--inventory"),
    backend: str = typer.Option("auto", "--backend", help="auto, fixture o ssh."),
    fixture_dir: Path | None = typer.Option(None, "--fixture-dir"),
) -> None:
    """Reúne evidencia de solo lectura, o muestra el plan si --dry-run."""

    def accion() -> None:
        root = _raiz()
        path = resolver_inventario(root, inventory)
        inventario = load_inventory(path)
        seco = _estado(ctx).get("dry_run", False)
        resultado = auditar(inventario, dry_run=bool(seco), backend=backend, fixture_dir=fixture_dir or root / "tests" / "fixtures" / "fleet")
        datos = _auditoria_dict(resultado)
        lineas = [
            f"auditoría fuente={resultado.fuente} dry_run={resultado.dry_run} ejemplo={resultado.es_ejemplo}",
            resultado.nota,
        ]
        for server in resultado.servidores:
            lineas.append(f"- {server.name} ({server.ssh_host}) estado={server.estado} fuente={server.fuente}")
            if _estado(ctx).get("verbose"):
                lineas.extend(f"  {nota}" for nota in server.inferencias)
        _emitir(ctx, datos, "\n".join(lineas))

    _ejecutar(ctx, accion)


def _auditoria_dict(resultado: Any) -> dict[str, Any]:
    return {
        "ok": True,
        "ejecutado": resultado.ejecutado,
        "dry_run": resultado.dry_run,
        "fuente": resultado.fuente,
        "es_ejemplo": resultado.es_ejemplo,
        "nota": resultado.nota,
        "modifica_servidores": False,
        "servidores": [
            {
                "name": server.name,
                "ssh_host": server.ssh_host,
                "ring": server.ring,
                "estado": server.estado,
                "fuente": server.fuente,
                "inferencias": server.inferencias,
                "comandos": [
                    {
                        "id": comando.id,
                        "comando": comando.comando,
                        "ejecutado": comando.ejecutado,
                        "codigo": comando.codigo,
                    }
                    for comando in server.comandos
                ],
            }
            for server in resultado.servidores
        ],
    }


@deploy_app.command("plan")
def deploy_plan(
    ctx: typer.Context,
    ring: str = typer.Option(..., "--ring"),
    version: str = typer.Option(..., "--version"),
    inventory: Path | None = typer.Option(None, "--inventory"),
    output: Path | None = typer.Option(None, "--output"),
    settings: Path | None = typer.Option(None, "--settings"),
) -> None:
    """Describe el despliegue del anillo. No se conecta."""

    def accion() -> None:
        root = _raiz()
        cfg = _settings(root, settings)
        inventario = load_inventory(resolver_inventario(root, inventory))
        salida = (output if output is not None else root / cfg.directorio_salida).resolve()
        plan = plan_despliegue(inventario, ring, version, salida / f"hostium-{version}.zip")
        lineas = [f"deploy plan anillo {ring} versión {version}", "No se modificó ningún servidor."]
        lineas.extend(f"- {paso}" for paso in plan["pasos_humanos"])
        _emitir(ctx, plan, "\n".join(lineas))

    _ejecutar(ctx, accion)


@deploy_app.command("apply")
def deploy_apply(
    ctx: typer.Context,
    ring: str = typer.Option(..., "--ring"),
    version: str = typer.Option(..., "--version"),
    approve: bool = typer.Option(False, "--approve", help="No desbloquea la operación en v1."),
) -> None:
    """Bloqueado. No despliega."""

    def accion() -> None:
        _ = (ring, version, approve)
        apply_despliegue()

    _ejecutar(ctx, accion)


@deploy_app.command("verify")
def deploy_verify(
    ctx: typer.Context,
    ring: str = typer.Option(..., "--ring"),
    version: str = typer.Option("1.0.0", "--version"),
    output: Path | None = typer.Option(None, "--output"),
    settings: Path | None = typer.Option(None, "--settings"),
) -> None:
    """Revisa si el artefacto local existe. No verifica servidores."""

    def accion() -> None:
        _ = ring
        root = _raiz()
        cfg = _settings(root, settings)
        salida = (output if output is not None else root / cfg.directorio_salida).resolve()
        datos = verificar_despliegue_local(salida / f"hostium-{version}.zip", salida / "meta_hostium.yaml")
        _emitir(ctx, datos, "verificación remota no ejecutada")
        if not datos["zip_presente"] or not datos["metadata_presente"]:
            raise HostiumError("no hay artefacto local para esa versión; la verificación remota tampoco se ejecutó")

    _ejecutar(ctx, accion)


@rollback_app.command("plan")
def rollback_plan_cmd(
    ctx: typer.Context,
    ring: str = typer.Option(..., "--ring"),
    inventory: Path | None = typer.Option(None, "--inventory"),
) -> None:
    """Describe las dos vías de rollback. No las ejecuta."""

    def accion() -> None:
        root = _raiz()
        inventario = load_inventory(resolver_inventario(root, inventory))
        plan = plan_rollback(inventario, ring)
        lineas = [f"rollback plan anillo {ring}", "No se modificó ningún servidor."]
        for via in plan["vias"]:
            lineas.append(via["nombre"] + ": " + via["efecto"])
            lineas.extend(f"- {paso}" for paso in via["pasos"])
        _emitir(ctx, plan, "\n".join(lineas))

    _ejecutar(ctx, accion)


@rollback_app.command("apply")
def rollback_apply(
    ctx: typer.Context,
    ring: str = typer.Option(..., "--ring"),
    approve: bool = typer.Option(False, "--approve"),
) -> None:
    """Bloqueado. No revierte servidores."""

    def accion() -> None:
        _ = (ring, approve)
        apply_rollback()

    _ejecutar(ctx, accion)


@report_app.command("generate")
def report_generate(
    ctx: typer.Context,
    formato: str = typer.Option("markdown", "--format", help="markdown o json."),
    output: Path | None = typer.Option(None, "--output"),
    settings: Path | None = typer.Option(None, "--settings"),
) -> None:
    """Genera un informe local de validación y, si existe, del artefacto."""

    def accion() -> None:
        if formato not in {"markdown", "json"}:
            raise HostiumError("el formato debe ser markdown o json")
        root = _raiz()
        cfg = _settings(root, settings)
        issues, _ = _validar(root, cfg)
        if issues:
            raise HostiumError("no se genera informe de un árbol inválido", issues=issues)
        salida = root / cfg.directorio_salida
        meta = salida / "meta_hostium.yaml"
        artefacto = None
        if meta.is_file():
            data, meta_issues = load_metadata(meta)
            if meta_issues:
                raise HostiumError("la metadata local no es válida", issues=meta_issues)
            artefacto = {"metadata": str(meta), "motores": [clave for clave in data if clave != "attributes"]}
        integracion = cargar_evidencia_integracion(root / "reports")
        contenido = generar_informe(
            formato=formato,
            validacion=[],
            artefacto=artefacto,
            auditoria=None,
            integracion=integracion,
        )
        destino = output or (root / "reports" / ("informe.json" if formato == "json" else "informe.md"))
        escribir_informe(destino, contenido)
        datos = {"ok": True, "formato": formato, "archivo": str(destino)}
        if _estado(ctx).get("json"):
            _emitir(ctx, datos, contenido)
        else:
            sys.stdout.write(contenido)
            sys.stderr.write(f"informe escrito en {destino}\n")

    _ejecutar(ctx, accion)
