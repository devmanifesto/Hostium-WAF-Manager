"""Validación estática de manifiestos, política, exclusiones y SecLang propio."""

from __future__ import annotations

import re
from datetime import date, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from hostium_waf.errors import Issue
from hostium_waf.models import Cambio, CasoPrueba, Manifiesto, Politica, Regla, Settings
from hostium_waf.security import es_semver, regex_peligrosa

ESTADOS = {"borrador", "experimental", "probado", "piloto", "produccion", "retirado"}
MODOS = {"log-only", "detection", "deny"}
SEVERIDADES = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"}
EJECUCIONES = {"automatizada", "pendiente", "laboratorio"}
ANILLOS = {"lab", "pilot", "canary", "production"}
_METODOS_HTTP = {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
_CLAVES_EXCLUSION = {"id", "tipo", "regla_objetivo", "motivo", "owner", "fecha_revision", "alcance", "ticket"}
_CLAVES_REGLA = {
    "id",
    "nombre",
    "descripcion",
    "categoria",
    "modulo",
    "archivo",
    "version_de_introduccion",
    "autor",
    "owner",
    "motivacion",
    "tipo_de_ataque",
    "referencias",
    "falsos_positivos_probables",
    "fase",
    "variables_inspeccionadas",
    "operador",
    "transformaciones",
    "accion",
    "severidad",
    "etiquetas",
    "estado",
    "modo_por_defecto",
    "incluir_en_paquete",
    "casos_de_prueba_positivos",
    "casos_de_prueba_negativos",
    "impacto_previsto",
    "fecha_de_revision",
    "ultima_validacion",
    "excepciones",
    "registro_de_cambio",
}
_CLAVES_CASO = {"titulo", "path", "metodo", "dispara", "status", "ejecucion", "headers", "notas"}
_ID_ACTIVO = re.compile(r"\bid:(\d+)\b")
_PROHIBIDO_PAQUETE = (
    (re.compile(r"\bSecRuleEngine\s+Off\b", re.I), "apaga el motor"),
    (re.compile(r"\bctl:ruleEngine\s*=\s*Off\b", re.I), "apaga el motor en la transacción"),
    (re.compile(r"\bSecRuleRemoveById\b"), "exclusión configure-time: no va en el ZIP del vendor"),
    (re.compile(r"\bctl:ruleRemove(?:Target)?ById\b"), "exclusión runtime: no va en el ZIP del vendor"),
    (re.compile(r"(?:^|[,\s])allow(?:\s|,|$)", re.I), "una acción allow puede evadir CRS"),
)


def validar_manifiesto(data: Any, *, rango_inicio: int, rango_fin: int) -> list[Issue]:
    issues: list[Issue] = []
    if not isinstance(data, dict):
        return [Issue("tipo_invalido", "el manifiesto debe ser un mapa", "manifiesto")]
    for clave in ("version_esquema", "rango_ids", "reglas"):
        if clave not in data:
            issues.append(Issue("campo_faltante", "falta la clave", f"manifiesto.{clave}"))
    if issues:
        return issues
    if data["version_esquema"] != 1:
        issues.append(Issue("version_esquema", "solo se admite la versión 1", "manifiesto.version_esquema"))
    rango = data["rango_ids"]
    if not isinstance(rango, dict) or rango.get("inicio") != rango_inicio or rango.get("fin") != rango_fin:
        issues.append(
            Issue(
                "rango_ids",
                f"el rango del manifiesto debe ser {rango_inicio}-{rango_fin}",
                "manifiesto.rango_ids",
            )
        )
    reglas = data["reglas"]
    if not isinstance(reglas, list) or not reglas:
        issues.append(Issue("campo_faltante", "no hay reglas", "manifiesto.reglas"))
        return issues
    vistos: dict[int, str] = {}
    for indice, cruda in enumerate(reglas):
        ruta = f"manifiesto.reglas[{indice}]"
        if not isinstance(cruda, dict):
            issues.append(Issue("tipo_invalido", "la regla debe ser un mapa", ruta))
            continue
        issues.extend(_validar_regla(cruda, ruta, rango_inicio, rango_fin, vistos))
    return issues


def _validar_regla(
    cruda: dict[str, Any],
    ruta: str,
    rango_inicio: int,
    rango_fin: int,
    vistos: dict[int, str],
) -> list[Issue]:
    issues: list[Issue] = []
    for clave in sorted(set(cruda) - _CLAVES_REGLA):
        issues.append(Issue("campo_desconocido", "campo no admitido", f"{ruta}.{clave}"))
    for clave in sorted(_CLAVES_REGLA - set(cruda)):
        issues.append(Issue("campo_faltante", "falta el campo", f"{ruta}.{clave}"))
    if issues:
        return issues
    identificador = cruda["id"]
    if isinstance(identificador, bool) or not isinstance(identificador, int):
        issues.append(Issue("tipo_invalido", "id debe ser un entero", f"{ruta}.id"))
    else:
        if identificador < rango_inicio or identificador > rango_fin:
            issues.append(Issue("id_fuera_de_rango", f"id {identificador} fuera de {rango_inicio}-{rango_fin}", f"{ruta}.id"))
        if identificador in vistos:
            issues.append(Issue("id_duplicado", f"el id {identificador} ya está en {vistos[identificador]}", f"{ruta}.id"))
        else:
            vistos[identificador] = ruta
    for clave in (
        "nombre",
        "descripcion",
        "categoria",
        "modulo",
        "archivo",
        "autor",
        "owner",
        "motivacion",
        "tipo_de_ataque",
        "falsos_positivos_probables",
        "operador",
        "accion",
        "impacto_previsto",
    ):
        if not isinstance(cruda[clave], str) or not cruda[clave].strip():
            issues.append(Issue("tipo_invalido", "debe ser texto no vacío", f"{ruta}.{clave}"))
    if not es_semver(str(cruda["version_de_introduccion"])):
        issues.append(Issue("semver", "version_de_introduccion no es SemVer", f"{ruta}.version_de_introduccion"))
    archivo = cruda["archivo"]
    if isinstance(archivo, str):
        posix_parts = PurePosixPath(archivo.replace("\\", "/")).parts
        if ".." in Path(archivo).parts or archivo.startswith(("/", "\\")):
            issues.append(Issue("ruta", "el archivo sale del árbol de reglas", f"{ruta}.archivo"))
        elif not posix_parts or posix_parts[0] != "rules":
            issues.append(Issue("ruta", "el archivo debe estar bajo rules/", f"{ruta}.archivo"))
    if cruda["estado"] not in ESTADOS:
        issues.append(Issue("estado_invalido", "estado no reconocido", f"{ruta}.estado"))
    if cruda["modo_por_defecto"] not in MODOS:
        issues.append(Issue("modo_invalido", "modo_por_defecto no reconocido", f"{ruta}.modo_por_defecto"))
    if cruda["severidad"] not in SEVERIDADES:
        issues.append(Issue("severidad", "severidad ModSecurity no reconocida", f"{ruta}.severidad"))
    if isinstance(cruda["fase"], bool) or not isinstance(cruda["fase"], int) or not 1 <= cruda["fase"] <= 5:
        issues.append(Issue("fase", "la fase debe ser un entero entre 1 y 5", f"{ruta}.fase"))
    if not isinstance(cruda["incluir_en_paquete"], bool):
        issues.append(Issue("tipo_invalido", "incluir_en_paquete debe ser booleano", f"{ruta}.incluir_en_paquete"))
    if cruda.get("incluir_en_paquete") is True and cruda.get("estado") != "produccion":
        issues.append(Issue("estado_invalido", "solo una regla en producción entra al paquete", f"{ruta}.estado"))
    if cruda.get("estado") == "produccion" and cruda.get("incluir_en_paquete") is not True:
        issues.append(Issue("estado_invalido", "una regla en producción debe incluir_en_paquete", f"{ruta}.incluir_en_paquete"))
    if isinstance(archivo, str) and archivo.endswith((".example", ".conf.example")) and cruda.get("incluir_en_paquete") is True:
        issues.append(Issue("ejemplo_en_paquete", "un .example no puede marcarse para el paquete", f"{ruta}.archivo"))
    _lista_textos(cruda, "referencias", ruta, issues)
    _lista_textos(cruda, "variables_inspeccionadas", ruta, issues)
    _lista_textos(cruda, "transformaciones", ruta, issues)
    _lista_textos(cruda, "etiquetas", ruta, issues)
    if isinstance(cruda.get("operador"), str) and not cruda["operador"].startswith("@"):
        issues.append(Issue("operador", "el operador debe empezar con @", f"{ruta}.operador"))
    if isinstance(cruda.get("transformaciones"), list) and cruda["transformaciones"]:
        if cruda["transformaciones"][0] != "t:none":
            issues.append(Issue("transformaciones", "la primera transformación debe ser t:none", f"{ruta}.transformaciones"))
    modo = cruda.get("modo_por_defecto")
    accion = cruda.get("accion")
    if modo == "deny" and accion != "deny":
        issues.append(Issue("accion", "modo deny exige accion deny", f"{ruta}.accion"))
    if modo in {"log-only", "detection"} and accion == "deny":
        issues.append(Issue("accion", "ese modo no puede declarar accion deny", f"{ruta}.accion"))
    fecha = _fecha(cruda.get("fecha_de_revision"))
    if fecha is None:
        issues.append(Issue("fecha", "fecha_de_revision debe ser AAAA-MM-DD", f"{ruta}.fecha_de_revision"))
    if cruda.get("ultima_validacion") is not None and _fecha(cruda.get("ultima_validacion")) is None:
        issues.append(Issue("fecha", "ultima_validacion debe ser AAAA-MM-DD o null", f"{ruta}.ultima_validacion"))
    issues.extend(_validar_casos(cruda.get("casos_de_prueba_positivos"), f"{ruta}.casos_de_prueba_positivos", True))
    issues.extend(_validar_casos(cruda.get("casos_de_prueba_negativos"), f"{ruta}.casos_de_prueba_negativos", False))
    if cruda.get("incluir_en_paquete") is True:
        for grupo in ("casos_de_prueba_positivos", "casos_de_prueba_negativos"):
            for caso in cruda.get(grupo) or []:
                if isinstance(caso, dict) and caso.get("ejecucion") != "automatizada":
                    issues.append(
                        Issue(
                            "sin_pruebas",
                            "una regla empaquetada necesita casos automatizados",
                            f"{ruta}.{grupo}",
                        )
                    )
    if not isinstance(cruda.get("excepciones"), list):
        issues.append(Issue("tipo_invalido", "excepciones debe ser una lista", f"{ruta}.excepciones"))
    else:
        for i, excepcion in enumerate(cruda["excepciones"]):
            issues.extend(_validar_excepcion_breve(excepcion, f"{ruta}.excepciones[{i}]"))
    if not isinstance(cruda.get("registro_de_cambio"), list) or not cruda["registro_de_cambio"]:
        issues.append(Issue("campo_faltante", "falta el registro de cambio", f"{ruta}.registro_de_cambio"))
    else:
        for i, cambio in enumerate(cruda["registro_de_cambio"]):
            ruta_cambio = f"{ruta}.registro_de_cambio[{i}]"
            if not isinstance(cambio, dict):
                issues.append(Issue("tipo_invalido", "el cambio debe ser un mapa", ruta_cambio))
                continue
            if not es_semver(str(cambio.get("version", ""))):
                issues.append(Issue("semver", "version inválida", f"{ruta_cambio}.version"))
            if _fecha(cambio.get("fecha")) is None:
                issues.append(Issue("fecha", "fecha inválida", f"{ruta_cambio}.fecha"))
            if not isinstance(cambio.get("nota"), str) or not cambio["nota"].strip():
                issues.append(Issue("campo_faltante", "falta la nota", f"{ruta_cambio}.nota"))
    return issues


def _lista_textos(cruda: dict[str, Any], clave: str, ruta: str, issues: list[Issue]) -> None:
    valor = cruda.get(clave)
    if not isinstance(valor, list) or not valor or not all(isinstance(item, str) and item.strip() for item in valor):
        issues.append(Issue("tipo_invalido", "debe ser una lista de textos no vacíos", f"{ruta}.{clave}"))


def _validar_casos(valor: Any, ruta: str, positivos: bool) -> list[Issue]:
    issues: list[Issue] = []
    if not isinstance(valor, list) or not valor:
        return [Issue("sin_pruebas", "la regla necesita al menos un caso", ruta)]
    for i, caso in enumerate(valor):
        actual = f"{ruta}[{i}]"
        if not isinstance(caso, dict):
            issues.append(Issue("tipo_invalido", "el caso debe ser un mapa", actual))
            continue
        for clave in sorted(set(caso) - _CLAVES_CASO):
            issues.append(Issue("campo_desconocido", "campo no admitido", f"{actual}.{clave}"))
        for clave in ("titulo", "path", "metodo", "dispara", "ejecucion"):
            if clave not in caso:
                issues.append(Issue("campo_faltante", "falta el campo", f"{actual}.{clave}"))
        if "titulo" in caso and (not isinstance(caso.get("titulo"), str) or not caso["titulo"].strip()):
            issues.append(Issue("caso", "titulo debe ser texto no vacío", f"{actual}.titulo"))
        if "metodo" in caso and (not isinstance(caso.get("metodo"), str) or caso["metodo"] not in _METODOS_HTTP):
            issues.append(Issue("caso", "metodo HTTP no válido", f"{actual}.metodo"))
        if caso.get("ejecucion") not in EJECUCIONES:
            issues.append(Issue("ejecucion", "ejecucion debe ser automatizada, pendiente o laboratorio", f"{actual}.ejecucion"))
        if not isinstance(caso.get("path"), str) or not caso["path"].startswith("/"):
            issues.append(Issue("caso", "path debe empezar con /", f"{actual}.path"))
        if caso.get("dispara") is not True and caso.get("dispara") is not False:
            issues.append(Issue("caso", "dispara debe ser booleano", f"{actual}.dispara"))
        if positivos and caso.get("dispara") is not True:
            issues.append(Issue("caso", "un caso positivo debe disparar la regla", f"{actual}.dispara"))
        if not positivos and caso.get("dispara") is not False:
            issues.append(Issue("caso", "un caso negativo no debe disparar la regla", f"{actual}.dispara"))
        if caso.get("dispara") is True and caso.get("status") != 403:
            issues.append(Issue("caso", "un caso que dispara debe esperar status 403", f"{actual}.status"))
        headers = caso.get("headers", {})
        if headers is None:
            headers = {}
        if "headers" in caso and not isinstance(caso["headers"], dict):
            issues.append(Issue("caso", "headers debe ser un mapa", f"{actual}.headers"))
    return issues


def _validar_excepcion_breve(excepcion: Any, ruta: str) -> list[Issue]:
    if not isinstance(excepcion, dict):
        return [Issue("tipo_invalido", "la excepción debe ser un mapa", ruta)]
    issues: list[Issue] = []
    for clave in ("id", "motivo", "owner", "fecha_revision", "tipo"):
        if clave not in excepcion:
            issues.append(Issue("campo_faltante", "falta el campo", f"{ruta}.{clave}"))
    if excepcion.get("tipo") not in {None, "runtime", "configure-time"}:
        issues.append(Issue("exclusion", "tipo debe ser runtime o configure-time", f"{ruta}.tipo"))
    if "fecha_revision" in excepcion and _fecha(excepcion.get("fecha_revision")) is None:
        issues.append(Issue("fecha", "fecha_revision inválida", f"{ruta}.fecha_revision"))
    return issues


def validar_exclusiones(data: Any) -> list[Issue]:
    issues: list[Issue] = []
    if not isinstance(data, dict):
        return [Issue("tipo_invalido", "el archivo de exclusiones debe ser un mapa", "exclusiones")]
    if data.get("version_esquema") != 1:
        issues.append(Issue("version_esquema", "solo se admite la versión 1", "exclusiones.version_esquema"))
    lista = data.get("exclusiones")
    if lista is None:
        return issues + [Issue("campo_faltante", "falta exclusiones", "exclusiones.exclusiones")]
    if not isinstance(lista, list):
        return issues + [Issue("tipo_invalido", "exclusiones debe ser una lista", "exclusiones.exclusiones")]
    ids_vistos: set[str] = set()
    for i, item in enumerate(lista):
        issues.extend(_validar_item_exclusion(item, f"exclusiones.exclusiones[{i}]", ids_vistos))
    return issues


def _validar_item_exclusion(item: Any, ruta: str, ids_vistos: set[str] | None = None) -> list[Issue]:
    if not isinstance(item, dict):
        return [Issue("tipo_invalido", "la exclusión debe ser un mapa", ruta)]
    issues: list[Issue] = []
    for extra in sorted(set(item) - _CLAVES_EXCLUSION):
        issues.append(Issue("campo_desconocido", "campo no admitido", f"{ruta}.{extra}"))
    requeridos = ("id", "tipo", "regla_objetivo", "motivo", "owner", "fecha_revision", "alcance")
    for clave in requeridos:
        valor = item.get(clave)
        if not isinstance(valor, str) or not valor.strip():
            issues.append(Issue("campo_faltante", "falta el campo", f"{ruta}.{clave}"))
    exc_id = item.get("id")
    if ids_vistos is not None and isinstance(exc_id, str) and exc_id.strip():
        if exc_id in ids_vistos:
            issues.append(Issue("id_duplicado", f"el id de exclusión {exc_id} está repetido", f"{ruta}.id"))
        ids_vistos.add(exc_id)
    if item.get("tipo") not in {"runtime", "configure-time"}:
        issues.append(Issue("exclusion", "tipo debe ser runtime o configure-time", f"{ruta}.tipo"))
    if _fecha(item.get("fecha_revision")) is None:
        issues.append(Issue("fecha", "cada exclusión necesita fecha de revisión", f"{ruta}.fecha_revision"))
    return issues


def validar_politica(data: Any, modulos_conocidos: set[str]) -> list[Issue]:
    issues: list[Issue] = []
    if not isinstance(data, dict):
        return [Issue("tipo_invalido", "la política debe ser un mapa", "politica")]
    if data.get("version_esquema") != 1:
        issues.append(Issue("version_esquema", "solo se admite la versión 1", "politica.version_esquema"))
    modulos = data.get("modulos_habilitados")
    if not isinstance(modulos, list) or not all(isinstance(item, str) for item in modulos):
        return issues + [Issue("tipo_invalido", "modulos_habilitados debe ser una lista de textos", "politica.modulos_habilitados")]
    if len(modulos) != len(set(modulos)):
        issues.append(Issue("politica", "hay módulos repetidos", "politica.modulos_habilitados"))
    for modulo in modulos:
        if modulo not in modulos_conocidos:
            issues.append(Issue("politica", f"el módulo {modulo} no existe en el manifiesto", "politica.modulos_habilitados"))
    return issues


def ids_activos(texto: str) -> list[int]:
    encontrados: list[int] = []
    for linea in texto.splitlines():
        pelada = linea.strip()
        if not pelada or pelada.startswith("#"):
            continue
        encontrados.extend(int(valor) for valor in _ID_ACTIVO.findall(pelada))
    return encontrados


def validar_conf_de_reglas(root: Path, reglas: list[Regla]) -> list[Issue]:
    issues: list[Issue] = []
    por_archivo: dict[str, list[Regla]] = {}
    for regla in reglas:
        por_archivo.setdefault(regla.archivo, []).append(regla)
    for relativo, grupo in por_archivo.items():
        path = root / relativo
        if not path.is_file():
            issues.append(Issue("archivo", "no existe el archivo de la regla", relativo))
            continue
        texto = path.read_text(encoding="utf-8")
        activos = ids_activos(texto)
        if len(activos) != len(set(activos)):
            issues.append(Issue("id_duplicado", "hay IDs repetidos en el archivo", relativo))
        declarados = {regla.id for regla in grupo}
        desconocidos = [str(valor) for valor in activos if valor not in declarados]
        if desconocidos:
            issues.append(Issue("id_desconocido", "hay IDs activos que no están en el manifiesto: " + ", ".join(desconocidos), relativo))
        empaquetables = [regla for regla in grupo if regla.incluir_en_paquete]
        if empaquetables:
            faltan = declarados - set(activos)
            esperados = {regla.id for regla in empaquetables}
            if not esperados.issubset(set(activos)):
                issues.append(Issue("id_ausente", f"faltan IDs activos: {sorted(faltan)}", relativo))
            issues.extend(_revisar_conf_empaquetable(texto, relativo, empaquetables))
        if "INCOMPLETO" in texto and any(regla.incluir_en_paquete for regla in grupo):
            issues.append(Issue("ejemplo_en_paquete", "un archivo marcado INCOMPLETO no puede empaquetarse", relativo))
    carpeta_hostium = root / "rules" / "hostium"
    if carpeta_hostium.is_dir():
        declaradas_norm = {PurePosixPath(rel.replace("\\", "/")).as_posix() for rel in por_archivo}
        for archivo_real in sorted(carpeta_hostium.iterdir()):
            if not archivo_real.is_file():
                continue
            rel_posix = f"rules/hostium/{archivo_real.name}"
            if rel_posix not in declaradas_norm:
                issues.append(Issue("archivo_huerfano", "el archivo en rules/hostium no figura en el manifiesto", rel_posix))
    return issues


def _revisar_conf_empaquetable(texto: str, relativo: str, reglas: list[Regla]) -> list[Issue]:
    issues: list[Issue] = []
    activas = "\n".join(linea for linea in texto.splitlines() if linea.strip() and not linea.strip().startswith("#"))
    for patron, motivo in _PROHIBIDO_PAQUETE:
        if patron.search(activas):
            issues.append(Issue("regla_prohibida", motivo, relativo))
    if regex_peligrosa(activas):
        issues.append(Issue("regex_peligrosa", "hay un cuantificador anidado con riesgo de ReDoS", relativo))
    for regla in reglas:
        if f"id:{regla.id}" not in activas:
            issues.append(Issue("id_ausente", f"no aparece id:{regla.id}", relativo))
        if regla.modo_por_defecto == "deny" and not re.search(r"(?:^|[,\s])deny(?:\s|,|$)", activas):
            issues.append(Issue("accion", "la regla deny no contiene la acción deny", relativo))
        if f"ver:'hostium/{regla.version_de_introduccion}'" not in activas:
            issues.append(
                Issue(
                    "version",
                    "falta ver:'hostium/<version_de_introduccion>'",
                    relativo,
                )
            )
    return issues


def cargar_manifiesto(data: dict[str, Any]) -> Manifiesto:
    reglas = [_cargar_regla(item) for item in data["reglas"]]
    return Manifiesto(
        version_esquema=data["version_esquema"],
        rango_inicio=data["rango_ids"]["inicio"],
        rango_fin=data["rango_ids"]["fin"],
        reglas=reglas,
    )


def _cargar_regla(cruda: dict[str, Any]) -> Regla:
    return Regla(
        id=cruda["id"],
        nombre=cruda["nombre"],
        descripcion=cruda["descripcion"],
        categoria=cruda["categoria"],
        modulo=cruda["modulo"],
        archivo=cruda["archivo"],
        version_de_introduccion=str(cruda["version_de_introduccion"]),
        autor=cruda["autor"],
        owner=cruda["owner"],
        motivacion=cruda["motivacion"],
        tipo_de_ataque=cruda["tipo_de_ataque"],
        referencias=list(cruda["referencias"]),
        falsos_positivos_probables=cruda["falsos_positivos_probables"],
        fase=cruda["fase"],
        variables_inspeccionadas=list(cruda["variables_inspeccionadas"]),
        operador=cruda["operador"],
        transformaciones=list(cruda["transformaciones"]),
        accion=cruda["accion"],
        severidad=cruda["severidad"],
        etiquetas=list(cruda["etiquetas"]),
        estado=cruda["estado"],
        modo_por_defecto=cruda["modo_por_defecto"],
        incluir_en_paquete=cruda["incluir_en_paquete"],
        casos_positivos=[_cargar_caso(item) for item in cruda["casos_de_prueba_positivos"]],
        casos_negativos=[_cargar_caso(item) for item in cruda["casos_de_prueba_negativos"]],
        impacto_previsto=cruda["impacto_previsto"],
        fecha_de_revision=_fecha(cruda["fecha_de_revision"]) or "",
        ultima_validacion=_fecha(cruda["ultima_validacion"]),
        excepciones=list(cruda["excepciones"]),
        registro_de_cambio=[
            Cambio(version=str(item["version"]), fecha=_fecha(item["fecha"]) or "", nota=item["nota"])
            for item in cruda["registro_de_cambio"]
        ],
    )


def _cargar_caso(cruda: dict[str, Any]) -> CasoPrueba:
    headers = cruda.get("headers") or {}
    return CasoPrueba(
        titulo=cruda["titulo"],
        path=cruda["path"],
        metodo=cruda["metodo"],
        dispara=cruda["dispara"],
        status=cruda.get("status"),
        ejecucion=cruda["ejecucion"],
        headers={str(k): str(v) for k, v in headers.items()},
        notas=str(cruda.get("notas") or ""),
    )


def cargar_politica(data: dict[str, Any]) -> Politica:
    return Politica(version_esquema=data["version_esquema"], modulos_habilitados=list(data["modulos_habilitados"]))


def validar_repositorio(root: Path, settings: Settings, manifiesto_data: dict[str, Any], politica_data: dict[str, Any]) -> tuple[Manifiesto, Politica, list[Issue]]:
    issues = validar_manifiesto(manifiesto_data, rango_inicio=settings.rango_inicio, rango_fin=settings.rango_fin)
    if any(item.codigo in {"campo_faltante", "tipo_invalido", "campo_desconocido"} and item.ruta.startswith("manifiesto.reglas") for item in issues):
        return Manifiesto(1, settings.rango_inicio, settings.rango_fin, []), Politica(1, []), issues
    try:
        manifiesto = cargar_manifiesto(manifiesto_data)
    except (KeyError, TypeError, ValueError) as exc:
        issues.append(Issue("manifiesto", f"no se pudo interpretar el manifiesto: {exc}", "manifiesto"))
        return Manifiesto(1, settings.rango_inicio, settings.rango_fin, []), Politica(1, []), issues
    modulos = {regla.modulo for regla in manifiesto.reglas}
    issues.extend(validar_politica(politica_data, modulos))
    politica = Politica(1, [])
    if not any(item.ruta.startswith("politica") for item in issues):
        politica = cargar_politica(politica_data)
    issues.extend(validar_conf_de_reglas(root, manifiesto.reglas))
    issues.extend(_cruce_politica(manifiesto, politica))
    return manifiesto, politica, issues


def _cruce_politica(manifiesto: Manifiesto, politica: Politica) -> list[Issue]:
    issues: list[Issue] = []
    habilitados = set(politica.modulos_habilitados)
    for regla in manifiesto.reglas:
        if regla.modulo not in habilitados:
            continue
        if not regla.incluir_en_paquete:
            issues.append(
                Issue(
                    "politica",
                    f"el módulo {regla.modulo} está habilitado pero la regla {regla.id} no es incluible",
                    f"regla.{regla.id}",
                )
            )
        if regla.archivo.endswith((".example", ".conf.example")):
            issues.append(Issue("ejemplo_en_paquete", "la política intenta habilitar un example", regla.archivo))
    return issues


def seleccionar_reglas(manifiesto: Manifiesto, politica: Politica) -> list[Regla]:
    habilitados = set(politica.modulos_habilitados)
    return [
        regla
        for regla in manifiesto.reglas
        if regla.incluir_en_paquete and regla.estado == "produccion" and regla.modulo in habilitados
    ]


def _fecha(valor: Any) -> str | None:
    if valor is None:
        return None
    if isinstance(valor, datetime):
        valor = valor.date()
    if isinstance(valor, date):
        return valor.isoformat()
    if isinstance(valor, str):
        try:
            date.fromisoformat(valor)
        except ValueError:
            return None
        return valor
    return None
