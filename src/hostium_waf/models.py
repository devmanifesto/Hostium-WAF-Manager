"""Tipos del dominio. La validación vive en validation.py y reporta la ruta del campo."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CasoPrueba:
    titulo: str
    path: str
    metodo: str
    dispara: bool
    status: int | None
    ejecucion: str
    headers: dict[str, str]
    notas: str


@dataclass
class Cambio:
    version: str
    fecha: str
    nota: str


@dataclass
class Regla:
    id: int
    nombre: str
    descripcion: str
    categoria: str
    modulo: str
    archivo: str
    version_de_introduccion: str
    autor: str
    owner: str
    motivacion: str
    tipo_de_ataque: str
    referencias: list[str]
    falsos_positivos_probables: str
    fase: int
    variables_inspeccionadas: list[str]
    operador: str
    transformaciones: list[str]
    accion: str
    severidad: str
    etiquetas: list[str]
    estado: str
    modo_por_defecto: str
    incluir_en_paquete: bool
    casos_positivos: list[CasoPrueba]
    casos_negativos: list[CasoPrueba]
    impacto_previsto: str
    fecha_de_revision: str
    ultima_validacion: str | None
    excepciones: list[dict[str, object]]
    registro_de_cambio: list[Cambio]


@dataclass
class Manifiesto:
    version_esquema: int
    rango_inicio: int
    rango_fin: int
    reglas: list[Regla]


@dataclass
class Politica:
    version_esquema: int
    modulos_habilitados: list[str]


@dataclass
class Settings:
    version_esquema: int
    vendor_id: str
    nombre_visible: str
    descripcion: str
    vendor_url: str
    base_url: str
    motor_por_defecto: str
    canal_por_defecto: str
    manifiesto: str
    politica: str
    directorio_salida: str
    rango_inicio: int
    rango_fin: int
    origen: str


@dataclass
class Server:
    name: str
    ssh_host: str
    ssh_user: str
    ring: str
    environment: str
    tags: list[str] = field(default_factory=list)
    port: int = 22


@dataclass
class Inventory:
    servers: list[Server]
    origen: str
    es_ejemplo: bool
