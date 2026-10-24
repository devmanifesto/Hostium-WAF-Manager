"""Errores de dominio y códigos de salida de la CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_BLOCKED = 3


@dataclass(frozen=True)
class Issue:
    codigo: str
    mensaje: str
    ruta: str = ""

    def formato(self) -> str:
        if self.ruta:
            return f"[{self.codigo}] {self.ruta}: {self.mensaje}"
        return f"[{self.codigo}] {self.mensaje}"


class HostiumError(Exception):
    def __init__(
        self,
        message: str,
        *,
        issues: list[Issue] | None = None,
        exit_code: int = EXIT_ERROR,
        datos: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.issues = issues or []
        self.exit_code = exit_code
        self.datos = datos or {}


class BlockedOperation(HostiumError):
    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=EXIT_BLOCKED)


class UsageError(HostiumError):
    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=EXIT_USAGE)
