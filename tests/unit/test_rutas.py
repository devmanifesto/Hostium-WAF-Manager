"""Aproximación en Python de las rutas. No sustituye a ModSecurity."""

from __future__ import annotations

import html
import posixpath
import re
from urllib.parse import unquote

ENV = re.compile(r"(?:^|/)\.env(?:$|[./?])")
GIT = re.compile(r"(?:^|/)\.git/config(?:$|[./?])")


def normalizar(valor: str) -> str:
    valor = unquote(unquote(valor))
    valor = html.unescape(valor)
    valor = valor.lower().replace("\x00", "")
    if valor.startswith("/"):
        return posixpath.normpath(valor)
    return posixpath.normpath("/" + valor)


def test_env_positivo_y_negativo() -> None:
    positivos = ["/.env", "/.ENV", "/.env.local", "/app/.env", "/foo/../.env", "/%2eenv", "/%252eenv"]
    negativos = ["/environment", "/.environment", "/assets/env.js", "/my.env", "/wp-login.php"]
    for ruta in positivos:
        assert ENV.search(normalizar(ruta)), ruta
    for ruta in negativos:
        assert ENV.search(normalizar(ruta)) is None, ruta


def test_git_positivo_y_negativo() -> None:
    positivos = ["/.git/config", "/.GIT/CONFIG", "/.git/config.bak", "/app/.git/config"]
    negativos = ["/git/config", "/.gitignore", "/blog/post", "/.git/configuration"]
    for ruta in positivos:
        assert GIT.search(normalizar(ruta)), ruta
    for ruta in negativos:
        assert GIT.search(normalizar(ruta)) is None, ruta
