from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _en_la_raiz(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
