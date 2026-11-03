"""Rutas del vendor candidato 2.1.5. El conf de puntaje no entra al ZIP."""

from __future__ import annotations

VERSION_RULESET = "2.1.5"
MOTORES_CANDIDATA = frozenset({"2.9.15"})
ARCHIVO_EXCLUSIONES = "rules/hostium/REQUEST-900-CRS-EXCLUSIONS.conf"
ARCHIVO_PUNTAJE = "rules/hostium/REQUEST-910-CRS-ANOMALY-SCORE.conf"
DIR_CRS = "third_party/coreruleset-v3.3.10/rules"
ARCHIVOS_PUNTAJE = (
    "REQUEST-911-METHOD-ENFORCEMENT.conf",
    "REQUEST-922-MULTIPART-ATTACK.conf",
    "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    "REQUEST-934-APPLICATION-ATTACK-NODEJS.conf",
    "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
)
