# Cómo contribuir

1. Partí de `docs/ESPECIFICACION_MAESTRA.md` y de `AGENTS.md`.
2. Una regla nueva necesita id libre en 5500000–5509999, manifiesto completo, prueba positiva, prueba negativa, la primera línea `# Reglas complementarias de seguridad administradas por Hostium <semver>` y una nota de rollback.
3. No la marques `produccion` ni `incluir_en_paquete: true` hasta que la política la habilite y la suite la ejecute.
4. No copies reglas de Imunify360, Imunify365 ni Comodo.
5. No edites los archivos del RPM de OWASP CRS.
6. `python -m pytest` y `python -m ruff check src tests` tienen que pasar.
7. Si la regla hace `deny`, hace falta revisión humana. El ZIP de una versión ya publicada no se regenera con otros bytes: subí el SemVer.
8. No despliegues ni reinicies Apache desde un pull request.

Los `.conf.example` pueden describir trabajo futuro. El empaquetador los excluye.
