# Observabilidad y logs

## Alcance

`logs analyze` implementa diagnóstico local de mensajes de ModSecurity v2. No abre SSH, no cambia Apache y no determina automáticamente si una petición era legítima.

Admite líneas `ModSecurity:` del error log de Apache y líneas `Message:` de la sección H del audit log nativo v2. No interpreta audit JSON ni correlaciona secciones A/B/F aisladas. Si no reconoce ningún ID, termina en error explícito. Informa mensajes descartados y deja sin correlación los mensajes que no tienen `unique_id`; nunca los une solo por URI o cercanía.

## Uso

SOLO LECTURA del original; `--output` escribe un informe local:

```powershell
python -m hostium_waf logs analyze --input C:/evidencias/error.log --server nodo-piloto --output C:/evidencias/antes.json
python -m hostium_waf logs analyze --input C:/evidencias/error-despues.log --server nodo-piloto --baseline C:/evidencias/antes.json --output C:/evidencias/despues.json
python -m hostium_waf logs analyze --input C:/evidencias/error.log --server nodo-piloto --include-locations --format markdown
```

Los informes comparados deben usar el mismo alias de servidor y modo de ubicaciones. Se suman conteos por dominio, ruta, ID y variable, incluso si cambió `ver`. Una diferencia de conteos no es una tasa de falsos positivos: hacen falta ventanas y volúmenes comparables, más confirmación de operaciones legítimas.

## Datos y privacidad

Agrupa transacciones por `unique_id` internamente. Emite conteos por dominio/ruta, ID, variable, versión y fuente inferida por rango. Separa IDs de evaluación como 949110 de detectores. Solo cuenta bloqueo observado si aparece `Access denied with code`; conserva sus códigos. Las fechas Apache reconocidas se informan como hora local sin suponer zona horaria. Sin fechas reconocibles devuelve null.

No emite request IDs, IP, mensajes, valores de parámetros, cabeceras, cuerpos ni query strings. Por defecto los dominios y rutas se sustituyen por SHA256 truncado estable: sirve para agrupar, pero un diccionario puede recuperar nombres previsibles. `--include-locations` permite investigar con dominio y ruta visibles; el path puede contener datos personales. Los nombres de parámetros también pueden ser sensibles.

Mantener logs e informes fuera de Git y CI pública, en almacenamiento con permisos restringidos y retención definida por el operador. El comando nunca sobrescribe su archivo de entrada ni la base de comparación. No cambia `SecAuditLogParts`: el original puede contener datos sensibles aunque el informe no los copie.

## Operación y límites

Correlacionar error log con access log y proxy para determinar el estado final recibido por el cliente. Dos fuentes concatenadas con el mismo `unique_id` se deduplican por ID/variable/versión/ubicación/denegación; si no hay request ID, no es posible garantizar deduplicación. Si un request ID tiene ubicaciones contradictorias, el informe las marca ambiguas.

No hay recolector remoto, Prometheus ni autoexcepciones. `fleet audit` sigue siendo inventario de configuración. Las pruebas del parser usan datos sintéticos. Para tomar decisiones productivas faltan eventos reales y confirmación del dueño de la aplicación.

## Verificación y rollback

`python -m pytest tests/unit/test_eventos.py` verifica correlación, privacidad, deduplicación, fuentes no soportadas y comparación. Borrar un informe local no cambia el servidor. No borrar el original hasta cumplir su política de retención.

## Referencias

[ModSecurity v2: audit log y mensajes](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)), [CRS: identificación de falsos positivos](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/). Consulta: 2 de noviembre de 2026.
