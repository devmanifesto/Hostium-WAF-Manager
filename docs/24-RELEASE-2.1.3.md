# Release estable 2.1.3 — corrección de plantillas WHMCS

## Autorización y alcance

2 de noviembre de 2026 (fecha del operador). El usuario autorizó publicación estable, confirmó `https://clientes.hostium.com/admin1911/configgeneral.php?action=save` y decidió actualizar calcium por su cuenta. Esta sesión no abre SSH, no cambia servicios ni afirma haber guardado opciones reales de WHMCS.

La 2.1.2 es una candidata local ya construida con otros bytes; no se publica ni reescribe. La nueva distribution es hostium-2.1.3. Conserva vendor_id hostium, raíz hostium/, los mismos dos conf, IDs, fases y acciones. No agrega REQUEST-910, puntaje global ni hostium-tune.

## Causa y corrección

El operador reportó que la 2.1.1 redujo el score de 55 a 5 y que 921130 aportó esos 5 sobre emailglobalheader, disparando 949110. La fuente oficial CRS 3.3.10 confirma que 921130 es fase 2, attack-protocol, severidad CRITICAL y patrón que incluye `<html` y `<meta`; no es el DOCTYPE aislado. Esto es coherente con el caso, pero no se relee el log productivo desde esta sesión.

5500902 mantiene los controles XSS/RCE de los dos campos de plantilla y suma `ctl:ruleRemoveTargetById=921130` para ambos. Solo corre en POST, Host clientes.hostium.com y REQUEST_FILENAME exacto /admin1911/configgeneral.php. El ctl va al final de la cadena. No se excluye toda attack-protocol ni otros argumentos. 921120 continúa bloqueando un payload de protocolo en el mismo campo.

Los otros cuatro casos mantienen compatibilidad temporal con 2.1.1, fijada al SHA256 del ZIP base, para no restaurar falsos positivos al instalar. No se permite ampliar sus controles o inventar IDs heredados. PrestaShop selecciona REQUEST_FILENAME en lugar de REQUEST_URI para no activarse desde la query. El alcance amplio de esos cuatro casos sigue pendiente de delimitar y está documentado en el catálogo.

## Evidencia local realmente ejecutada

- `python -m pytest`: **107 passed, 18 deselected**, un warning esperado al fabricar ZIP duplicado.
- `python -m ruff check src tests`: **All checks passed!**
- Integración estricta (`HOSTIUM_REQUIRE_INTEGRATION=1`): **18 passed, 103 deselected in 70.49s**. Los cuatro tests unitarios de compatibilidad se agregaron después y están incluidos en las 107 pasadas; no cambian el HTTP.
- `doctor --local`, validación de reglas y ZIP: correctos.
- Dos builds independientes de 2.1.3 idénticos. Los archivos históricos se compararon byte a byte con Git antes de agregar la nueva release: intactos.

La integración usa CRS 3.3.10 con digest fijado. El selector productivo completo se cargó en un contenedor separado. Para header y footer con plantilla HTML, devolvió 503 porque el backend de laboratorio está deliberadamente ausente, sin 921130 ni 949110. No se presenta como un guardado 200 de WHMCS real. También hubo 403 con 921120 en ese mismo campo y con 921130 al cambiar argumento o dominio.

## Artefacto

- Bytes: **4628**
- MD5: `5006f1a7c49accbd1bcf37ea27ef6fc2`
- SHA512: `e90a464b4b9cee808617df7db38d981f8872c43ddbbda481393237bba5712212980c20e5404417995c0990f99a01b8f66b93cc9b96603139b9f51177e88ef852`
- SHA256: `4e88faf6a3cf4c2eb13b8c0f3454920165d8044d1b8ab891034ed7d8d557901e`
- ZIP: https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/hostium-2.1.3.zip
- Metadata: https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml

Se publica primero ZIP y sidecar; después de descargar y comparar los hashes se promueve la metadata. El resultado de esa verificación se registra al final de este documento. No se reutiliza un nombre con otros bytes.

## Actualización en calcium a cargo del operador

Guardar la salida previa de vendor list, httpd -t e includes, más el estado del vendor Hostium, fuera de Git. Luego:

```sh
# PRODUCCIÓN / MODIFICA: autorizado para que el operador lo ejecute.
/usr/local/cpanel/scripts/modsec_vendor update hostium
# SOLO LECTURA:
/usr/local/cpanel/scripts/modsec_vendor list
httpd -t
httpd -t -D DUMP_INCLUDES
```

Confirmar description 2.1.3, dos sets en uso y el nuevo conf. Repetir el guardado legítimo en WHMCS; correlacionar request ID y comprobar que no aparecen 921130 ni 949110 en ese POST. Si todavía falla, conservar los IDs nuevos para diagnosticar; no apagar todo CRS ni enviar un POST sintético que modifique opciones reales. Si la sintaxis falla, no recargar y restaurar el estado anterior. Ninguna comprobación local rellena ultima_validacion.

## Rollback

Conservar copia de metadata 2.1.1 y su ZIP antes de actualizar. Para volver, publicar metadata anterior y actualizar vendor; evita que una actualización automática reintroduzca inmediatamente 2.1.3. El procedimiento manual está en documento 14 y no se ensayó remotamente aquí. Volver a 2.1.1 restaura el falso positivo 921130 y el alcance global anterior de WHMCS. No editar ZIP ni reglas RPM de OWASP.

## Referencias oficiales

Consulta del 2 de noviembre de 2026: https://raw.githubusercontent.com/coreruleset/coreruleset/v3.3.10/rules/REQUEST-921-PROTOCOL-ATTACK.conf y https://docs.cpanel.net/whm/scripts/the-modsec_vendor-script/. El comando oficial update hostium actualiza desde la URL con la que se instaló el vendor.
