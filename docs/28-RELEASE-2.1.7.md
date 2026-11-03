# Release estable 2.1.7 — HTML bajo /aplicacion_customs/MCP/

## Autorización y alcance

3 de noviembre de 2026. El operador pidió publicar hostium-2.1.7. ZIP nuevo. No se reescribe hostium-2.1.6.zip ni los anteriores. Los controles de 5500900–5500916 no cambian. Esta sesión no abre SSH, no refresca hostium-tune y no mete REQUEST-910 ni SecRuleUpdateActionById en el ZIP. El único meta de instalación sigue siendo publish/stable/meta_hostium.yaml.

La distribution es hostium-2.1.7. Conserva vendor_id hostium, raíz hostium/ y los dos conf REQUEST-410 y REQUEST-900. ultima_validacion sigue null.

## Causa y corrección

5500917 se genera desde config/exclusions.yaml. Fase 1, pass, nolog, t:none, tag hostium-crs-exclusion, ver hostium/2.1.7. Sin dominio. El campo no es fijo: el mismo HTML apareció en ARGS:reemplazar, ARGS:buscar y ARGS:x.

- REQUEST_FILENAME `@beginsWith /aplicacion_customs/MCP/`
- REQUEST_METHOD POST
- En el último eslabón, `ctl:ruleRemoveTargetById` de 941100, 941130, 941160, 941170 y 941200 sobre ARGS entero

No quita 932, 942, 933 ni 930. No desactiva reglas. No usa allow, SecRuleRemoveById ni apagado del motor.

## Evidencia local realmente ejecutada

- `python -m pytest`: **110 passed, 24 deselected**.
- `python -m ruff check src tests`: **All checks passed!**
- `python -m hostium_waf rules validate` y `rules check-ids`: en verde. Colisión con reglas instaladas: no_comprobado.
- La regresión HTTP de 5500917, contra `owasp/modsecurity-crs:3.3.10-apache-202610180210-lts` y el conf de producción, pasó en 7.35s.
  - POST `/aplicacion_customs/MCP/api_plantillas/plantillas_h2_editar_html.php` con `reemplazar=<img src="logo.jpg">`: 503, sin 949110.
  - El mismo cuerpo en `/index.php` del mismo host: 403 y 949110.
  - POST `/aplicacion_customs/MCP/api_compras/compras_h3_crear_factura_compra.php` con `descripcion=; cmd`: 403 y 932110.
- No se corrió el resto de la suite de integración. 503 es el backend de laboratorio ausente, no un 200 de la aplicación. No se observó en cPanel.

## Artefacto

- Bytes: **5737**
- MD5: `0d93c26ee8302c84540748083453bbea`
- SHA512: `2b33633bee6c567e1c2b605244d963980a0874125e2755cbf55eb1b1e8fd8ed9cf0e8221e0cc777712072545d4ab95109feb173b148252a90719120abdd7725e`
- SHA256: `235f82fc5c3bfe5809d54f0ff7bc7e6ad9bff8fceeeb32dd83e7dc39b475789d`
- ZIP: https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/hostium-2.1.7.zip
- Metadata: https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml

El ZIP contiene `hostium/`, REQUEST-410 y REQUEST-900. No contiene REQUEST-910 ni SecRuleUpdateActionById. hostium-2.1.6.zip conserva MD5 `fb920ce9bb67244dcebf100b3d45c19d` y 5672 bytes. meta_hostium-tune.yaml no se reescribió.

## Verificación pública

Pendiente del GET sin sesión, después de subir este commit. No se ejecutó SSH ni `modsec_vendor`.

## Actualización en calcium a cargo del operador

Guardar la salida previa de vendor list, httpd -t e includes. Luego, como root:

```sh
/usr/local/cpanel/scripts/modsec_vendor update hostium
/usr/local/cpanel/scripts/modsec_vendor list
httpd -t
httpd -t -D DUMP_INCLUDES
```

Confirmar description 2.1.7 y dos sets. Si httpd -t falla, no recargar. Esta sesión no ejecutó esos comandos.
