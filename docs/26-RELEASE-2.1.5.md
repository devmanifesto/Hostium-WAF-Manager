# Release estable 2.1.5 — editor de WordPress en excerpt y content

## Autorización y alcance

3 de noviembre de 2026. El operador pidió publicar hostium-2.1.5 subiendo solo el último número. ZIP nuevo. No se reescribe hostium-2.1.4.zip ni los anteriores. Esta sesión no abre SSH, no refresca hostium-tune y no mete REQUEST-910 ni SecRuleUpdateActionById en el ZIP. El único meta de instalación sigue siendo publish/stable/meta_hostium.yaml.

La distribution es hostium-2.1.5. Conserva vendor_id hostium, raíz hostium/ y los dos conf REQUEST-410 y REQUEST-900. Los controles de 5500900–5500905 no cambian. ultima_validacion sigue null.

## Causa y corrección

Evidencia de barium, 2026-11-03 08:14–10:10 ART, CRS 3.3.10, paranoia 1. Al guardar posts de WordPress, 949110 responde con score 10. Host capacitaciones.municipalidadsalta.gob.ar. Paths POST /wp-admin/post.php y POST /wp-admin/admin-ajax.php. La exclusión de WordPress ya estaba prendida y estos campos no entran.

5500906 se genera desde config/exclusions.yaml. Fase 1, pass, nolog, t:none, tag hostium-crs-exclusion, ver hostium/2.1.5. Una sola cadena, solo ese host:

- REQUEST_HEADERS:Host exacto, con el puerto opcional que ya usa el resto de las cadenas con dominio
- REQUEST_FILENAME `@beginsWith /wp-admin/`
- REQUEST_METHOD POST
- En el último eslabón, `ctl:ruleRemoveTargetById` de 941100, 941160, 941200, 941310 y 941350, cada una sobre ARGS:excerpt y ARGS:content

No quita ARGS entero. No desactiva esas reglas. No usa allow, SecRuleRemoveById ni apagado del motor. No excluye 942190. No ata la regla al id del post.

## Evidencia local realmente ejecutada

- `python -m pytest`: **109 passed, 20 deselected**.
- `python -m ruff check src tests`: **All checks passed!**
- `python -m hostium_waf rules validate` y `rules check-ids`: en verde. Colisión con reglas instaladas: no_comprobado.
- La regresión HTTP de 5500906, contra `owasp/modsecurity-crs:3.3.10-apache-202610180210-lts` y el conf de producción, pasó en 8.30s.
  - POST `/wp-admin/post.php` en ese host, con `excerpt=<h2>Lavado de manos</h2>` y `content=<h3 class="x">texto</h3>`: 503, sin 941100, sin 941160 y sin 949110.
  - Esos encabezados solos no suman en CRS 3.3.10 con paranoia 1. 941160 no mira `h2` ni `h3`. El mismo texto más `<img src=x>`, que sí mira 941160, sigue en 503 en `/wp-admin/post.php` de ese host, sin 941100, sin 941160 y sin 949110.
  - Ese cuerpo con img, posteado a `/` del mismo host: 403 y 949110.
  - El mismo cuerpo posteado a `/wp-admin/post.php` de otro host: 403 y 949110.
  - POST `/wp-admin/post.php` en ese host con `q=<script>alert(1)</script>`: 403 y 949110.
- No se corrió el resto de la suite de integración. 503 es el backend de laboratorio ausente, no un 200 de WordPress. No se observó en cPanel.

## Artefacto

- Bytes: **4929**
- MD5: `e7e47f18451bc794d3575ae53cd28f89`
- SHA512: `c2ba2099ee81ef0ec89537f1a7a7f8c9c71a797056e91a80b9843e9be7addb368f40e551d2aa9ab6a271aa0279d47b8d8af0e3f8ec15afb2c898081522af0b5a`
- SHA256: `7e4031d8b59bed78fe87b524ce9d044269378662e80fc233c33e1862b6a925b1`
- ZIP: https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/hostium-2.1.5.zip
- Metadata: https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml

El ZIP contiene `hostium/`, REQUEST-410 y REQUEST-900. No contiene REQUEST-910 ni SecRuleUpdateActionById. hostium-2.1.4.zip conserva MD5 `8a0b7c1ad1441e977dbb9622d8608950` y 4764 bytes. meta_hostium-tune.yaml no se reescribió.

## Verificación pública

Commit 3a97203 en origin/main. Un GET sin sesión de la metadata y del ZIP 2.1.5 devolvió ambos archivos. El ZIP público tiene 4929 bytes y MD5 `e7e47f18451bc794d3575ae53cd28f89`. La metadata pública tiene 506 bytes, MD5 `4915b160fc52f27c572f096f82914d9c`, y nombra `hostium-2.1.5` con ese mismo MD5 de ZIP. No se ejecutó SSH ni `modsec_vendor`.

## Actualización en calcium a cargo del operador

Guardar la salida previa de vendor list, httpd -t e includes. Luego, como root:

```sh
/usr/local/cpanel/scripts/modsec_vendor update hostium
/usr/local/cpanel/scripts/modsec_vendor list
httpd -t
httpd -t -D DUMP_INCLUDES
```

Confirmar description 2.1.5 y dos sets. Si httpd -t falla, no recargar. Esta sesión no ejecutó esos comandos.
