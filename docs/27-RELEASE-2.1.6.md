# Release estable 2.1.6 — exclusiones sin dominio de path y de campo

## Autorización y alcance

3 de noviembre de 2026. El operador pidió publicar hostium-2.1.6 subiendo solo el último número. ZIP nuevo. No se reescribe hostium-2.1.5.zip ni los anteriores. 5500906 ya estaba en el árbol como 2.1.5, así que no se republicó. Esta sesión no abre SSH, no refresca hostium-tune y no mete REQUEST-910 ni SecRuleUpdateActionById en el ZIP. El único meta de instalación sigue siendo publish/stable/meta_hostium.yaml.

La distribution es hostium-2.1.6. Conserva vendor_id hostium, raíz hostium/ y los dos conf REQUEST-410 y REQUEST-900. Los controles de 5500900–5500906 no cambian. ultima_validacion sigue null.

## Causa y corrección

Los casos nuevos se generan desde config/exclusions.yaml. Fase 1, pass, nolog, t:none, tag hostium-crs-exclusion, ver hostium/2.1.6. Ninguno lleva dominio: el path o el nombre del campo viaja con la cuenta.

- 5500907. POST y REQUEST_FILENAME `@beginsWith /modules_/imno_/`. ctl:ruleRemoveTargetById=933210;ARGS:comentario.
- 5500908. POST y REQUEST_FILENAME `@beginsWith /modules_/imno/`. ctl:ruleRemoveTargetById=942100;ARGS:transferencia. Ese prefijo no cubre `/modules_/imno_/`.
- 5500909. POST y REQUEST_FILENAME `@beginsWith /server20200601/mod/reportes/`. ctl:ruleRemoveTargetById=942100;ARGS:ctas.
- 5500910. POST y REQUEST_FILENAME `@streq /server20200601/mod/compras/fcompra.php`. ctl de 942100 sobre ARGS:description y de 930110 sobre ARGS:flete_observaciones.
- 5500911. POST y REQUEST_FILENAME `@streq /server20200601/mod/compras/itemfcompra.php`. ctl:ruleRemoveTargetById=930110;ARGS:marcades.
- 5500912. POST y REQUEST_FILENAME `@streq /server20200601/mod/agro/laboractividad.php`. ctl:ruleRemoveTargetById=930110;ARGS. Es la única regla nueva que quita ARGS entero. El nombre marcaid_Ndes cambia y no hay regex. Un `../` real en otro campo de esa pantalla deja de verlo 930110. El resto de las reglas siguen.
- 5500913. SecAction sin URI. ctl de 932130, 932140 y 942170 sobre ARGS:codscripttarjeta.
- 5500914, 5500915 y 5500916. El pedido de Moodle eran tres controles con selectores distintos. Un id no puede repetirse y una cadena es un Y, no un O. Quedaron en tres directivas. 5500914 es POST bajo `/mod/quiz/` y quita MULTIPART_PART_HEADERS de 922130. No baja el puntaje global. 5500915 es POST bajo `/mod/forum/` y quita 941100 y 941160 de ARGS:message[text]. 5500916 es SecAction sin URI para ARGS:summary_editor[text], las mismas dos reglas. No usa `/login/`.

No se desactivan reglas. No se usa allow, SecRuleRemoveById ni apagado del motor. No se excluye 942190. 930110 solo sale de los campos y scripts de arriba. El id de catálogo del puntaje, que no es una SecRule y no entra al ZIP, pasa de 5500910 a 5500990 para dejar 5500910 a fcompra.php. El conf de puntaje y hostium-tune-2.1.0.zip no cambian.

## Evidencia local realmente ejecutada

- `python -m pytest`: **110 passed, 23 deselected**.
- `python -m ruff check src tests`: **All checks passed!**
- `python -m hostium_waf rules validate` y `rules check-ids`: en verde. Colisión con reglas instaladas: no_comprobado.
- Tres regresiones HTTP contra `owasp/modsecurity-crs:3.3.10-apache-202610180210-lts` y el conf de producción, en 10.44s.
  - POST `/modules_/imno_/saveData.php` con `comentario` igual a `GARANTIAS: AVENALI ADOLFO (3364)668153 (padre inq)`: 503, sin 933210 y sin 949110. El mismo cuerpo en `/index.php`: 403, con 933210 y 949110.
  - `(3364)668153` solo no coincide con 933210 de CRS 3.3.10. La expresión pide otro paréntesis después del primero. La frase de evidencia sí coincide, y es la que se posteó.
  - POST multipart `/mod/quiz/processattempt.php` con partes `q1:`, `q2:` y `q3:`: 503, sin 922130 y sin 949110. Las mismas partes en `/index.php`: 403, con 922130 y 949110.
  - POST `/mod/forum/post.php` con `message[text]=<h2>hola</h2>`: 503, sin 941100 y sin 941160. Esos encabezados solos no suman en CRS 3.3.10 con paranoia 1. El mismo campo con `<img src=x>`, que sí mira 941160, sigue en 503 en el foro, sin 941100 y sin 941160. Ese img en `/index.php`: 403 y 941160. Un `<script>` en otro campo de `/mod/forum/post.php`: 403 y 949110.
- No se corrió el resto de la suite de integración. 503 es el backend de laboratorio ausente, no un 200 de la aplicación. No se observó en cPanel.

## Artefacto

- Bytes: **5672**
- MD5: `fb920ce9bb67244dcebf100b3d45c19d`
- SHA512: `5630a5348e2c0bcfbcef5fe4783431b4aa6c0bd531cbf5c20d2dc83732f1b0611d687b1442acd29eed47e8fb6e1cc10fd7a1af9e8f6a353c9a4a35b7980b5d6b`
- SHA256: `a67803befc9030cbef83b8e24342d0f1a4007e5fcf00b3a39e4b332bd11902ea`
- ZIP: https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/hostium-2.1.6.zip
- Metadata: https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml

El ZIP contiene `hostium/`, REQUEST-410 y REQUEST-900. No contiene REQUEST-910 ni SecRuleUpdateActionById. hostium-2.1.5.zip conserva MD5 `e7e47f18451bc794d3575ae53cd28f89` y 4929 bytes. meta_hostium-tune.yaml no se reescribió.

## Verificación pública

Commit 07123c2 en origin/main. Un GET sin sesión de la metadata y del ZIP 2.1.6 devolvió ambos archivos. El ZIP público tiene 5672 bytes y MD5 `fb920ce9bb67244dcebf100b3d45c19d`. La metadata pública tiene 506 bytes, MD5 `8b75844f435d3a33ac03f6f1208e74f6`, y nombra `hostium-2.1.6` con ese mismo MD5 de ZIP. El ZIP público 2.1.5 sigue en 4929 bytes y MD5 `e7e47f18451bc794d3575ae53cd28f89`. No se ejecutó SSH ni `modsec_vendor`.

## Actualización en calcium a cargo del operador

Guardar la salida previa de vendor list, httpd -t e includes. Luego, como root:

```sh
/usr/local/cpanel/scripts/modsec_vendor update hostium
/usr/local/cpanel/scripts/modsec_vendor list
httpd -t
httpd -t -D DUMP_INCLUDES
```

Confirmar description 2.1.6 y dos sets. Si httpd -t falla, no recargar. Esta sesión no ejecutó esos comandos.
