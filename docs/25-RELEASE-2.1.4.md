# Release estable 2.1.4 — portada Moodle en pluginfile.php

## Autorización y alcance

2 de noviembre de 2026. El operador pidió publicar hostium-2.1.4 subiendo solo el último número. ZIP nuevo. No se reescribe hostium-2.1.3.zip ni los anteriores. Esta sesión no abre SSH, no refresca hostium-tune y no mete REQUEST-910 ni SecRuleUpdateActionById en el ZIP. El único meta de instalación sigue siendo publish/stable/meta_hostium.yaml.

La distribution es hostium-2.1.4. Conserva vendor_id hostium, raíz hostium/ y los dos conf REQUEST-410 y REQUEST-900. Los controles de 5500900–5500904 no cambian. ultima_validacion sigue null.

## Causa y corrección

Evidencia de zinc, 2026-11-02 22:32–22:46 ART, CRS 3.3.10. La 933210 (PHP Injection Attack: Variable Function Call Found, crítica, 5 puntos) coincide en REQUEST_FILENAME con el dato `(1) (1) (1) (1)` de una portada servida por pluginfile.php. La 949110 devuelve el bloqueo. El host visto no entra en la regla: el mismo path tiene que pasar en cualquier servidor de la flota.

5500905 se genera desde config/exclusions.yaml. No es heredada_estable y no lleva lista de hosts. Fase 1, pass, nolog, t:none, tag hostium-crs-exclusion, ver hostium/2.1.4. Una sola cadena:

- REQUEST_FILENAME `@beginsWith /pluginfile.php/`
- REQUEST_METHOD GET
- `ctl:ruleRemoveTargetById=933210;REQUEST_FILENAME` en el último eslabón

No quita ARGS, ARGS_NAMES, cookies ni headers. No desactiva 933210, no le baja el puntaje y no usa allow, SecRuleRemoveById ni apagado del motor. No limita por extensión ni escribe una regex del `(1)`.

En CRS 3.3.10 la 933210 pide la forma de llamada variable, por ejemplo `(1) (1)`. Un solo `(1)` no es ese patrón. `uca(1)` solo tampoco. `uca(1)(1)` sí, y queda en ARGS. `system(` sin el paréntesis de cierre no coincide con 933160; `system(id)` sí y sigue sumando 5 fuera del prefijo.

## Evidencia local realmente ejecutada

- `python -m pytest`: **108 passed, 19 deselected**.
- `python -m ruff check src tests`: **All checks passed!**
- `python -m hostium_waf rules validate` y `rules check-ids`: en verde. Colisión con reglas instaladas: no_comprobado.
- La regresión HTTP de 5500905, contra `owasp/modsecurity-crs:3.3.10-apache-202610180210-lts` y el conf de producción, pasó en 7.98s. Host de laboratorio `moodle.example.test`, no el host visto en zinc.
  - GET `/pluginfile.php/1/course/overviewfiles/portada%20(1).png`: 503, sin 933210 y sin 949110.
  - GET del nombre de la evidencia, cuatro `(1)`, bajo `/pluginfile.php/`: 503, sin 933210 y sin 949110.
  - El mismo nombre fuera de `/pluginfile.php/`: 403, 933210, dato `(1) (1) (1) (1)` en REQUEST_FILENAME, 949110 con puntaje 5.
  - GET `/pluginfile.php/1/course/overviewfiles/x.png?x=uca(1)(1)`: 403, 933210 con `found within ARGS`, 949110.
  - GET `/files/system(id).png`: 403, 933160 y 949110.
- No se corrió el resto de la suite de integración. 503 es el backend de laboratorio ausente, no un 200 de Moodle. No se observó en cPanel.

## Artefacto

- Bytes: **4764**
- MD5: `8a0b7c1ad1441e977dbb9622d8608950`
- SHA512: `42006f56ccbca6fc9ee80ddec028b849ae20e3dab2a2f5a3006afceb60ec0c36d4ba89437385cf54a0f712e8c77168b210f4210d5d455a6e5204e01862e0e67d`
- SHA256: `6ec885f9f461bd096aef2219837f20b1012a4f83a3362bb06896b7872d80ca8e`
- ZIP: https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/hostium-2.1.4.zip
- Metadata: https://raw.githubusercontent.com/devmanifesto/Hostium-WAF-Manager/main/publish/stable/meta_hostium.yaml

El ZIP contiene `hostium/`, REQUEST-410 y REQUEST-900. No contiene REQUEST-910 ni SecRuleUpdateActionById. hostium-2.1.3.zip y meta_hostium-tune.yaml no se reescriben. La comprobación pública por HTTPS se anota al final cuando el push ya está en main.

## Actualización en calcium a cargo del operador

Guardar la salida previa de vendor list, httpd -t e includes. Luego, como root:

```sh
/usr/local/cpanel/scripts/modsec_vendor update hostium
/usr/local/cpanel/scripts/modsec_vendor list
httpd -t
httpd -t -D DUMP_INCLUDES
```

Confirmar description 2.1.4 y dos sets. Si httpd -t falla, no recargar. Esta sesión no ejecutó esos comandos.
