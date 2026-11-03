# Falsos positivos y excepciones

## Estado y objetivo

La estable preparada para publicación es **2.1.4**, autorizada por el operador. 5500905 exceptúa el GET cuyo path empieza por `/pluginfile.php/`: quita solo `REQUEST_FILENAME` de 933210 y no lleva dominio. La 2.1.3 ya corrigió el bloqueo WHMCS que sobrevivía a las exclusiones XSS/RCE: 921130 aportaba los 5 puntos que disparaban 949110. En CRS 3.3.10 el patrón incluye `<html` y `<meta`; el texto DOCTYPE por sí solo no es ese patrón. Se reproduce con una plantilla que contiene `<html`.

El control agregado es `ruleRemoveTargetById=921130`, para emailglobalheader y emailglobalfooter. No se elimina attack-protocol completo: 921120 continúa bloqueando un payload de cabecera en el mismo campo. El selector es Host clientes.hostium.com, REQUEST_FILENAME exacto /admin1911/configgeneral.php y método POST. La query action=save no cambia el selector; otros campos siguen inspeccionados.

La candidata 2.1.2 permanece como artefacto local anterior y no se reutiliza. Los otros cuatro casos no se desactivan al publicar: conservan temporalmente el comportamiento de 2.1.1, con compatibilidad explícita y revisión pendiente. PrestaShop ahora selecciona REQUEST_FILENAME para que una query no active su excepción.

## Diagnóstico local, solo lectura

1. Obtener por un mecanismo autorizado un error log de Apache o los mensajes de la sección H del audit log ModSecurity v2. Mantener el original fuera del repositorio, con acceso restringido. Este comando no descarga nada del servidor.
2. Analizar sin persistir resultados:

```powershell
python -m hostium_waf logs analyze --input C:/evidencias/error.log --server nodo-piloto
```

3. Para identificar rutas, usar explícitamente `--include-locations`. Siempre se elimina la query string. El path puede contener datos personales; proteger también el informe. Sin esa opción, dominios y rutas se representan por alias SHA256 estables, que no equivalen a anonimización irreversible.
4. Revisar los IDs detectores y la variable. `949110` es evaluación del puntaje: no reemplaza el diagnóstico de los IDs que aportaron a ese puntaje. Un `Access denied with code` confirma una denegación observada por ModSecurity, no el estado final de toda la cadena proxy.
5. Confirmar con el dueño de la aplicación que la operación era legítima y reproducirla en laboratorio. Nunca clasificar automáticamente todo hit como falso positivo.

## Configuración de una excepción activa

Este ejemplo es exclusivamente de laboratorio; no inventa dominios productivos:

```yaml
version_esquema: 1
exclusiones:
  - id: '5500900'
    tipo: runtime
    habilitada: true
    dominios: [tuning.example.test]
    metodos: [POST]
    uri:
      operador: '@streq'
      valor: /firma.php
    controles:
      - tipo: ruleRemoveTargetById
        objetivo: '941170'
        variable: ARGS:firmadatos
    regla_objetivo: '941170'
    motivo: Firma JPEG en data-URI, reproducida en laboratorio
    owner: equipo-seguridad
    ticket: LAB-5500900
    fecha_revision: '2027-05-02'
    alcance: POST de firma en el virtualhost de laboratorio
```

El dominio es exacto, sin comodines ni IP. Se permiten varios dominios explícitos si el mismo caso está confirmado para cada uno. Host es un selector del virtualhost, no autenticación. La configuración del servidor debe rechazar hosts ajenos al sitio; esta excepción no acredita permisos del usuario.

`@streq` exige el endpoint completo. `@beginsWith` solo admite directorios terminados en `/`, por ejemplo `/admin1911/sell/catalog/products/`; exige confirmar que todo ese subárbol merece la excepción. Se usa `REQUEST_FILENAME`, que no incluye query string. No se admiten `@contains`, regex arbitrarias, rutas `/`, escapes ni toda la colección `ARGS`. Los parámetros soportados son nombres simples `ARGS:nombre`.

Una regla con `selector: path` no lleva dominio. Hoy el único caso es 5500905: métodos `["GET"]`, prefijo `/pluginfile.php/` y un ctl `REQUEST_FILENAME`. No se marca `heredada_estable` y no se inventa una lista de hosts. El ctl va en el eslabón del método, así un POST al mismo prefijo no lo ejecuta.

Los controles admitidos son `ruleRemoveTargetById` y `ruleRemoveTargetByTag`; preferir IDs individuales. Excluir tags amplía el impacto y exige justificar cada familia afectada. No se admiten `allow`, quita de reglas completas ni apagado del motor.

## Generación y orden

```powershell
# MODIFICA solo el conf local; valida el catálogo antes de escribir.
python -m hostium_waf rules render-exclusions
# SOLO LECTURA local.
python -m hostium_waf rules validate
python -m hostium_waf rules check-ids
```

Cada entrada activa genera una cadena fase 1: dominio → ruta → método. El ctl está en la última condición: no se ejecuta si falla cualquiera de las anteriores. No se inspecciona el cuerpo en fase 1; se configura el objetivo que CRS inspeccionará en fase 2.

Las exclusiones runtime deben ejecutarse antes de las reglas afectadas. En laboratorio se probó incluir el conf después de CRS y alcanzar reglas de fase 2 desde fase 1. Esto no autoriza a aplicar el mismo mecanismo sobre reglas CRS de fase 1. El esquema no descubre la fase del RPM; hay que comprobar cada objetivo, includes y efecto en el cPanel real. Las exclusiones configure-time van después de las definiciones CRS.

## Compatibilidad transitoria

Los IDs 5500900, 5500901, 5500903 y 5500904 conservan los controles del ZIP 2.1.1, fijado al SHA256 `231a9d1746faa26f6f98580602f01bcd82174587c6d5cdeaef9ee8475e685d31`. `heredada_estable: true` solo se permite para esos cuatro IDs, con controles idénticos, dominios/metodos vacíos y motivo pendiente. No admite casos nuevos, agregar controles ni cambiar selectores. El único ajuste del selector heredado es REQUEST_FILENAME en 5500903, que elimina coincidencias por query sin ampliar el alcance.

Es una excepción temporal a la exigencia de dominio para no romper operaciones actualmente exceptuadas. Su alcance amplio sigue siendo una limitación: faltan dominios/endpoints confirmados para firma, selección de cuentas, PrestaShop y turnero. Para migrar cada caso, quitar heredada_estable, completar dominio/ruta/método/parámetro, probar y publicar otra versión. No presentar estos cuatro casos como alcance ya corregido.

5500905 no es heredada. Evidencia del 2026-11-02, 22:32–22:46 ART, CRS 3.3.10: 933210 (crítica, 5) coincide en `REQUEST_FILENAME` con el nombre de una portada y 949110 devuelve el bloqueo. El host visto no entra en la regla: el mismo path tiene que pasar en cualquier servidor de la flota. No se limita por extensión ni se escribe una regex del `(1)`. Un nombre con `system(` fuera de `/pluginfile.php/` sigue sumando 5 por las reglas PHP que no son esta excepción. ARGS, cookies y headers de 933210 no se quitan.

WHMCS 5500902 no admite modo heredado: su alcance fue confirmado por el usuario y las regresiones incluyen ambos campos, dominio ajeno, otro argumento y la regla 921120 todavía activa. La fixture de laboratorio tiene dominios sintéticos; no reemplaza el ensayo de cPanel.

## Revisión y regresión

Una entrada activa vencida bloquea render y build. La fecha es una revisión de configuración, **no una caducidad automática en Apache**: una instalación existente sigue usando el conf anterior hasta cambiarla. No hay scheduler ni borrado remoto automático.

Antes de activar: petición legítima con el ID observado; mismo contenido en otro dominio, ruta, método y parámetro; ataque que otra regla siga detectando dentro del alcance. Verificar IDs por transacción, además del HTTP. Medir antes/después con ventanas comparables; conservar el ticket y rollback. `ultima_validacion` queda null hasta cPanel real.

## Puntaje y reglas propias

`REQUEST-910` no entra al ZIP. Bajar puntajes de métodos, multipart, RCE, NodeJS o Java también reduce bloqueo de ataques que solo activen una detección. `rules render-score` exige `--crs-dir` con una copia local idéntica de los cinco archivos y `--acknowledge-reduced-sensitivity`. La comparación no prueba el resto de la configuración: umbrales, paranoia, includes y funcionamiento requieren validación adicional. `package build-tune` está bloqueado con código 3; el ZIP histórico se conserva intacto.

`REQUEST-410` hace deny directo y no usa el puntaje CRS. Una exclusión 9xxxxx no elimina un bloqueo 5500xxx. Revisar especialmente multipart chunked, PHPSESSID como argumento, anidación profunda y grandes cargas. No se alteraron las expresiones ni las acciones de ese módulo en esta serie.

## Rollback

Deshabilitar la entrada, regenerar y construir una versión nueva. No editar ZIP publicados. Retirar una exclusión restaura inspección y puede restaurar el falso positivo; requiere coordinar la operación legítima. Los procedimientos de servidor permanecen en el documento 14 y requieren autorización explícita. Volver a 2.1.1 restaura el alcance global anterior de WHMCS y el bloqueo por 921130; no es una solución al incidente.

## Referencias

Consultadas el 2 de noviembre de 2026: [CRS, tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/) y [ModSecurity v2, variables y cadenas](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)).
