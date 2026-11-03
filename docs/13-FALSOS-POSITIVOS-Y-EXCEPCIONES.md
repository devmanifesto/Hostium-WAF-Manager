# Falsos positivos y excepciones

## Estado y objetivo

La estable publicada sigue siendo **2.1.1**. La candidata local **2.1.2** corrige el modelo de excepciones; no se promovió ni instaló. Reducir bloqueos legítimos requiere evidencia de la operación, no solo un 403.

Las cinco excepciones históricas están en `config/exclusions.yaml`, ahora con `habilitada: false`. No se conocen los dominios confirmados ni el parámetro de edición de PrestaShop. Por eso se conservan sus IDs mediante condiciones imposibles `@rx (?!)`, fase 1, `pass`, sin ctl. **Instalar la candidata sin completar el alcance puede hacer reaparecer los falsos positivos que la 2.1.1 exceptuaba.** No promoverla para resolver esos incidentes hasta validar cada caso.

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

`@streq` exige el endpoint completo. `@beginsWith` solo admite directorios terminados en `/`, por ejemplo `/admin1911/sell/catalog/products/`; exige confirmar que todo ese subárbol merece la excepción. Se usa `REQUEST_FILENAME`, que no incluye query string. No se admiten `@contains`, regex arbitrarias, rutas `/`, escapes ni toda la colección `ARGS`. Los parámetros soportados son nombres simples `ARGS:nombre`; otros formatos requieren implementar y probar soporte específico.

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

## Casos históricos pendientes

| ID | Caso | Información que falta confirmar |
| --- | --- | --- |
| 5500900 | `firmadatos`: 941130 y 941170 | Dominio y endpoint de la firma |
| 5500901 | `vseleccionados`: 942100 | Dominio y endpoint de selección |
| 5500902 | Plantilla WHMCS: tags XSS y RCE | Dominio, endpoint administrativo, autorización y IDs mínimos necesarios |
| 5500903 | Edición PrestaShop: 941160 | Dominio, ruta administrativa real y parámetro; no se permite `ARGS` completo |
| 5500904 | Serialización en `datos`: 933170 | Dominio y endpoint exacto del turnero |

`tests/fixtures/exclusiones-laboratorio.yaml` contiene el alcance sintético usado en pruebas. Sus dominios, rutas y fecha lejana no son datos de producción.

## Revisión y regresión

Una entrada activa vencida bloquea render y build. La fecha es una revisión de configuración, **no una caducidad automática en Apache**: una instalación existente sigue usando el conf anterior hasta cambiarla. No hay scheduler ni borrado remoto automático.

Antes de activar: petición legítima con el ID observado; mismo contenido en otro dominio, ruta, método y parámetro; ataque que otra regla siga detectando dentro del alcance. Verificar IDs por transacción, además del HTTP. Medir antes/después con ventanas comparables; conservar el ticket y rollback. `ultima_validacion` queda null hasta cPanel real.

## Puntaje y reglas propias

`REQUEST-910` no entra al ZIP. Bajar puntajes de métodos, multipart, RCE, NodeJS o Java también reduce bloqueo de ataques que solo activen una detección. `rules render-score` exige `--crs-dir` con una copia local idéntica de los cinco archivos y `--acknowledge-reduced-sensitivity`. La comparación no prueba el resto de la configuración: umbrales, paranoia, includes y funcionamiento requieren validación adicional. `package build-tune` está bloqueado con código 3; el ZIP histórico se conserva intacto.

`REQUEST-410` hace deny directo y no usa el puntaje CRS. Una exclusión 9xxxxx no elimina un bloqueo 5500xxx. Revisar especialmente multipart chunked, PHPSESSID como argumento, anidación profunda y grandes cargas. No se alteraron las expresiones ni las acciones de ese módulo en esta serie.

## Rollback

Deshabilitar la entrada, regenerar y construir una versión nueva. No editar ZIP publicados. Retirar una exclusión restaura inspección y puede restaurar el falso positivo; requiere coordinar la operación legítima. Los procedimientos de servidor permanecen en el documento 14 y requieren autorización explícita. Volver a 2.1.1 también restaura sus excepciones globales: no es una solución al alcance inseguro.

## Referencias

Consultadas el 2 de noviembre de 2026: [CRS, tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/) y [ModSecurity v2, variables y cadenas](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)).
