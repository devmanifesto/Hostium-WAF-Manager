# Roadmap

## Estado al 3 de noviembre de 2026

Estable 2.1.7 publicada en el origen. 5500917 cubre el POST bajo `/aplicacion_customs/MCP/` para cinco reglas XSS sobre ARGS. 5500907–5500916 siguen cubriendo rutas y nombres de campo sin dominio. 5500906 sigue cubriendo el POST de un host bajo `/wp-admin/` para excerpt y content. 5500905 sigue cubriendo el GET de `/pluginfile.php/` sin dominio. WHMCS sigue con dominio, ruta y POST confirmados. La actualización de calcium la hará el operador. Los otros cuatro casos mantienen compatibilidad transitoria con la estable 2.1.1; siguen pendientes de delimitar. La candidata 2.1.2 no se publicó ni se reescribe. `hostium-2.1.6.zip` queda inmutable.

## Prioridad inmediata

- Confirmar dominio, endpoint, método, parámetro e IDs de los cuatro casos heredados. Permanecen activos por compatibilidad y no deben ampliarse sin esos datos.
- Obtener eventos reales por un mecanismo autorizado, mantenerlos fuera de Git y analizarlos con logs analyze. Confirmar paranoia, puntajes y umbrales efectivos por servidor.
- Ensayar el ZIP candidato en cPanel de laboratorio: includes, sintaxis, estado por dominio, rutas del proxy y efectos de cada excepción. ultima_validacion sigue null hasta ese ensayo real.
- Confirmar que las operaciones legítimas pasan y que los ataques fuera del alcance siguen detectándose; comparar períodos de tráfico equivalentes.

## Operación de flota

Los apply de deploy, rollback, publish y updates permanecen bloqueados. Faltan captura de estado previo, idempotencia, aprobación y rollback ensayado. No se automatizan cambios SSH ni recargas. La auditoría de inventario no descarga logs y no prueba protección por dominio.

## Evolución

- Autorización y alcance por aplicación con evidencia; no usar login/admin como criterio de confianza.
- Más formatos de audit log, ventanas temporales verificadas y tasas con denominador de tráfico. Hoy solo se comparan conteos de archivos locales.
- Integraciones de observabilidad, firmas verificadas por pipeline, RBAC y panel solo después del circuito de tuning.
- CRS 4, ModSecurity 3 y Coraza requieren validaciones separadas; no se declaran compatibles.

## Promoción y rollback

Revisar documento 13 y QA 23 antes de publicar. Retirar una excepción puede restaurar el falso positivo. Volver a 2.1.1 reintroduce sus excepciones globales. Los ZIP históricos son inmutables y no se reconstruyen para reemplazar bytes.
