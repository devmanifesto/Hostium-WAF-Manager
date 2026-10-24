# Seguridad

## Versiones

La línea mantenida en este repositorio es la 1.0.x del ruleset y de la herramienta. No hay una ventana de soporte distinta para releases anteriores porque no existen.

## Qué reportar

Escribí al equipo de seguridad de Hostium por el canal interno que ya usen para incidentes de plataforma. No abras un issue público con un log de ModSecurity, una cookie, un cuerpo de petición o una clave.

Incluí la versión del ruleset (`hostium-x.y.z`), el id de la regla, el commit y una petición mínima que reproduzca el problema sin datos de clientes.

## Credenciales

No hay tokens en el repositorio. SSH usa el agente o las claves del operador. La CLI no acepta contraseñas en el inventario. No pongas `StrictHostKeyChecking=no`.

## Artefactos

MD5 y SHA512 cumplen el contrato de cPanel. No autentican al publicador. Una firma externa, si se agrega, la verifica este proyecto, no WHM.

## Logs

No subas auditorías reales de ModSecurity a git ni a una CI pública. Pueden contener URLs, cookies y cuerpos.
