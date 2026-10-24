# Runbook de incidentes

## Objetivo

Ordenar las primeras acciones cuando el ruleset, el publicador o un falso positivo se salen de cauce.

## Audiencia

Quien esté de guardia. No hace falta que haya construido el ZIP.

## Prerrequisitos

Acceso de lectura a WHM y, si hay que deshabilitar el vendor, aprobación para modificar.

## Falso positivo masivo

1. SOLO LECTURA: anotá dominio, ruta, id y la hora de inicio.
2. Si el id es 5500100 o 5500101 y el impacto es amplio, PRODUCCIÓN / MODIFICA: `modsec_vendor disable hostium`. No deshabilites OWASP3.
3. REINICIA Apache solo si hace falta para que el disable aplique, en la misma ventana.
4. Después, la excepción estrecha del documento 13. No dejes el vendor apagado como solución permanente sin una fecha.

## Posible bypass nuevo

No escribas una regla `deny` en caliente dentro del include del servidor. El cambio entra por git, con casos, y sale como versión nueva. Mientras tanto, CRS sigue en su sitio.

## Publicador caído

WHM no puede actualizar. Las reglas ya cargadas siguen hasta que alguien corra un update. No hace falta apagar el vendor por un 404 del origen. Avisá y restaurá el origen con el ZIP y la metadata de `dist/releases` o del backup.

## Release mala ya distribuida

Documento 14, vía rápida y después la versionada para que un update no la reintroduzca.

## Verificación

`modsec_vendor list` muestra hostium disabled u OWASP3 enabled, según la acción que hayas tomado. Guardá esa salida fuera del git.

## Deshacer

Si deshabilitaste de más, no rehabilites hasta que la metadata apunte a una release verificada.

## Problemas frecuentes

Un 403 masivo cuyo id es de CRS (9xxxxx) y se trata como si fuera Hostium. El disable de `hostium` no lo va a sacar. La excepción va sobre el id que realmente aparece.

## Referencias

Documentos 13, 14 y 18 es este archivo.

## Limitaciones

No hay puente de guardia ni un comando de la CLI que ejecute estos pasos.
