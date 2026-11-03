# Compatibilidad

## Objetivo

Decir con qué se probó el diseño y qué sigue siendo una hipótesis.

## Audiencia

Quien planee llevar el ZIP a un nodo distinto de la notebook de desarrollo.

## Prerrequisitos

La línea base de la especificación y `docs/11-PRUEBAS-Y-VALIDACION.md`.

## Matriz

| Pieza | Lo que dice la línea base del piloto | Lo que este repo comprobó el 23 de octubre de 2026 |
| --- | --- | --- |
| cPanel / WHM | Vendor OWASP3 por `modsec_vendor` | No se ejecutó el script. El contrato se codificó según la documentación del 23 de octubre de 2026 |
| EasyApache 4 | Motor RPM 2.9.15 | El generador acepta la clave `2.9.15`. No se instaló el RPM |
| CloudLinux | Mencionado en el piloto | No se inspeccionó un nodo |
| Apache + ModSecurity Debian | `security2_module` cargado en el piloto | Contenedor local: paquete `modsecurity 2.9.7-1+deb12u2`, Apache/2.4.68 (Debian). Los ids 5500100 y 5500101 se observaron ahí. No es el RPM del piloto |
| Imagen OWASP CRS | RPM 3.3.10 en el piloto | Tag `owasp/modsecurity-crs:3.3.10-apache-202610180210-lts`, digest `sha256:98fb77754c674c235b05ed7883974d7dea6f1ab9ff4ae0f08fd40456ba9d2aec`. `apachectl -v` imprimió Apache/2.4.69 (Unix). El módulo contiene la cadena `ModSecurity-2.9.15/apache2` y también `2.9.14`. No es el RPM de cPanel y no se copia al ZIP |
| CRS 4 | No está en el piloto | Sin promesa |
| Engintron / NGINX | Posible en el piloto | `rpm -q ea-nginx` es una inferencia. No demuestra el camino del tráfico |
| ModSecurity 3 / Coraza | No | No se declara la misma clave de motor para un paquete no probado |

## Verificación

`package build --engine 2.9.15` escribe esa clave como string. En la candidata 2.1.2 el builder rechaza otros motores; la validación de forma YAML no acredita compatibilidad. Ampliar MOTORES_CANDIDATA requiere evidencia de laboratorio y revisión, sin afirmar validación en cPanel. En 1.0.0 la clave que escribe el flujo de desarrollo es `2.9.15`, que es la del piloto según la especificación. El Apache donde se vieron los ids es el de Debian 2.9.7 y el de la imagen CRS descrita arriba.

## Deshacer

No hace falta. No se cambió la compatibilidad de un servidor.

## Problemas frecuentes

Leer la descripción del vendor OWASP en `modsec_vendor list` como si fuera la versión del RPM. La especificación ya vio una descripción 3.3.9 con un RPM 3.3.10. La fuente de la versión instalada es `rpm -q`.

## Referencias

`docs/REFERENCIAS.md`.

## Limitaciones

La celda Debian usa el paquete que imprimió el contenedor. La celda CRS usa `apachectl` y una cadena del `.so`. Ninguna de las dos es el RPM `2.9.15-2.3.1.cpanel`. En la imagen local, `apache2ctl configtest` aceptó los dos `.conf` que entran al ZIP. El 24 de octubre de 2026 se repitió ese `configtest` y `test_motor_ve_las_reglas_410` pidió los casos de `docs/22-QA-TRES-PASADAS.md` ya cerrados en la 1.1.2. El example de fase 4 no se montó.

## Candidata local 2.1.2

Las pruebas nuevas cargan REQUEST-900 con CRS 3.3.10 en imagen fijada por digest. El conf de laboratorio se incluye después de CRS: los ctl fase 1 afectan los objetivos fase 2. Esto no comprueba el RPM, los includes, los virtualhosts ni la autenticación de un cPanel. La prueba de sintaxis ahora extrae REQUEST-410 y REQUEST-900 del ZIP candidato real. Los resultados actuales están en el documento 23; las filas fechadas arriba son históricas.
