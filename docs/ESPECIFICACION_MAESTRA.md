# PROMPT MAESTRO PARA CURSOR — HOSTIUM WAF MANAGER

> **Uso:** copiá el contenido íntegro de este documento y pegalo en Cursor, preferentemente en modo Agent dentro de un repositorio nuevo. Este texto es una especificación de trabajo, no código ya implementado. Fecha de referencia: 23 de octubre de 2026.

---

## 0. Rol, modalidad y regla de ejecución

Actuá como **arquitecto de software senior, ingeniero de seguridad WAF, especialista en ModSecurity SecLang, administrador senior de cPanel/WHM y CloudLinux, y responsable de DevSecOps/SRE**. Tu trabajo es **DISEÑAR, IMPLEMENTAR, PROBAR Y DOCUMENTAR** un producto funcional denominado **Hostium WAF Manager**. No quiero únicamente sugerencias, pseudocódigo, fragmentos aislados, esqueletos ni documentación genérica: creá en este repositorio los archivos reales, código completo, fixtures de pruebas, scripts y manuales necesarios.

Trabajá en español en toda la documentación, comentarios explicativos, reportes y ayudas de CLI; mantené nombres técnicos, opciones y APIs en su formato original. Priorizá **seguridad, compatibilidad con cPanel, trazabilidad, reversibilidad y bajo riesgo de falsos positivos** antes que sumar muchas reglas.

Reglas de trabajo:

1. Empezá por leer el repositorio actual e identificar archivos preexistentes para no pisarlos. Si está vacío, inicializalo.
2. Primero redactá un `docs/00-PLAN-DE-IMPLEMENTACION.md` con decisiones, fases y criterios de aceptación; luego **continuá implementando**, no te detengas tras la planificación.
3. En cada fase entregá archivos completos, comandos reproducibles y resultados verificables de pruebas. Ejecutá todas las pruebas locales que permita el entorno. Si una prueba requiere cPanel real, documentala como pendiente de validación real; jamás simules un éxito.
4. Si encontrás ambigüedades de compatibilidad, consultá fuentes oficiales actuales y citá URL, versión y fecha de consulta en `docs/REFERENCIAS.md`. No inventes comandos o API.
5. No hagas cambios en servidores productivos, no actives reglas globales, no reinicies Apache, no subas artefactos a Internet y no uses credenciales reales sin una instrucción posterior explícita. Todo lo potencialmente disruptivo debe ser `dry-run` por defecto y requerir opt-in y aprobación.
6. No uses ni copies reglas propietarias de Imunify360, Imunify365, Comodo u otros proveedores cerrados. Creá contenido original utilizando estándares y patrones públicos. OWASP CRS es un proyecto independiente de código abierto con licencia Apache 2.0; si se reutiliza algún contenido, conservá las atribuciones correspondientes y documentá su procedencia.
7. Antes de afirmar que algo funciona, probalo o identificá exactamente qué no se pudo probar. No equipares sintaxis válida con protección efectiva.
8. Cuando modifiques cualquier script o archivo durante el proyecto, dejalo completo y coherente con el resto; no entregues solamente un diff como resultado final.

## 1. Contexto operativo REAL que debés respetar

El producto pertenece a **Hostium**, proveedor de hosting con varios servidores cPanel/WHM y CloudLinux, Apache y, en algunos nodos, NGINX/Engintron delante de Apache. Hay sitios WordPress y WooCommerce y también aplicaciones PHP propias. La infraestructura requiere operación multi-servidor y mínima interrupción.

Servidor piloto **calcium** (información confirmada manualmente por el operador, no significa que Cursor tenga acceso SSH):

- ModSecurity Apache: `ea-apache24-mod_security2-2.9.15-2.3.1.cpanel.x86_64`.
- Apache: módulo `security2_module` cargado.
- `SecRuleEngine On` declarado en `/etc/apache2/conf.d/modsec/modsec2.cpanel.conf`.
- OWASP CRS: paquete RPM `ea-modsec2-rules-owasp-crs-3.3.10-1.2.1.cpanel.x86_64`, instalado desde repositorio EasyApache 4.
- En `/usr/local/cpanel/scripts/modsec_vendor list`: vendor `OWASP3`, `enabled 1`, `in_use 33`, `configs (33)`; descripción textual que todavía decía v3.3.9, pese a que el RPM era 3.3.10. Diferenciar metadata descriptiva y versión instalada.
- Los 33 archivos de OWASP aparecieron efectivamente en `httpd -t -D DUMP_INCLUDES` dentro de `/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/`.
- COMODO aparece instalado pero deshabilitado; no figuró entre las inclusiones activas en esa comprobación.
- `httpd -t` indicó `Syntax OK` después de instalar el paquete OWASP.
- Rutas observadas: `/etc/apache2/conf.d/modsec/modsec2.user.conf`, `/etc/apache2/conf.d/modsec/modsec2.cpanel.conf`, `/etc/apache2/conf.d/modsec_vendor_configs/`.
- El servidor piloto **no ha sido validado todavía con una prueba efectiva de bloqueo de extremo a extremo**. No asumas que toda URL está protegida; revisá además ModSecurity por dominio y posibles bypass de NGINX.

**Importante:** esta información es una línea base, no una licencia para alterar calcium. Diseñá discovery dinámico para cualquier otro servidor, porque las versiones y rutas podrían variar.

## 2. Objetivo general

Construir **Hostium WAF Manager**, con estos componentes:

- **Hostium WAF Ruleset**: conjunto original, modular, testeable y versionado de reglas ModSecurity SecLang, que complemente OWASP CRS sin duplicar indiscriminadamente sus reglas.
- **Constructor de paquetes**: genera ZIP y YAML compatibles con el sistema de proveedores ModSecurity de cPanel/WHM.
- **Validador**: verifica reglas, IDs, metadatos, checksums, rutas, contenido ZIP, dependencias, compatibilidad, orden y riesgos comunes.
- **Pruebas automáticas**: tests unitarios, integración local con ModSecurity 2 y OWASP CRS, pruebas positivas/negativas, y tests de regresión antes de publicar.
- **Publicador**: genera artefactos inmutables para distribuir por HTTPS; publicación remota opcional y explícita, segura y transaccional, nunca automática en producción por defecto.
- **Administrador multi-servidor**: primero inventario y auditoría en modo lectura; luego despliegue gradual, consulta de versiones, actualización, verificación, rollback y reporte central, preferentemente mediante SSH/Ansible o mecanismo equivalente sin agente propietario.
- **Documentación operativa completa**: instalación, arquitectura, construcción, desarrollo de reglas, integración WHM, observabilidad, incidentes, restauración, actualización, seguridad del pipeline y solución de problemas.

El resultado debe ser instalable y mantenible por el equipo de Hostium sin necesitar Imunify360 ni licencias del ruleset propio.

## 3. Alcance y límites explícitos

### Incluido en la primera versión funcional

1. Proyecto Python 3.11+ moderno, CLI ejecutable, módulos reutilizables y pruebas.
2. Archivos `.conf` SecLang originales, organizados por categoría.
3. Definición estructurada de reglas en manifiestos YAML propios para facilitar auditoría (no reemplazan los `.conf` interpretados por ModSecurity).
4. Validaciones estáticas e integración real cuando se disponga de Docker o Apache+ModSecurity de prueba.
5. Empaquetado compatible con el proveedor externo de WHM.
6. Reportes JSON y Markdown para evidencias.
7. Manual de operación y pasos de verificación en calcium.
8. Estrategia por anillos: laboratorio, piloto, lote, flota.
9. Simulación y rollback, sin modificar productivo por defecto.

### Fuera de alcance de v1, pero documentado como evolución

- Panel web multiusuario completo con login, RBAC y base de datos central.
- Sustituir Imunify360, OWASP CRS o un EDR/antivirus.
- Inventar virtual patches efectivos contra CVE sin una PoC pública/privada autorizada y pruebas reproducibles.
- Análisis antimalware de archivos en disco; ModSecurity inspecciona tráfico HTTP y no sustituye un escáner de filesystem.
- Prometer que reglas cargadas por Apache protegen contenido servido directamente por NGINX/CDN.
- Mecanismos de detección de bots de aprendizaje automático sin datos ni infraestructura disponibles.

Si hay módulos opcionales, que no bloqueen el MVP.

## 4. Arquitectura y stack técnico

Elegí una arquitectura simple y extensible. Recomendación de stack inicial:

- Python 3.11+; `pyproject.toml` con dependencias y entrada de consola `hostium-waf`.
- `Typer` y `Rich` para CLI, `PyYAML` con carga segura para configuración, `pytest` para pruebas y `ruff` para lint; podés proponer alternativas si justificás la decisión.
- Biblioteca estándar `zipfile` y `hashlib` para paquetes reproducibles, MD5/SHA512 según requisitos cPanel; SHA-256 adicional para inventario propio.
- Manifiestos de configuración propios en YAML con esquema explícito, tipos y errores claros.
- Tests de integración mediante contenedores aislados basados en ModSecurity v2/Apache y OWASP CRS, con versiones fijadas, si Docker está disponible. Explorar `go-ftw` para pruebas WAF en formato de casos reproducibles.
- Git para código fuente, Git tags y release notes; pipeline CI compatible con GitHub Actions, mantenible y sin secretos incrustados.
- Para administración de flota: interfaz de transporte abstracta, un backend SSH con autenticación por clave o wrapper de Ansible. Una implementación real mínima de inventario remoto en modo lectura es preferible a un gran framework incompleto.
- Soporte a Linux para los servidores; desarrollo desde Windows o Linux sin requerir cPanel en la máquina del desarrollador.
- Configuración en archivos, parámetros CLI y variables de entorno, sin credenciales hardcodeadas.

Separar claramente **código de proyecto**, **artefactos compilados**, **estado de despliegues** y **logs/reportes**.

## 5. Árbol de directorios obligatorio (adaptable con justificación)

Crear como mínimo esta estructura, con contenido sustancial en los documentos:

```text
hostium-waf-manager/
├── README.md
├── AGENTS.md
├── LICENSE
├── CHANGELOG.md
├── SECURITY.md
├── CONTRIBUTING.md
├── .gitignore
├── .env.example
├── pyproject.toml
├── Makefile
├── config/
│   ├── settings.example.yaml
│   ├── fleet.example.yaml
│   ├── policy.example.yaml
│   └── exclusions.example.yaml
├── rules/
│   ├── README.md
│   ├── manifests/
│   │   └── rules.yaml
│   └── hostium/
│       ├── REQUEST-000-SELFTEST.conf.example
│       ├── REQUEST-100-SENSITIVE-FILES.conf
│       ├── REQUEST-200-WORDPRESS.conf.example
│       ├── REQUEST-300-PHP-RCE.conf.example
│       ├── REQUEST-400-CVE.conf.example
│       └── REQUEST-500-SCANNERS.conf.example
├── src/hostium_waf/
│   ├── __init__.py
│   ├── cli.py
│   ├── settings.py
│   ├── models.py
│   ├── inventory.py
│   ├── validation.py
│   ├── packaging.py
│   ├── metadata.py
│   ├── publishing.py
│   ├── fleet.py
│   ├── deployment.py
│   ├── rollback.py
│   ├── reporting.py
│   └── security.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   ├── ftw/
│   └── expected/
├── scripts/
│   ├── discover-cpanel.sh
│   ├── check-apache-modsec.sh
│   ├── publish-local.sh
│   └── verify-server.sh
├── .github/workflows/
│   ├── ci.yml
│   └── release.yml
├── docs/
│   ├── 00-PLAN-DE-IMPLEMENTACION.md
│   ├── 01-VISION-Y-ALCANCE.md
│   ├── 02-ARQUITECTURA.md
│   ├── 03-REQUERIMIENTOS.md
│   ├── 04-INSTALACION-DESARROLLO.md
│   ├── 05-REGLAS-SECLANG.md
│   ├── 06-CICLO-DE-VIDA-DE-REGLAS.md
│   ├── 07-PAQUETES-CPANEL-WHM.md
│   ├── 08-PUBLICACION-HTTPS.md
│   ├── 09-DESPLIEGUE-CALCIUM.md
│   ├── 10-OPERACION-MULTISERVIDOR.md
│   ├── 11-PRUEBAS-Y-VALIDACION.md
│   ├── 12-OBSERVABILIDAD-Y-LOGS.md
│   ├── 13-FALSOS-POSITIVOS-Y-EXCEPCIONES.md
│   ├── 14-ROLLBACK-Y-RECUPERACION.md
│   ├── 15-SEGURIDAD-Y-MODELO-DE-AMENAZAS.md
│   ├── 16-COMPATIBILIDAD-Y-MATRIZ.md
│   ├── 17-API-CLI-Y-CONFIGURACION.md
│   ├── 18-RUNBOOK-DE-INCIDENTES.md
│   ├── 19-ROADMAP.md
│   ├── 20-GLOSARIO.md
│   ├── ADR/
│   │   └── 0001-proveedor-nativo-whm.md
│   └── REFERENCIAS.md
├── dist/              # generado, no versionado
└── reports/           # generado, no versionado
```

**Cuidado:** los `.conf.example` son ejemplos **no incluidos en paquetes productivos**. El empaquetador solo debe seleccionar módulos expresamente habilitados por manifiesto y política. No actives por defecto protecciones especulativas de WordPress, RCE, CVE ni escáneres.

## 6. Compatibilidad real con el proveedor de cPanel: especificación obligatoria

Implementá de acuerdo con la documentación oficial **Tutorial – Create a ModSecurity Vendor**:

`https://api.docs.cpanel.net/guides/quickstart-development-guide/tutorial-create-a-modsecurity-vendor`

Reglas verificables del artefacto:

- El archivo de metadata se debe llamar `meta_hostium.yaml` y ser accesible mediante HTTPS.
- El nombre corto `vendor_id` es `hostium`, derivado del nombre `meta_hostium.yaml`.
- El ZIP debe extraerse bajo **un único directorio raíz llamado `hostium/`**, no bajo `hostium-1.0.0/`, y contener ahí los archivos `.conf` efectivamente habilitados.
- La metadata YAML debe contener claves **de versiones del motor ModSecurity**, por ejemplo `'2.9.15'`. NO confundas esa clave con la versión del ruleset Hostium.
- Bajo cada versión de motor deben figurar `MD5`, `SHA512`, `distribution` y `url` según el esquema admitido; el ZIP debe terminar en `.zip`.
- `distribution` cambia al publicar una revisión (por ejemplo `hostium-1.0.0`) y debe ser un identificador inmutable, independiente del nombre del directorio ZIP.
- `attributes` debe incluir `name`, `description` y `vendor_url`; `report_url` solo si existe de verdad un receptor válido.
- Compatibilidad con otros motores se declara únicamente tras pruebas por versión. No copiar ciegamente la misma regla a una versión no probada.
- El generador debe permitir versiones múltiples del motor en la metadata, cuando existan paquetes validados para cada una.
- Debe rechazar metadata malformada y ZIP peligrosos (path traversal `../`, rutas absolutas, symlinks no previstos, nombres duplicados, vacíos, rutas fuera de `hostium/`, extensiones inesperadas).

Ejemplo orientativo de YAML **con valores ficticios** que el código deberá generar con hashes reales:

```yaml
---
'2.9.15':
  MD5: '<MD5_REAL_DEL_ZIP>'
  SHA512: '<SHA512_REAL_DEL_ZIP>'
  distribution: 'hostium-1.0.0'
  url: 'https://waf.hostium.com/releases/hostium-1.0.0.zip'
attributes:
  name: 'Hostium WAF Ruleset'
  description: 'Reglas complementarias de seguridad administradas por Hostium'
  vendor_url: 'https://hostium.com'
```

El generador debe publicar SHA512 y MD5 porque forman parte del contrato de cPanel, pero explicar que un checksum descargado junto con metadata no autentica por sí solo al publicador. Evaluá firma **externa al mecanismo nativo de WHM** (por ejemplo cosign/minisign/GPG) y verificación con clave fijada en el pipeline propio; **no afirmes que cPanel valida esa firma**.

Tomá la versión del motor desde inventario, no la del paquete de reglas ni el número de versión de Apache. No inventes la disponibilidad de versiones en repositorios.

## 7. Modelo de reglas y convenciones de seguridad

Definí para cada regla los siguientes atributos en el manifiesto propio:

- `id` numérico único; rango inicial reservado **5500000–5509999**, comprobable contra IDs ya instalados.
- `nombre`, `descripcion`, `categoria`, `modulo`, `archivo`, `version_de_introduccion`, `autor`/`owner`.
- `motivacion`, `tipo_de_ataque`, `referencias` oficiales, `falsos_positivos_probables`.
- `fase`, `variables_inspeccionadas`, `operador`, `transformaciones`, `accion`, `severidad`, `etiquetas`.
- `estado`: borrador, experimental, probado, piloto, producción, retirado.
- `modo_por_defecto`: log-only, detection, deny; explicá cómo se traduce a acciones reales de ModSecurity, sin confundir modo global `SecRuleEngine DetectionOnly` con una regla no disruptiva.
- `casos_de_prueba_positivos`, `casos_de_prueba_negativos`, `impacto_previsto`, `fecha_de_revision`, `ultima_validacion`.
- Excepciones documentadas y registro de cambio.

Convenciones:

1. Nunca duplicar IDs, tampoco en cadenas `chain` o proveedores instalados.
2. Todos los módulos y reglas deben ser legibles, comentados y trazables.
3. Usar `t:none` y transformaciones explícitas según corresponda; justificar excepciones.
4. No crear patrones regex catastróficos o con riesgo de ReDoS; medir rendimiento y límites.
5. No usar patrones amplísimos como bloquear cualquier `POST`, cualquier `base64`, cualquier WordPress REST API, cualquier `admin-ajax.php` o toda petición de user agent desconocido.
6. No introducir reglas `allow` globales que evadan OWASP, salvo justificación explícita y pruebas exhaustivas.
7. No modificar archivos administrados por RPM de OWASP CRS.
8. Usar `msg`, `tag` y `severity` coherentes, sin introducir datos privados en mensajes de log.
9. Las reglas deben funcionar con Apache ModSecurity v2.9.15 en el piloto; compatibilidad con v3/Coraza es futura y requiere validación independiente.
10. No vender una regla simple como una mitigación completa de CVE: cada virtual patch requiere vector de explotación definido, prueba positiva, prueba negativa y limitaciones documentadas.

### Reglas iniciales

Implementá **como regla funcional en el MVP** una protección de acceso a archivos secretos de alto consenso (`/.env`, `/.git/config`, según transformaciones correctas y rutas de prueba), con alcance ajustado, prevención de evasiones evidentes y pruebas negativas para rutas legítimas. Verificá solapamiento con OWASP: el valor aquí es demostrar gobernanza propia, no afirmar que OWASP carecía de protección.

Creá además una regla **de autocomprobación deshabilitada por defecto** (`REQUEST-000-SELFTEST.conf.example`) que responda a un header especial solamente en laboratorio; documentá activación temporal, prueba controlada, observación de `403` e ID exacto, y desactivación posterior. No tratar el header como autenticación y no mantenerla públicamente activa.

Para WordPress, WooCommerce, PHP RCE, escáneres y CVE: generar estructura, especificaciones y tests pendientes **pero no reglas disruptivas productivas sin evidencia**. Las reglas que se vayan habilitando después deben contemplar `wp-login.php`, `xmlrpc.php`, `wp-json`, `admin-ajax.php`, cookies, APIs e integraciones legítimas, con pruebas de casos buenos.

## 8. Reglas de orden y excepciones OWASP (crítico)

Documentá e implementá verificación del orden real de inclusión:

- Las exclusiones **runtime** con acciones `ctl:ruleRemoveById` o `ctl:ruleRemoveTargetById` deben ejecutarse **antes** de la regla CRS a la que afectan.
- Las exclusiones **configure-time** con `SecRuleRemoveById` o `SecRuleUpdateTargetById` deben declararse **después** de que las reglas CRS hayan sido incluidas.
- La ubicación de un proveedor Hostium agregado desde WHM **no garantiza por sí sola** estar antes o después de CRS en todos los escenarios. Comprobar mediante `httpd -t -D DUMP_INCLUDES` y pruebas de efecto.
- Separar en el diseño: **reglas Hostium independientes**, **exclusiones runtime pre-CRS** y **exclusiones configure-time post-CRS**. Las dos últimas pueden requerir un mecanismo de configuración administrado por cPanel aparte del ZIP vendor; no forzarlas a un orden incorrecto.
- Documentar la forma segura de configurar excepciones por dominio/ruta/parámetro para WordPress/WooCommerce, sin apagar OWASP globalmente.
- Exigir justificación y fecha de expiración/revisión para cada excepción.

Referencia obligatoria: `https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/`.

## 9. CLI completa y comportamiento esperado

Proponé e implementá una CLI coherente, documentada y testeada. Como mínimo:

```text
hostium-waf --help
hostium-waf version
hostium-waf init
hostium-waf doctor --local
hostium-waf rules list
hostium-waf rules validate
hostium-waf rules check-ids
hostium-waf package build --version 1.0.0 --engine 2.9.15
hostium-waf package verify --zip dist/hostium-1.0.0.zip --metadata dist/meta_hostium.yaml
hostium-waf metadata show --file dist/meta_hostium.yaml
hostium-waf publish plan --version 1.0.0
hostium-waf fleet list --inventory config/fleet.yaml
hostium-waf fleet audit --inventory config/fleet.yaml --dry-run
hostium-waf deploy plan --ring pilot --version 1.0.0
hostium-waf deploy apply --ring pilot --version 1.0.0 --approve
hostium-waf deploy verify --ring pilot
hostium-waf rollback plan --ring pilot
hostium-waf rollback apply --ring pilot --approve
hostium-waf report generate --format markdown
```

Los subcomandos que todavía no estén implementados completamente deben fallar de forma explícita y segura, no con un éxito ficticio. El MVP debe implementar de verdad: `init`, `version`, `rules list/validate/check-ids`, `package build/verify`, `metadata show`, `doctor --local` y un `fleet audit` de solo lectura con backend SSH probado o acotado a fixtures cuando no exista entorno SSH.

`deploy apply` y `rollback apply` son capacidades posteriores que solo se habilitan si existe ejecución idempotente, capturas del estado anterior, aprobaciones, verificaciones post-deploy y rollback ensayado. Si no se alcanzan esos requisitos en v1, dejarlos claramente bloqueados y detallados en roadmap; no entregar comandos que parezcan funcionar pero no lo hagan.

La CLI debe tener códigos de salida consistentes, `--json` para automatizaciones, mensajes aptos para captura de evidencia, `--verbose` sin exponer secretos, y `--dry-run` por defecto en operaciones remotas modificadoras.

## 10. Compilación reproducible y releases

Implementá el builder con estas propiedades:

1. Construcción reproducible: mismo contenido y parámetros = mismos bytes de ZIP, timestamps y orden de entradas normalizados, salvo campos explícitos intencionadamente variables.
2. No aceptar archivos inesperados, cambios invisibles o enlaces simbólicos.
3. El ZIP contiene `hostium/` como único directorio raíz y archivos `.conf` permitidos.
4. Los archivos experimentales `.conf.example` jamás se incluyen por accidente.
5. Versión SemVer del **ruleset** separada de versión del **motor**.
6. Generar `meta_hostium.yaml` real y hashes calculados del archivo final. Releer el ZIP para validar.
7. No sobrescribir jamás artefactos de versiones publicadas; fallar si la versión ya existe y difiere.
8. Mantener `releases/` o una estructura equivalente con ZIP versionados y un metadata `latest` controlado por canal.
9. Publicación atómica: subir primero ZIP, verificar, después metadata. Prever fallo a mitad, URL inválida, SHA inconsistente, rollback y caché CDN.
10. Soportar `stable` y `canary` separados por URLs/metadata, ya que el mecanismo cPanel consulta la URL desde la cual se instaló el proveedor. No afirmar que WHM soporte canales nativos; son una convención que implementamos mediante URLs distintas.
11. No exponer un endpoint editable por cuentas cPanel de clientes.
12. Documentar HTTPS/TLS, control de acceso, IP allowlist cuando sea posible, caducidad de certificados, auditoría del servidor de publicación y dependencias externas.

## 11. Administración en WHM / cPanel

Tomar como referencia oficial:

- `https://docs.cpanel.net/whm/security-center/modsecurity-vendors/`
- `https://docs.cpanel.net/whm/scripts/the-modsec_vendor-script/`
- `https://api.docs.cpanel.net/guides/quickstart-development-guide/tutorial-create-a-modsecurity-vendor`

Crear un manual con procedimientos concretos de:

1. Comprobar motor y proveedor actual (`rpm -q`, `httpd -M`, `SecRuleEngine`, inventario de vendors).
2. Verificar `OWASP3` instalado por RPM y `in_use`, sin tratar la descripción de versión como prueba única.
3. Instalar **solo en laboratorio/piloto y con aprobación** nuestro vendor desde URL de metadata: `/usr/local/cpanel/scripts/modsec_vendor add <URL>` o WHM GUI.
4. Listar, habilitar/deshabilitar vendor, habilitar/deshabilitar archivos de configuración, actualizar desde el origen y gestionar updates automáticos.
5. Validar `httpd -t` y `httpd -t -D DUMP_INCLUDES`.
6. Confirmar protección **por dominio** en cPanel/WHM y existencia de reglas en Apache.
7. Ejecutar reload/graceful de Apache de manera controlada cuando corresponda; no asumir que cada operación del vendor recarga automáticamente.
8. Crear smoke tests en sitio autorizado de prueba, revisar HTTP response, ID disparado y Hits List/log de auditoría.
9. Manejar interacción con NGINX/Engintron, CDN, proxy IP real, rutas servidas sin Apache y cache bypass.
10. Rollback por módulo, proveedor y versión, sin dejar OWASP apagado.

**Detalle a verificar:** la documentación de cPanel muestra variantes de grafía de `enable-updates`/`enable_updates`. No adivinar la opción para automatización: verificar ayuda o comportamiento en versión real del script e incluir la variante constatada para el entorno. En general, preferí invocar comandos documentados y probados, nunca construir shell arbitrario con parámetros de usuario.

## 12. Desarrollo y pruebas automatizadas

Preparar al menos estos niveles:

### A. Tests unitarios

- Schema YAML válido/inválido, listas de reglas, tipos, severidades y estados.
- Detección de IDs duplicados, fuera de rango, referencias faltantes, reglas sin pruebas.
- Escapes de rutas en ZIP, symlinks, nombres repetidos, estructura raíz incorrecta.
- Hashes y dist del ZIP; verificación positiva y fallo frente a modificación de bytes.
- Determinismo de build; asegurar ZIP idéntico para entradas idénticas.
- Configuración faltante, URLs no HTTPS, credenciales accidentales, inyección en argumentos.

### B. Tests SecLang/Apache

- Compilación con ModSecurity v2/Apache de pruebas.
- Sintaxis de todas las reglas habilitadas; fallar por `duplicate rule id`, `Invalid command`, regex inválida u orden incorrecto.
- Tests con y sin OWASP CRS para confirmar coexistencia y evitar solapamientos destructivos.
- Medir tiempo de ejecución de reglas sobre solicitudes legítimas y maliciosas de prueba.

### C. Pruebas funcionales HTTP y regresión

- Peticiones claramente maliciosas generadas solo contra contenedores o dominios expresamente autorizados.
- Casos normales: WordPress login legítimo, REST API, `admin-ajax.php`, query strings comunes, WooCommerce carrito/checkout de prueba, cargas multipart autorizadas, API JSON.
- Probar expected status y logs/IDs; un HTTP 403 sin ID observado no es prueba suficiente de una regla concreta.
- Pruebas de selftest con regla habilitada únicamente en lab; deshabilitada en paquete estable.
- Pruebas de error de NGINX/CDN proxy, para no atribuir falsamente bloqueos a Apache.
- Incluir fixtures en `tests/ftw/` o un formato equivalente; usar `go-ftw` cuando sea práctico.

### D. CI

- Lint, types (si se introduce mypy), pytest, verificación de ZIP y esquemas.
- Tests de integración contenedorizados cuando el runner lo permita; fijar versiones de imágenes o digests.
- Gate de release: no liberar si falla test crítico; revisión humana necesaria para regla nueva con `deny`.
- Generar reporte con números de casos aprobados y fallidos. No inventar porcentajes de cobertura.

## 13. Despliegues, inventario y operación de flota

Diseñar inventario YAML, por ejemplo:

```yaml
servers:
  - name: calcium
    ssh_host: calcium.example.invalid
    ssh_user: root
    ring: pilot
    environment: production
    tags: [cpanel, cloudlinux, apache, possible-nginx]
  - name: node-example
    ssh_host: node.example.invalid
    ssh_user: root
    ring: canary
    environment: staging
    tags: [cpanel, apache]
```

**Nunca interpretar estos hosts de ejemplo como reales.** Leer credenciales exclusivamente de SSH agent, llaves configuradas o secret store; comprobar identidad de host SSH (known_hosts), sin `StrictHostKeyChecking=no` por defecto.

`fleet audit` debe poder reunir en modo lectura:

- Hostname, SO/CloudLinux, fecha y versión de cPanel, Apache, versión motor ModSecurity y RPM OWASP.
- Vendors instalados, `enabled`, `in_use`, `update`, paths y origen.
- ModSecurity habilitado globalmente y estado por dominio cuando se pueda consultar de manera segura.
- `httpd -t` y mapa de includes.
- Presencia/versión de Hostium WAF en WHM.
- Detección de NGINX/Engintron/CDN cuando se pueda comprobar; indicar si es inferencia.
- Última ejecución con evidencia y fallos de conectividad, sin alterar configuración.

Diseñar despliegue por anillos: `lab` → `pilot` → `canary` → `production`. No promover con fallos ni sin aprobación humana. Cada operación debe producir reporte por servidor y registro de auditoría con actor, fecha, commit Git, versión, hashes, acciones, exit status y decisión de rollback.

Mantener **dos vías de rollback** diferenciadas: deshabilitar módulo/vendor (medida rápida) y restaurar ZIP/metadata de release anterior (recuperación versionada). Rehabilitar el mismo proveedor después de un rollback debe tener pruebas de no reintroducir inmediatamente la versión problemática mediante auto-update.

## 14. Observabilidad, privacidad y falsos positivos

Crear un diseño implementable de extracción y normalización de eventos con:

- Host, timestamp, dominio, ID de regla, categoría, acción, status HTTP, request ID, versión del ruleset, fuente (OWASP/Hostium) y, cuando proceda, IP real verificada.
- Métricas de hits y bloqueos por servidor, dominio y versión; comparación antes/después de un release.
- Integración futura con Prometheus/Grafana/Alertmanager y/o Zabbix, sin requerirlas en v1.
- Umbrales de alerta por disparo inusual o incremento brusco de 403 después del despliegue.
- Retención definida, control de acceso y minimización de datos.

**Los logs de ModSecurity pueden incluir URLs, cookies, credenciales, datos personales y cuerpos de requests.** No copies cuerpos completos al repositorio ni a reportes por defecto. Proponé campos redactados/anonimizados y logs de auditoría protegidos. Nunca subas logs reales a Git ni a CI pública.

Crear manual detallado de falsos positivos: clasificación, reproducción segura, ID, dominio/ruta/parámetro exacto, motivo de excepción, fase de la regla, antes/después de CRS, owner, ticket, vencimiento, pruebas negativas, despliegue y medición posterior. Evitar deshabilitar todas las reglas por un falso positivo puntual.

## 15. Documentación: criterio de calidad obligatorio

Toda la documentación debe ser **en español, operativa y exhaustiva**, no índices vacíos. Cada archivo `docs/*.md` relevante debe incluir, según corresponda:

1. Objetivo, audiencia, prerequisitos y alcance.
2. Diagrama Mermaid cuando aporte claridad, con flujo de datos y límites de confianza.
3. Pasos numerados reproducibles; comandos completos con aclaración `solo lectura`, `modifica archivos`, `reinicia servicio` o `producción`.
4. Ejemplos de entrada/salida esperada sin fingir capturas reales.
5. Qué sucede internamente, por qué se hace así, riesgos, falsos positivos, casos límite.
6. Criterios de verificación, evidencias, señales de éxito/fallo.
7. Procedimiento de deshacer cambios y recuperar.
8. Troubleshooting con síntomas y diagnóstico.
9. Referencias externas oficiales, versiones y fecha de consulta.
10. Historial de decisiones y una sección de limitaciones conocidas.

Contenido mínimo por documento:

- `README.md`: descripción, quickstart, requisitos, estructura, demos seguras, comandos CLI, estado real, enlaces a docs.
- `AGENTS.md`: instrucciones para futuras sesiones de Cursor/AI; convenciones, definición de terminado, qué no tocar y cómo extender reglas sin romper releases.
- `00`: plan por fases con entregables y riesgos.
- `01`: problema, objetivos, no objetivos, escenarios Hostium.
- `02`: arquitectura, límites de confianza, flujos y decisiones.
- `03`: requisitos funcionales/no funcionales, prioridades, trazabilidad.
- `04`: instalación de desarrollo desde cero en Windows/Linux, Python, dependencias y Docker opcional.
- `05`: guía SecLang (variables, fases, acciones, transformaciones, `chain`, IDs, regex, logs) y ejemplos comentados.
- `06`: ciclo de vida del cambio, pull request, revisión, aprobación y release.
- `07`: especificación cPanel ZIP/YAML, casos positivos/negativos, `vendor_id`, versiones motor.
- `08`: HTTPS, canal stable/canary, hashes, firma opcional, publicación atómica y backups.
- `09`: runbook paso a paso para calcium, con **comandos revisados**, antes/después, logs, tests, rollback y aprobación explícita.
- `10`: flota, inventario, anillos, idempotencia, auditoría y permisos.
- `11`: matriz de pruebas, cómo ejecutarlas y evidencias.
- `12`: logs, métricas, privacidad, alertas y dashboards futuros.
- `13`: tuning de OWASP, exclusiones runtime/configure-time, WordPress/WooCommerce, revisión periódica.
- `14`: rollback inmediato y restauración de releases, escenarios de fallo y RTO estimado solo si medido.
- `15`: amenazas de supply chain, metadata maliciosa, ZIP traversal, MITM, robo de claves, CI comprometido, acceso SSH, secretos.
- `16`: compatibilidad: cPanel, EA4, CloudLinux, Apache, ModSecurity 2.9.x, OWASP CRS 3.3.x, Engintron; CRS4 futuro sin promesas.
- `17`: referencia de CLI, parámetros, configuración, formatos JSON y códigos de salida.
- `18`: incidentes, falsos positivos masivos, nuevo exploit, publisher caído, rollback de emergencia.
- `19`: roadmap con P0/P1/P2 y criterios de promoción.
- `20`: glosario para personal de soporte.
- `ADR`: razones para usar vendor nativo de cPanel, en vez de editar reglas OWASP o un plugin WHM.
- `REFERENCIAS`: URLs oficiales, especificaciones, licencias, date checked.
- `SECURITY.md`: divulgación responsable, tratamiento de hallazgos, versiones soportadas y manejo de credenciales.

Si un paso exige infraestructura no disponible (por ejemplo `waf.hostium.com`, clave SSH o cPanel), dejá instrucciones completas y valores `.example` **sin hacer creer que ya fueron provisionados**.

## 16. Plan de ejecución obligatorio para vos (Cursor)

### Fase 1 — Diseño, fuentes y contratos

- Inspeccioná el repositorio.
- Consultá documentación oficial de cPanel/ModSecurity/CRS y registrá hechos verificados.
- Escribí arquitectura, requisitos, ADR y árbol de proyecto.
- Definí contrato real para metadata cPanel, ZIP y reglas SecLang.

### Fase 2 — MVP ejecutable y verificable

- Inicializá paquete Python, CLI, config y validadores.
- Implementá build reproducible, hashes y verificación.
- Agregá una regla original de archivos sensibles con tests y un selftest de laboratorio excluido de producción.
- Implementá `pytest` y CI mínimo.
- Ejemplificá generación de `meta_hostium.yaml` y ZIP correctos mediante comandos que funcionen.

### Fase 3 — Integración y QA

- Tests reales con contenedor WAF, si el entorno lo permite.
- Pruebas positivas/negativas, compatibilidad con OWASP, verificación de includes.
- Analizá posibles falsos positivos y performance.
- Corregí y repetí la suite; registrá limitaciones.

### Fase 4 — Operación, flota y documentación

- Agregá inventario read-only y plan de despliegue.
- Manuales cPanel, publicaciones, seguimiento y rollback.
- No implementes escrituras SSH inseguras o simuladas.
- Dejá completo `AGENTS.md` para las próximas iteraciones.

### Fase 5 — Auditoría y cierre

- Revisá que no haya credenciales, URLs productivas inventadas, ejemplos disfrazados de producción, IDs duplicados ni código muerto crítico.
- Corré todas las pruebas disponibles y reportá éxitos/fallos reales.
- Indicá exactamente qué requiere validación en un cPanel real.
- Entregá informe final de archivos creados, comandos para reproducir el build, evidencias, limitaciones y siguientes pasos.

**No te detengas simplemente porque completaste una fase documental.** Avanzá lo máximo posible dentro del entorno sin tocar servidores productivos.

## 17. Criterios de aceptación del MVP

La versión 1.0.0 no se considera terminada hasta que:

- [ ] Existe un proyecto instalable con `pyproject.toml` y una CLI que funciona.
- [ ] La documentación contiene comandos utilizables, especificación técnica y rollback.
- [ ] Una regla original sensible está implementada y tiene tests positivos y negativos.
- [ ] El selftest es opt-in y está fuera del ZIP estable.
- [ ] Todas las reglas incluidas tienen IDs únicos y manifiesto válido.
- [ ] Se puede construir dos veces un ZIP idéntico y verificar SHA512/MD5 contra metadata.
- [ ] El ZIP tiene una única raíz `hostium/` y metadata `meta_hostium.yaml` compatible con cPanel.
- [ ] El `distribution` cambia por release; no se reutilizan versiones con contenido distinto.
- [ ] El validador detecta ZIP maliciosos, rutas incorrectas, hashes inválidos y metadata malformada.
- [ ] CI local o runner ejecuta tests, lint y validaciones de packaging.
- [ ] Hay un runbook de instalación en calcium, pero NO se instaló ni modificó ese servidor sin aprobación posterior.
- [ ] El diseño mantiene OWASP CRS independiente, con excepciones correctamente ordenadas.
- [ ] Se diferencia evidencia de sintaxis de evidencia de protección real.
- [ ] No se copiaron reglas privativas ni secretos.
- [ ] Hay un README útil y `AGENTS.md` listo para continuar el proyecto.

## 18. Fuentes oficiales iniciales: verificarlas antes de codificar

1. cPanel, creación de proveedor propio: https://api.docs.cpanel.net/guides/quickstart-development-guide/tutorial-create-a-modsecurity-vendor
2. cPanel, administración de vendors: https://docs.cpanel.net/whm/security-center/modsecurity-vendors/
3. cPanel, script `modsec_vendor`: https://docs.cpanel.net/whm/scripts/the-modsec_vendor-script/
4. cPanel, herramientas y hits: https://docs.cpanel.net/whm/security-center/modsecurity-tools/
5. cPanel, activación por dominio: https://docs.cpanel.net/cpanel/security/modsecurity/
6. CRS, excepciones y orden: https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/
7. CRS, documentación general y licencia: https://coreruleset.org/docs/
8. ModSecurity, manual: https://modsecurity.org/docs/
9. ModSecurity, herramientas de testing (`go-ftw`): https://modsecurity.org/docs/7-development/7-3-tools/index.html

Anotá si alguna fuente cambió desde el 23/10/2026, y priorizá el comportamiento que se pueda comprobar sobre un entorno real antes que asumir compatibilidad.

## 19. Forma de mostrarme el trabajo

En tu respuesta final dentro de Cursor, reportá:

1. Qué fases completaste realmente y qué quedó pendiente.
2. Árbol de archivos reales creados.
3. Comandos exactos para preparar entorno, correr tests, construir/verificar ZIP y generar YAML.
4. Salida resumida de tests **realmente ejecutados**.
5. Cómo instalar en un laboratorio cPanel o piloto autorizado (sin instalarlo vos).
6. Qué hacer para actualizar a v1.0.1 y cómo revertirla.
7. Riesgos remanentes y qué datos del servidor necesitarías para validar con seguridad.

**Orden final:** construí una primera versión técnicamente correcta, probada, operable y muy bien documentada de **Hostium WAF Manager**. Prefiero un MVP pequeño y real a una suite grande con comandos que no funcionan. Empezá ahora revisando el repositorio y generando `docs/00-PLAN-DE-IMPLEMENTACION.md`, y continuá con la implementación completa sin detenerte en entregas de texto solamente.
