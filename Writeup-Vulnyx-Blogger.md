# VulNyx — Blogger | Writeup
> Laboratorio de pentesting en un entorno controlado. Este documento describe únicamente las pruebas realizadas sobre la máquina **Blogger** de VulNyx.

## Información del laboratorio

<img width="553" height="305" alt="image" src="https://github.com/user-attachments/assets/d5374301-922c-4823-8377-d2f696f38dad" />

| Característica | Valor |
|---|---|
| Plataforma | VulNyx |
| Máquina | Blogger |
| Objetivo | `192.168.0.12` |
| Atacante | `192.168.0.13` (Kali Linux) |
| Dominio virtual | `megablog.nyx` |
| Aplicación | WordPress 6.3 |
| Herramientas | Nmap, Gobuster, WPScan, curl, Hydra, RockYou, Netcat |

## Resumen

La máquina exponía SSH y un servidor Apache con una instalación de WordPress. Mediante enumeración se identificó el usuario `peter`. Posteriormente, un ataque de diccionario con **Hydra y RockYou completo** permitió obtener su contraseña y acceder al panel de administración de WordPress.

Desde el panel se instaló un plugin PHP que permitió obtener una reverse shell. Durante la enumeración local se inspeccionó `wp-config.php`, donde se encontraron credenciales de base de datos cuya contraseña también funcionaba para la cuenta `root`. La reutilización de credenciales permitió completar la escalada de privilegios.

## 1. Descubrimiento de hosts (Host Discovery)

El trabajo comenzó desde Kali Linux, antes de conocer qué servicios ofrecía la máquina Blogger. Primero se identificaron los equipos accesibles en la red local del laboratorio y se determinó cuál correspondía a la máquina objetivo.

**Red del laboratorio:** el atacante utilizaba `192.168.0.13` y el objetivo identificado fue `192.168.0.12`.

### 1.1 Identificación de la red del atacante

El primer paso consistió en revisar la configuración de red de Kali para conocer la interfaz y el segmento IP. Un comando habitual para documentar esta etapa es:

```bash
ip -br a
ip route
```
<img width="558" height="64" alt="image" src="https://github.com/user-attachments/assets/61f94210-6208-4556-b54c-d33424df0153" />
<img width="541" height="48" alt="image" src="https://github.com/user-attachments/assets/20e407fa-aaf8-4512-9eac-379f95a93aeb" />


### 1.2 Descubrimiento de equipos activos

Se realizó una búsqueda de hosts activos para identificar la máquina vulnerable antes de comenzar el escaneo de servicios.

```bash
# Ejemplo reproducible para una red /24; verificar la subred real
sudo nmap -sn 192.168.0.0/24
```
<img width="469" height="439" alt="image" src="https://github.com/user-attachments/assets/bc5bfc1b-6bb6-40b8-bcdb-8b61c8233828" />
<img width="775" height="201" alt="image" src="https://github.com/user-attachments/assets/1a731858-6d61-433e-9db4-5c15248616dc" />
<img width="452" height="153" alt="image" src="https://github.com/user-attachments/assets/883ea563-7682-4eca-b700-2a198db4de5c" />


### 1.3 Identificación del objetivo

Después de contrastar los equipos encontrados con la configuración del laboratorio, se estableció `192.168.0.12` como objetivo y `192.168.0.13` como equipo atacante.

<img width="772" height="437" alt="image" src="https://github.com/user-attachments/assets/dd51926c-5dd5-4ac6-b6fe-ea2f68cebc40" />


## 2. Escaneo de puertos y detección de servicios

Una vez identificado el host, se realizó el reconocimiento de puertos TCP y la detección de versiones con Nmap.

### 2.1 Escaneo de puertos

Se identificaron los servicios expuestos en `192.168.0.12`. La salida disponible confirma los puertos **22/TCP** y **80/TCP**.
<img width="606" height="178" alt="image" src="https://github.com/user-attachments/assets/0b176c04-0978-4fec-a348-f4b8d2f80b55" />

### 2.2 Identificación de servicios y versiones

```bash
nmap -sV -p 22,80 192.168.0.12
```
<img width="763" height="212" alt="image" src="https://github.com/user-attachments/assets/fa624083-2884-4d34-b0cf-2eb270ddb383" />

Servicios identificados:

```text
22/tcp  open  ssh   OpenSSH 8.4p1 Debian
80/tcp  open  http  Apache httpd 2.4.56
```

### 2.3 Interpretación de los resultados

- **22/TCP — SSH:** servicio de administración remota que puede requerir enumeración posterior.
- **80/TCP — HTTP:** servidor Apache que ofrece una superficie de ataque web.

No se atribuyó una vulnerabilidad explotable a OpenSSH o Apache únicamente por sus números de versión.

### 2.4 Identificación de la aplicación y del dominio virtual

El servicio HTTP alojaba una instalación de WordPress bajo `/wordpress/`. Durante la navegación se observó que la aplicación utilizaba el dominio `megablog.nyx`. Para resolverlo se agregó al archivo `/etc/hosts` de Kali:

```text
192.168.0.12 megablog.nyx
```

URL de la aplicación: `http://megablog.nyx/wordpress/`.
<img width="632" height="343" alt="image" src="https://github.com/user-attachments/assets/9726e98a-55ea-4970-bff8-1b7b2f74d8d1" />

<img width="710" height="456" alt="image" src="https://github.com/user-attachments/assets/e600caa5-6e20-4849-b635-990ff4a609ca" />

**02 - Aplicación web.** Navegador mostrando la página inicial de WordPress y el dominio `megablog.nyx`.

**03 - Resolución del dominio (opcional).** Entrada de `megablog.nyx` en `/etc/hosts`, sin otros datos innecesarios.

<img width="447" height="132" alt="image" src="https://github.com/user-attachments/assets/91017f73-f339-4a2d-ba41-c2ddb334fade" />

## 3. Enumeración web y WordPress

### 3.1 Enumeración de directorios y rutas con Gobuster

Se investigaron las rutas accesibles desde el servicio HTTP. Entre las rutas relevantes examinadas estuvieron:

```text
/wordpress/wp-admin/
/wordpress/wp-login.php
/wordpress/wp-content/
/wordpress/wp-includes/
/wordpress/xmlrpc.php
```

> Estas son rutas identificadas o investigadas durante el laboratorio; no se atribuye cada una exclusivamente a Gobuster sin la salida original.

**Comando de referencia:**

```bash
gobuster dir -u http://megablog.nyx/wordpress/ \
  -w /usr/share/wordlists/dirb/common.txt -x php
```

> Verificar el diccionario y los parámetros exactos utilizados en tus notas.

### 3.2 Enumeración de versiones, tema y usuarios con WPScan

Se utilizaron Gobuster, WPScan y peticiones HTTP para investigar rutas, versiones y usuarios.

```bash
wpscan --url http://megablog.nyx/wordpress/ -e u1-10
```
<img width="832" height="218" alt="image" src="https://github.com/user-attachments/assets/7cd31b21-5a43-4919-b078-0f24dc8c95ac" />
<img width="487" height="418" alt="image" src="https://github.com/user-attachments/assets/0e92591e-70b2-4308-9dd3-58e224390c90" />




Resultados relevantes:

- **WordPress:** versión 6.3.
- **Tema:** Twenty Twenty-One 1.9.
- **Usuario identificado:** `peter` (Peter Miller).
- **Panel de autenticación:** `/wordpress/wp-login.php`.
- **Endpoint XML-RPC:** `/wordpress/xmlrpc.php`.

### 3.3 Validación del usuario mediante peticiones HTTP

Antes de realizar fuerza bruta al usuario `peter`, se confirmó su existencia y  se verificó mediante el comportamiento del formulario de inicio de sesión: WordPress devolvía un mensaje de contraseña incorrecta para ese nombre de usuario.
El análisis de las respuestas con `curl` permitió diferenciar un nombre de usuario existente de uno inexistente. En las pruebas se observó también el papel de la cookie `wordpress_test_cookie` en el formulario de login.

### 3.4 Comprobación de API REST y registro de usuarios

Se comprobó el endpoint REST de WordPress:

```text
/wordpress/index.php?rest_route=/wp/v2/users
```

También se comprobó que el registro público de cuentas estaba deshabilitado.
<img width="611" height="102" alt="image" src="https://github.com/user-attachments/assets/76e96970-abd1-423b-b494-072d7fdf9231" />
<img width="1070" height="135" alt="image" src="https://github.com/user-attachments/assets/43520cd4-8494-495d-a2b8-c01742f08b80" />


### 3.5 Análisis de la superficie de ataque

La enumeración identificó WordPress 6.3, el tema Twenty Twenty-One 1.9, la cuenta `peter` (Peter Miller), el formulario de autenticación y XML-RPC. Estos hallazgos orientaron las pruebas de credenciales; la mera presencia de XML-RPC no demuestra por sí sola una vulnerabilidad explotable.

<img width="937" height="511" alt="image" src="https://github.com/user-attachments/assets/65b0087e-55bc-467f-91cf-f91ebc63806a" />

**05 - Enumeración con WPScan.** Versión de WordPress y descubrimiento del usuario `peter`.

<img width="832" height="218" alt="image" src="https://github.com/user-attachments/assets/7cd31b21-5a43-4919-b078-0f24dc8c95ac" />

**06 - Confirmación del usuario.** Respuesta de `wp-login.php` al introducir `peter` con una contraseña incorrecta; ocultá cualquier dato sensible.

## 4. Obtención de credenciales

### 4.1 Preparación y pruebas iniciales

Primero se preparó una lista de diez contraseñas y, posteriormente, un diccionario con las primeras 1.000 entradas de RockYou, almacenado como `05-Exploitation/Payloads/rockyou-1000.txt`. Ninguna de estas pruebas reducidas permitió encontrar una contraseña válida.

Durante la preparación del ataque se estudiaron los parámetros del formulario HTTP, la cookie de prueba y las condiciones de éxito o fracaso de Hydra.

<img width="306" height="198" alt="image" src="https://github.com/user-attachments/assets/0775f4b8-9601-4d2b-b0ec-c87a3b6c1af2" />
<img width="1076" height="439" alt="image" src="https://github.com/user-attachments/assets/3b6e94a5-b3c5-45e7-a8d8-8bf570468d64" />
<img width="1069" height="123" alt="image" src="https://github.com/user-attachments/assets/9cb54cdc-fcb5-4708-a3c7-274602fcf633" />

### 4.2 Ataque con el diccionario completo

Después se utilizó **el diccionario RockYou completo con Hydra**, lo que permitió descubrir la contraseña de `peter`.

Ejemplo de la estructura del ataque contra el formulario de WordPress:

```bash
hydra -l peter -P /usr/share/wordlists/rockyou.txt \
  -s 80 -t 40 -W 1 -f \
  megablog.nyx http-post-form \
  '/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&testcookie=1:C=/wordpress/wp-login.php:F=incorrect'
```

**Resultado:** se obtuvo una contraseña válida para el usuario `peter` y se confirmó su funcionamiento al iniciar sesión en WordPress.

> **Nota:** el comando muestra los parámetros utilizados en las pruebas de Hydra. El resultado del ataque con el diccionario completo debe respaldarse con su salida o captura original; no se reproduce aquí una salida de terminal no conservada.



**07 — Prueba inicial sin éxito (opcional).** Hydra finalizando el diccionario reducido de 1.000 contraseñas sin encontrar una válida.

**08 — Contraseña descubierta.** Resultado de Hydra con RockYou completo, mostrando el usuario `peter` y la confirmación del hallazgo. **Censurá la contraseña** antes de publicarla.

<img width="1082" height="216" alt="image" src="https://github.com/user-attachments/assets/b6c6fa93-f117-4f51-9919-27af78c9cbdf" />

## 5. Acceso al panel de administración

Con las credenciales descubiertas se accedió a:

```text
http://megablog.nyx/wordpress/wp-admin/
```
La cuenta tenía permisos para instalar y activar plugins. Esta funcionalidad permitió pasar del acceso a la aplicación web a la ejecución de código PHP en el servidor.


**09 — Acceso administrativo.** Dashboard de WordPress después de iniciar sesión como `peter`.

<img width="1077" height="448" alt="image" src="https://github.com/user-attachments/assets/b416920f-f0d9-4304-9ba9-216e8e162340" />

**10 — Permisos de instalación.** Menú *Plugins* o pantalla *Add New Plugin*, que demuestra la capacidad de instalar extensiones.

## 6. Ejecución de código y reverse shell

### 6.1 Intento inicial: carga directa de PHP

Primero se intentó la instalación de un archivo PHP común, pero WordPress lo rechazó porque esperaba un paquete ZIP de plugin válido (`PCLZIP_ERR_BAD_FORMAT (-10)`).

### 6.2 Creación e instalación de un plugin válido

A continuación, se creó un plugin de prueba con la cabecera requerida por WordPress, se empaquetó en ZIP y se instaló y activó correctamente. Este paso permitió verificar que la cuenta tenía capacidad de instalar código PHP personalizado. Documentación del procedimiento en: https://hacktricks.wiki/es/index.html

### 6.3 Obtención de la reverse shell

La prueba inicial confirmó que era posible instalar y activar código PHP personalizado desde la cuenta comprometida. Posteriormente, se utilizó un plugin PHP para iniciar una conexión inversa hacia Kali.

En el equipo atacante se preparó un listener:

```bash
nc -nlvp 4444
```

El plugin de laboratorio utilizó una conexión TCP hacia `192.168.0.13:4444`. Al ejecutar su funcionalidad desde WordPress, se obtuvo una **reverse shell** en el servidor.

**12 — Plugin instalado.** Confirmación de instalación y activación del plugin ZIP en WordPress.

<img width="913" height="224" alt="image" src="https://github.com/user-attachments/assets/c75e07e4-1538-4dae-9a72-cf8f6d4f020f" />

<img width="643" height="165" alt="image" src="https://github.com/user-attachments/assets/49ccc46e-3d6c-4581-9472-08d7c47a220e" />

**14 — Identidad de la shell (recomendado).** Salida de `whoami` y `id` desde la sesión remota, antes de la escalada.

<img width="493" height="132" alt="image" src="https://github.com/user-attachments/assets/36d5ee41-d9d1-4a88-ab88-411126a7a27a" />

## 7. Enumeración local y escalada de privilegios

Una vez dentro del sistema se investigaron los archivos de configuración de WordPress. Se encontró `wp-config.php`, archivo que contiene, entre otros parámetros, las credenciales usadas por WordPress para conectarse a su base de datos.

Ruta habitual en esta instalación:

```text
/var/www/html/wordpress/wp-config.php
```

Parámetros relevantes (valores ocultos):

```php
define('DB_NAME', '[REDACTED]');
define('DB_USER', '[REDACTED]');
define('DB_PASSWORD', '[REDACTED]');
define('DB_HOST', '[REDACTED]');
```

**Hallazgo clave:** la contraseña encontrada en la configuración de WordPress también era válida para la cuenta privilegiada `root` del sistema operativo.

Se comprobó la reutilización de credenciales mediante:

```bash
su root
```

Tras introducir la contraseña identificada, la autenticación fue exitosa. Se verificó el nivel de privilegios con:

```bash
whoami
id
```

**Resultado:** acceso como `root`.

La escalada se debió a la reutilización de una contraseña sensible entre la configuración de una aplicación y una cuenta privilegiada del sistema.

**15 — Archivo de configuración localizado.** Terminal mostrando la ruta de `wp-config.php` y sus permisos, si conservaste esa evidencia.

**16 — Credenciales de base de datos.** Fragmento de `wp-config.php` con los parámetros `DB_USER` y `DB_PASSWORD`. **Censurá completamente el valor de `DB_PASSWORD`**.

<img width="563" height="159" alt="image" src="https://github.com/user-attachments/assets/403da33a-2516-461e-8695-2f1b93d9f0ce" />

**18 — Privilegios confirmados.** Resultado de `whoami` y `id` con `uid=0(root)`.

## 8. Captura de la flag

Con acceso privilegiado, se buscó y encontró la flag final del laboratorio.

```bash
cd /root
ls -la
```

**Resultado:** flag de `root` obtenida. Se omite su contenido para evitar spoilers.


**19 — Flag final.** Terminal mostrando la ubicación de la flag en `/root`. Podés ocultar el contenido de la flag para evitar spoilers.

<img width="303" height="36" alt="image" src="https://github.com/user-attachments/assets/663a1b1d-04bb-4921-8233-34f2c182c97a" />

## 9. Cadena de ataque

```text
Descubrimiento de hosts → Identificación de 192.168.0.12
         ↓
Nmap → Apache / WordPress
         ↓
WPScan / Gobuster → Usuario peter
         ↓
Hydra + RockYou completo → Contraseña válida
         ↓
WordPress Admin → Instalación de plugin PHP
         ↓
Reverse shell → Acceso al sistema
         ↓
wp-config.php → Credenciales de base de datos
         ↓
Reutilización de contraseña → su root
         ↓
Root → Flag final
```

## 10. Hallazgos y recomendaciones

| Hallazgo | Riesgo | Recomendación |
|---|---|---|
| Contraseña de WordPress susceptible a ataque de diccionario | Acceso no autorizado al CMS | Contraseñas robustas, MFA y controles de intentos de autenticación |
| Cuenta de WordPress con capacidad de instalar plugins | Ejecución de código en el servidor tras comprometer la cuenta | Restringir cuentas administrativas y la instalación de plugins; aplicar mínimo privilegio |
| Credenciales sensibles en `wp-config.php` accesibles durante la postexplotación | Exposición de secretos de aplicación | Restringir permisos de lectura, limitar acceso al servidor y rotar secretos comprometidos |
| Reutilización de la contraseña de base de datos en `root` | Escalada a control total del sistema | Usar contraseñas únicas, fuertes y administradas separadamente para cada servicio y cuenta |
| WordPress 6.3 y PHP 7.4.33 observados en el laboratorio | Riesgos asociados a versiones antiguas | Mantener WordPress, plugins, temas y PHP en versiones soportadas y actualizadas |


## 12. Conclusión

Como conclusión **Blogger** permite practicar una cadena de ataque completa: reconocimiento, enumeración, obtención de credenciales, acceso administrativo a WordPress, ejecución de código mediante plugins, reverse shell y escalada de privilegios.

---

**Aviso:** este documento fue elaborado para una máquina intencionalmente vulnerable en un laboratorio autorizado. Las IP, contraseñas y capturas corresponden al entorno de práctica.
