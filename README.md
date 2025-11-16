  

# Prototipo TFG: Control de Seguridad en Correo Electrónico

## (Emiliano González Luparo - VLSI000745)

  

Este repositorio contiene el prototipo funcional para el Trabajo Final de Grado (TFG) de la Licenciatura en Seguridad Informática (Universidad Siglo 21).

  

El objetivo es demostrar un sistema de **Control De Seguridad En Correo Electrónico Con Cifrado y Monitoreo Automatizado**, implementando S/MIME (firma y cifrado) con un backend de monitoreo, un dashboard de KPIs y un asistente de generación de certificados.

  

---

  

### 🛠️ Stack Tecnológico

*  **API Backend:** Python 3 con Flask

*  **Verificación Criptográfica:** OpenSSL (invocado vía `subprocess` de Python)

*  **Automatización:** n8n (corriendo en Docker)

*  **Base de Datos:** SQLite 3

*  **Dashboard & Frontend:** HTML/CSS, Chart.js y Pandas (para KPIs)

  

---

  

### ⚙️ Instrucciones de Instalación (Entorno de Prueba)

  

Estos pasos recrean el entorno de prueba en una máquina Linux (ej. Kali/Ubuntu).

  

#### 1. Clonar el Repositorio

```bash

git  clone https://github.com/zonalez/tfg-smime-monitor.git

cd  tfg-smime-monitor

  

```

  

#### 2. Preparar el Entorno Python

  

Bash

  

```

# Crear un entorno virtual

python3 -m venv venv

  

# Activar el entorno

source venv/bin/activate

  

# Instalar las bibliotecas (Flask, Pandas, pyOpenSSL)

pip3 install -r requirements.txt

  

```

  

#### 3. Crear la Base de Datos

  

(Nota: El archivo `schema.sql` debe ser creado con la definición de las tablas `CERTIFICADOS` y `EVENTOS_CORREO` ).

  

Bash

  

```

# Crear la base de datos y las tablas base

sqlite3 tfg_security.db < schema.sql

  

# Añadir la columna 'subject' a la tabla EVENTOS_CORREO (necesaria para la v2.7+)

sqlite3 tfg_security.db "ALTER TABLE EVENTOS_CORREO ADD COLUMN subject TEXT"

  

```

  

#### 4. Generar Certificados de Prueba

  

La API necesita una CA y claves de receptor para funcionar. _(Asegúrate de tener `openssl` instalado: `sudo apt install openssl`)_

  

Bash

  

```

# 1. Crear la CA de Prueba

openssl genpkey -algorithm RSA -out Test_CA_Key.pem -aes256 -pkeyopt rsa_keygen_bits:4096

openssl req -x509 -new -nodes -key Test_CA_Key.pem -sha256 -days 1024 -out Test_CA_Cert.pem -subj "/C=AR/O=TFG CA/CN=TFG Test CA"

  

# 2. Crear Certificado del "Receptor" (para la API)

openssl genpkey -algorithm RSA -out receptor_key.pem -pkeyopt rsa_keygen_bits:2048

openssl req -new -key receptor_key.pem -out receptor_csr.pem -subj "/C=AR/CN=API Receptor/emailAddress=api@tfg.test"

openssl x509 -req -in receptor_csr.pem -CA Test_CA_Cert.pem -CAkey Test_CA_Key.pem -CAcreateserial -out receptor_cert.pem -days 365 -sha256

  

```

  

_(Nota: El prototipo `api_verifier.py` espera que estos archivos estén en `~/Documents/TFG/` o la ruta debe ser ajustada en el archivo Python)._

  

#### 5. Iniciar la API Backend

  

Bash

  

```

# (Asegúrate de que 'venv' esté activo)

python3 api_verifier.py

  

```

  

- **Dashboard:** `http://localhost:5000/dashboard`

- **Asistente:** `http://localhost:5000/asistente`

  

#### 6. Iniciar n8n (Motor de Automatización)

  

Bash

  

```

# Crear la carpeta de datos persistentes

mkdir -p ~/n8n_data

  

# Borrar contenedor viejo (si existe) y ejecutar el nuevo en modo 'detached' (-d)

sudo docker rm n8n_tfg

sudo docker run -d -p 5678:5678 --name n8n_tfg -v ~/n8n_data:/home/node/.n8n n8nio/n8n

  

```

  

- **Workflow:** Configurar el workflow de 2 nodos (Webhook -> HTTP Request) como se probó en `http://localhost:5678`.

- **Nodo 1 (Webhook):** `Raw Body` = ON.

- **Nodo 2 (HTTP Request):** `Body Content Type` = `n8n Binary File`, `Input Data Field Name` = `data`.

  

----------

  

### 🧪 Comandos de Prueba (Simulación `curl`)

  

Estos comandos simulan los 3 casos de uso enviados directamente a la API (saltándose n8n).

  

**(¡Asegúrate de que la API esté corriendo en `http://<tu-ip>:5000`!)**

  

Bash

  

```

# TEST A: Correo NO Firmado (Texto Plano)

curl -X POST -H "Content-Type: text/plain" --data "Prueba de correo no firmado" "http://localhost:5000/verify-email"

  

# TEST B: Correo FIRMADO (Necesita 'test_email.eml')

curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@test_email.eml" "http://localhost:5000/verify-email"

  

# TEST C: Correo FIRMADO y CIFRADO (Necesita 'test_cifrado.eml')

curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@test_cifrado.eml" "http://localhost:5000/verify-email"

  

```

  

----------

  

### 🔗 Endpoints del Prototipo

  

- **`POST /verify-email`**: Recibe el correo crudo, lo verifica, lo descifra y lo registra en la DB.

- **`GET /dashboard`**: Muestra el dashboard ejecutivo con KPIs y registros.

- **`GET /asistente`**: Muestra el formulario del asistente para generar certificados S/MIME.

- **`POST /generar-certificado`**: Genera y entrega un archivo `.p12` basado en los datos del formulario.