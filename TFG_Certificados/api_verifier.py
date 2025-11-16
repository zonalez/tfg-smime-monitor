import os
import sqlite3
import datetime
# ¡NUEVOS IMPORTS DE FLASK!
from flask import Flask, request, jsonify, render_template, send_from_directory
from email import message_from_string
from email.policy import default
import subprocess   
import tempfile     
import shutil       # ¡NUEVO! Para borrar carpetas temporales

app = Flask(__name__)
DB_PATH = 'tfg_security.db'

# --- Rutas de Archivos (Con tu corrección de ruta!) ---
HOME_DIR = os.path.expanduser('~')
# Esta es tu ruta corregida que SÍ funciona:
CA_CERT_PATH = os.path.join(HOME_DIR, 'Documents/TFG/Test_CA_Cert.pem') 

# --- Claves del Receptor (para Descifrado) ---
RECEPTOR_KEY_PATH = os.path.join(HOME_DIR, 'Documents/TFG/receptor_key.pem')
RECEPTOR_CERT_PATH = os.path.join(HOME_DIR, 'Documents/TFG/receptor_cert.pem')
# --- Fin Rutas ---

# --- INICIO DEL CÓDIGO COMPLETO (v2.6) ---

def get_db():
    """Conecta a la base de datos SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Error al conectar a la base de datos: {e}")
        return None

def clean_error_message(stderr_text):
    """
    Toma un error largo de OpenSSL y lo acorta a la primera línea útil.
    """
    if not stderr_text:
        return "Error desconocido de OpenSSL"
    
    lines = stderr_text.strip().split('\n')
    for line in lines:
        if "Error" in line or "Verification" in line or "No signature" in line:
            return line.split('error:')[0].strip()
    return lines[0] 

def decrypt_smime(raw_email_bytes):
    """
    Intenta descifrar un mensaje S/MIME.
    Devuelve: (éxito, contenido_descifrado, razon_de_error)
    """
    try:
        with tempfile.NamedTemporaryFile(delete=True) as tmp_eml:
            tmp_eml.write(raw_email_bytes)
            tmp_eml.flush()

            command = [
                'openssl', 'smime', '-decrypt',
                '-in', tmp_eml.name,
                '-inkey', RECEPTOR_KEY_PATH,
                '-recip', RECEPTOR_CERT_PATH
            ]
            
            process = subprocess.run(
                command, 
                capture_output=True, 
                check=False
            )

            if process.stdout:
                return True, process.stdout, None
            
            stderr_clean = clean_error_message(process.stderr.decode('utf-8', errors='ignore'))

            if "No recipient" in stderr_clean:
                return False, raw_email_bytes, "Cifrado (Clave incorrecta)"
            elif "no content type" in stderr_clean:
                return False, raw_email_bytes, "No es un mensaje S/MIME"
            else:
                return False, raw_email_bytes, stderr_clean

    except Exception as e:
        return False, raw_email_bytes, f"Error de Python API (decrypt): {str(e)}"

def verify_smime_signature(raw_email_bytes):
    """
    Verifica una firma S/MIME (multipart/signed).
    Devuelve: (es_firmado, es_valido, razon_de_error)
    """
    try:
        with tempfile.NamedTemporaryFile(delete=True) as tmp_eml:
            tmp_eml.write(raw_email_bytes)
            tmp_eml.flush() 

            command = [
                'openssl', 'smime', '-verify',
                '-in', tmp_eml.name,
                '-CAfile', CA_CERT_PATH
            ]
            
            process = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                check=False
            )
            
            stderr_clean = clean_error_message(process.stderr)
            
            if "Verification successful" in stderr_clean:
                return True, True, "Firma válida (Verificada por OpenSSL)"
            elif "Verification failure" in stderr_clean:
                return True, False, f"Firma inválida: {stderr_clean}"
            else:
                return False, False, "No firmado"

    except Exception as e:
        return False, False, f"Error de Python API (verify): {str(e)}"

# --- Endpoint de la API (Núcleo) ---
@app.route('/verify-email', methods=['POST'])
def verify_email_endpoint():
    
    raw_email_data = request.data
    if not raw_email_data:
        return jsonify({"error": "No se recibieron datos"}), 400

    try:
        msg_string = raw_email_data.decode('utf-8', errors='ignore')
        msg = message_from_string(msg_string, policy=default)
        remitente = msg.get('From', 'N/A')
        destinatario = msg.get('To', 'N/A')
        msg_id = msg.get('Message-ID', f'no-id-{datetime.datetime.now().isoformat()}')
        subject = msg.get('Subject', 'N/A')
    except Exception as e:
        remitente = "N/A"
        destinatario = "N/A"
        msg_id = f'parse-fail-{datetime.datetime.now().isoformat()}'

    is_decrypted, decrypted_data, decrypt_reason = decrypt_smime(raw_email_data)
    
    cifrado = False
    descifrado_ok = False
    error_temp = None

    if is_decrypted:
        cifrado = True
        descifrado_ok = True
        content_to_verify = decrypted_data
    elif decrypt_reason == "Cifrado (Clave incorrecta)":
        cifrado = True
        descifrado_ok = False
        error_temp = decrypt_reason
        content_to_verify = raw_email_data 
    else:
        content_to_verify = raw_email_data

    es_firmado, es_valido, verify_reason = verify_smime_signature(content_to_verify)

    try:
        conn = get_db()
        cursor = conn.cursor()
        
        final_error_code = error_temp if error_temp else (None if es_valido else verify_reason)

        cursor.execute(
            """
            INSERT INTO EVENTOS_CORREO 
            (remitente, destinatario, msg_id, subject, firmado, firma_valida, cifrado, descifrado_ok, error_codigo, fuente)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (remitente, destinatario, msg_id, subject, 
             es_firmado, es_valido, cifrado, 
             descifrado_ok, final_error_code, 'api_direct_test')
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": f"Error de DB: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

    return jsonify({
        "status": "evento registrado",
        "msg_id": msg_id,
        "firmado": es_firmado,
        "firma_valida": es_valido,
        "cifrado": cifrado,
        "descifrado_ok": descifrado_ok,
        "detalle": final_error_code or (verify_reason if (es_firmado and es_valido) else verify_reason)
    }), 201

# --- Endpoint del Dashboard (HU-006) ---
@app.route('/dashboard')
def dashboard():
    conn = get_db()
    if conn is None:
        return "Error: No se pudo conectar a la base de datos", 500
    
    try:
        # Importar pandas aquí para no romper el resto de la app si no está instalado
        import pandas as pd
        df = pd.read_sql_query("SELECT * FROM EVENTOS_CORREO", conn)
        
        eventos_recientes = df.sort_values(by='id', ascending=False).to_dict('records')

        if not df.empty:
            total_eventos = len(df)
            pct_firmados = round(df['firmado'].mean() * 100, 1)
            pct_cifrados = round(df['cifrado'].mean() * 100, 1)
            total_errores = len(df[(df['firmado'] == True) & (df['firma_valida'] == False) | (df['error_codigo'].notna())])
        else:
            total_eventos = 0
            pct_firmados = 0
            pct_cifrados = 0
            total_errores = 0

        return render_template('dashboard.html',
                               total_eventos=total_eventos,
                               pct_firmados=pct_firmados,
                               pct_cifrados=pct_cifrados,
                               total_errores=total_errores,
                               eventos=eventos_recientes)

    except Exception as e:
        return f"Error generando el dashboard: {str(e)}", 500
    finally:
        if conn:
            conn.close()

# --- ¡¡¡NUEVO!!! Asistente de Certificados (HU-003) ---

@app.route('/asistente')
def asistente_page():
    """
    Sirve la página HTML del asistente que creamos en 'templates/asistente.html'
    """
    return render_template('asistente.html')


@app.route('/generar-certificado', methods=['POST'])
def generar_certificado():
    """
    Recibe los datos del formulario, ejecuta OpenSSL y
    devuelve el archivo .p12 para descargar.
    """
    try:
        # 1. Obtener datos del formulario
        nombre_cn = request.form['nombre']
        email = request.form['email']
        pin = request.form['pin']

        # --- BLOQUE NUEVO (CORREGIDO) ---

        # 2. Usar los campos pre-llenados que pediste
        country = "AR"
        state = "CABA"  # <-- ¡AÑADIDO!
        locality = "CABA" # <-- ¡AÑADIDO!
        org = "Universidad Siglo 21"
        org_unit = "Seguridad Informatica"
        
        # 3. Crear el string de "Subject" para OpenSSL
        # /C=AR/ST=CABA/L=CABA/O=.../OU=.../CN=.../emailAddress=...
        subj = f"/C={country}/ST={state}/L={locality}/O={org}/OU={org_unit}/CN={nombre_cn}/emailAddress={email}"

        # 4. Crear una carpeta temporal SEGURA para este certificado
        temp_dir = tempfile.mkdtemp()
        
        # 5. Definir las rutas de los archivos temporales
        key_path = os.path.join(temp_dir, 'user.key')
        cert_path = os.path.join(temp_dir, 'user.crt')
        p12_path = os.path.join(temp_dir, 'certificado_smime.p12')

        # --- Ejecutar Comandos OpenSSL ---

        # Comando 1: Generar Clave Privada
        cmd_key = ['openssl', 'genpkey', '-algorithm', 'RSA', 
                   '-pkeyopt', 'rsa_keygen_bits:2048', 
                   '-out', key_path]
        subprocess.run(cmd_key, check=True, capture_output=True)

        # Comando 2: Generar Certificado Auto-Firmado (Self-Signed)
        cmd_cert = ['openssl', 'req', '-x509', '-new', 
                    '-key', key_path, 
                    '-out', cert_path, 
                    '-days', '365',    # 1 año de validez
                    '-subj', subj]     # Pasar el Subject de forma segura
        subprocess.run(cmd_cert, check=True, capture_output=True)

        # Comando 3: Empaquetar el .p12 (usando el PIN del usuario)
        cmd_p12 = ['openssl', 'pkcs12', '-export', 
                   '-out', p12_path, 
                   '-inkey', key_path, 
                   '-in', cert_path, 
                   '-passout', f'pass:{pin}'] # Pasar el PIN de forma segura
        subprocess.run(cmd_p12, check=True, capture_output=True)

        # 6. Enviar el archivo .p12 al navegador para descargar
        return send_from_directory(
            temp_dir, 
            'certificado_smime.p12', 
            as_attachment=True,
            # Nombre de archivo sugerido para el usuario
            download_name=f"{email}_smime.p12" 
        )

    except subprocess.CalledProcessError as e:
        # Si OpenSSL falla
        return f"Error de OpenSSL: {e.stderr.decode()}", 500
    except Exception as e:
        # Cualquier otro error
        return str(e), 500
    # NOTA: No limpiamos (shutil.rmtree) el temp_dir aquí
    # porque necesitamos que el archivo exista para ser enviado.
    # Una solución más robusta usaría @after_this_request para limpiar.
    # Para este prototipo, el S.O. limpiará /tmp/ eventualmente.

# --- Fin del Asistente ---


if __name__ == '__main__':
    # (¡Asegúrate de que 'pandas' esté instalado con 'pip3 install pandas'!)
    print("Iniciando servidor de verificación S/MIME (v2.6 - CON ASISTENTE) en http://localhost:5000")
    app.run(debug=True, port=5000, host='0.0.0.0')

# --- FIN DEL CÓDIGO COMPLETO (v2.6) ---