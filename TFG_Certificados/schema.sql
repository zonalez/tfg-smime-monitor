/* Tabla para el inventario básico de certificados (Figura 4) */
CREATE TABLE IF NOT EXISTS CERTIFICADOS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sujeto_cn TEXT NOT NULL UNIQUE,
    emisor TEXT NOT NULL,
    serie TEXT NOT NULL UNIQUE,
    vence DATE NOT NULL,
    estado TEXT DEFAULT 'valido',
    email TEXT,
    huella_sha256 TEXT,
    fuente TEXT
);

/* Tabla para los eventos de correo monitoreados (Figura 4) */
CREATE TABLE IF NOT EXISTS EVENTOS_CORREO (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    remitente TEXT,
    destinatario TEXT,
    msg_id TEXT NOT NULL UNIQUE,
    fecha_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
    firmado BOOLEAN DEFAULT 0,
    firma_valida BOOLEAN DEFAULT 0,
    cifrado BOOLEAN DEFAULT 0,
    descifrado_ok BOOLEAN DEFAULT 0,
    error_codigo TEXT,
    fuente TEXT
);
