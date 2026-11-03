# Notary - Herramienta de Firma CAdES con DNIe

**Notary** es una herramienta de línea de comandos (CLI) desarrollada en Python para la creación y verificación de firmas digitales CAdES-T utilizando tarjetas inteligentes PKCS#11 (como el DNIe español) o claves por software (`.pem`).

El proyecto cumple estrictamente con las reglas de seguridad, garantizando que el PIN se gestiona de forma segura y que la clave privada nunca abandona la tarjeta inteligente.

---

## 1. Instalación y Configuración

El proyecto debe ejecutarse dentro de un entorno virtual para aislar las dependencias (como `PyKCS11`, `asn1crypto` y `cryptography`).

### Requisito previo
Debes tener instalado Python 3.x y el middleware **OpenSC** en tu sistema operativo para poder interactuar con el lector de tarjetas.

### Instrucciones por Sistema Operativo

#### Windows
1. Clona o descarga el repositorio y abre una terminal en la carpeta del proyecto.
2. Crea el entorno virtual: `python -m venv venv`
3. Activa el entorno: `.venv\Scripts\activate`
4. Instala las dependencias: `pip install -r requirements.txt`

#### macOS
1. Clona o descarga el repositorio y abre un terminal en la carpeta del proyecto.
2. Crea el entorno virtual: `python3 -m venv venv`
3. Activa el entorno: `source.venv/bin/activate`
4. Instala las dependencias: `pip install -r requirements.txt`
*(Nota: Asegúrate de tener instalado OpenSC, por ejemplo, vía Homebrew: `brew install opensc`)*.

#### Linux
1. Clona o descarga el repositorio y abre una terminal en la carpeta del proyecto.
2. Crea el entorno virtual: `python3 -m venv venv`
3. Activa el entorno: `source.venv/bin/activate`
4. Instala las dependencias: `pip install -r requirements.txt`
*(Nota: Instala OpenSC si no lo tienes: `sudo apt-get install opensc`)*.

---

## 2. Uso y Comandos

Asegúrate de tener el entorno virtual activado antes de ejecutar los comandos.

### `info`
Muestra información sobre el lector de tarjetas, el token insertado (DNIe) y lista los certificados públicos disponibles en la tarjeta. También informa sobre el estado de seguridad del PIN (previene bloqueos).
```bash
python notary.py info
```

### `sign`
Genera una firma CAdES-T (con sello de tiempo) para un archivo.
*   **Firma con DNIe (Por defecto):**
    ```bash
    python notary.py sign documento.pdf -out firma.csig
    ```
*   **Firma por Software (Para desarrollo):**
    ```bash
    python notary.py sign documento.pdf --key mi_clave.pem --cert mi_cert.pem -out firma.csig
    ```
*   **Firma Attached (Documento inyectado en la firma):**
    ```bash
    python notary.py sign documento.pdf --format attached -out firma.csig
    ```
*   **Añadir evidencia LTV (Validación a largo plazo):**
    ```bash
    python notary.py sign documento.pdf --trust ca_raiz.pem -out firma.csig
    ```
*   **Firma con TSA concreta**
    ```bash
    python notary.py sign documento.pdf -tsa http://tss.accv.es:8318/tsa -out firma.csig
    ```

### `verify`
Verifica matemática y criptográficamente un archivo de firma `.csig`. Evalúa el hash del documento, la firma RSA, el sello de tiempo (TSA), la caducidad y la cadena de confianza.
*   **Verificar firma Detached (Requiere el documento original):**
    ```bash
    python notary.py verify firma.csig --content documento.pdf --trust ca_raiz.pem
    ```
*   **Verificar firma Attached:**
    ```bash
    python notary.py verify firma.csig --trust ca_raiz.pem
    ```
*   **Verificar validez en una fecha específica:**
    ```bash
    python notary.py verify firma.csig --content documento.pdf --trust ca_raiz.pem --at 2024-05-10
    ```
    