import sys
import argparse
import platform
from PyKCS11 import *
from asn1crypto import x509

# 1. Configuración de la ruta del módulo OpenSC según el sistema operativo
def get_pkcs11_module_path():
    os_name = platform.system()
    if os_name == "Windows":
        return r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
    elif os_name == "Darwin": # macOS
        return "/usr/local/lib/opensc-pkcs11.so" # o la ruta de brew
    else: # Linux
        return "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"

# ==========================================
# COMANDO: notary info
# ==========================================
def cmd_info(args):
    print("[*] Iniciando notary info...")
    pkcs11 = PyKCS11Lib()
    
    try:
        pkcs11.load(get_pkcs11_module_path())
    except Exception as e:
        print(f"[-] Error cargando el módulo OpenSC: {e}")
        sys.exit(1)

    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        print("[-] No se ha detectado ningún lector con tarjeta insertada.")
        sys.exit(1)

    for slot in slots:
        token_info = pkcs11.getTokenInfo(slot)
        print(f"\n[+] Lector detectado en el slot {slot}")
        print(f"    Token: {token_info.label.strip()}")
        
        # Comprobar el estado del PIN (Prevenir bloqueos)
        flags = token_info.flags
        if flags & CKF_USER_PIN_FINAL_TRY:
            print("    [!] ADVERTENCIA: Último intento del PIN. Si fallas, la tarjeta se bloqueará.")
        elif flags & CKF_USER_PIN_LOCKED:
            print("    [!] ERROR: El PIN está bloqueado.")
        else:
            print("    Estado del PIN: OK")

        # Abrir sesión pública (no requiere PIN) para leer los certificados
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION)
        
        # Buscar objetos de tipo Certificado
        certs = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
        print(f"\n    Certificados encontrados: {len(certs)}")
        
        for idx, cert_obj in enumerate(certs):
            # Extraer los atributos: Etiqueta y Valor (los bytes en DER del certificado)
            attributes = session.getAttributeValue(cert_obj, [CKA_LABEL, CKA_VALUE])
            label = attributes[0]
            cert_der = bytes(attributes[1])
            
            # Usar asn1crypto para decodificar la información del certificado
            cert = x509.Certificate.load(cert_der)
            
            print(f"\n    --- Certificado {idx + 1}: {label} ---")
            print(f"    Sujeto: {cert.subject.human_friendly}")
            print(f"    Emisor: {cert.issuer.human_friendly}")
            print(f"    Válido desde: {cert.not_valid_before}")
            print(f"    Válido hasta: {cert.not_valid_after}")
            
            # Extraer el uso de la clave (Key Usage)
            key_usage_ext = cert.key_usage_value
            if key_usage_ext:
                print(f"    Uso de la clave: {', '.join(list(key_usage_ext.native))}")

        session.closeSession()

# ==========================================
# COMANDO: notary sign (Esqueleto)
# ==========================================
def cmd_sign(args):
    print(f"[*] Preparando para firmar el archivo: {args.file}")
    # TODO: Leer el documento, calcular hash, pedir PIN con getpass
    # TODO: Firmar con la tarjeta, solicitar Timestamp (RFC 3161)
    # TODO: Construir y guardar el archivo CAdES-T (.csig)

# ==========================================
# COMANDO: notary verify (Esqueleto)
# ==========================================
def cmd_verify(args):
    print(f"[*] Preparando para verificar la prueba: {args.proof}")
    # TODO: Leer el archivo .csig usando asn1crypto.cms
    # TODO: Extraer tokens de tiempo, validar cadena OCSP y fechas de expiración

# ==========================================
# MENÚ PRINCIPAL (Argparse)
# ==========================================
def main():
    parser = argparse.ArgumentParser(description="Notary: Herramienta de firma y verificación con DNIe")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando 'info'
    parser_info = subparsers.add_parser("info", help="Muestra información de la tarjeta y certificados")

    # Subcomando 'sign'
    parser_sign = subparsers.add_parser("sign", help="Firma un documento PDF")
    parser_sign.add_argument("file", help="Archivo a firmar")
    parser_sign.add_argument("--format", default="detached", choices=["detached", "attached"], help="Formato de la firma")
    parser_sign.add_argument("-tsa", action="append", help="URL de la Autoridad de Sellado de Tiempo")
    parser_sign.add_argument("-out", help="Archivo de salida (.csig)")

    # Subcomando 'verify'
    parser_verify = subparsers.add_parser("verify", help="Verifica un archivo de firma .csig")
    parser_verify.add_argument("proof", help="Archivo de firma a verificar (.csig)")
    parser_verify.add_argument("--content", help="Documento original (si la firma es detached)")
    parser_verify.add_argument("--trust", action="append", help="Archivos de certificados de confianza")
    parser_verify.add_argument("--at", help="Fecha de evaluación (YYYY-MM-DD)")

    args = parser.parse_args()

    if args.command == "info":
        cmd_info(args)
    elif args.command == "sign":
        cmd_sign(args)
    elif args.command == "verify":
        cmd_verify(args)

if __name__ == "__main__":
    main()