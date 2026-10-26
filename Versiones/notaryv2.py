import sys
import argparse
import platform
from PyKCS11 import *
from asn1crypto import x509
import getpass
import hashlib
import datetime
from asn1crypto import cms, algos, core, x509
import os
import requests
from asn1crypto import tsp

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
# COMANDO: notary sign (COMPLETO: CAdES-T)
# ==========================================
def cmd_sign(args):
    print(f"[*] Preparando para firmar el archivo: {args.file}")

    # 1. Leer archivo y calcular hash
    try:
        with open(args.file, 'rb') as f:
            document_data = f.read()
    except FileNotFoundError:
        print(f"[-] Error: No se encuentra el archivo {args.file}")
        return

    document_hash = hashlib.sha256(document_data).digest()

    # 2. Conectar a la tarjeta y buscar el CertFirmaDigital
    pkcs11 = PyKCS11Lib()
    pkcs11.load(get_pkcs11_module_path())
    slots = pkcs11.getSlotList(tokenPresent=True)
    
    if not slots:
        print("[-] No hay tarjeta insertada.")
        return

    session = pkcs11.openSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
    certs = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
    cert_der, cert_id, cert_x509 = None, None, None
    
    for c in certs:
        attrs = session.getAttributeValue(c, [CKA_VALUE, CKA_ID])
        parsed_cert = x509.Certificate.load(bytes(attrs[0]))
        if parsed_cert.key_usage_value and 'non_repudiation' in parsed_cert.key_usage_value.native:
            cert_der = bytes(attrs[0])
            cert_id = attrs[1]
            cert_x509 = parsed_cert
            break
            
    if not cert_der:
        print("[-] No se encontró el Certificado de Firma Digital.")
        return

    # 3. Pedir PIN
    pin = getpass.getpass("    Introduce el PIN de tu DNIe: ")
    try:
        session.login(pin)
    except PyKCS11Error as e:
        print(f"[-] PIN incorrecto: {e}")
        session.closeSession()
        return

    # 4. Preparar SignedAttributes (Incluyendo signingCertificateV2)
    digest_attr = cms.CMSAttribute({'type': 'message_digest', 'values': [document_hash]})
    content_type_attr = cms.CMSAttribute({'type': 'content_type', 'values': ['data']})
    signing_time_attr = cms.CMSAttribute({'type': 'signing_time', 'values': [cms.Time({'utc_time': datetime.datetime.now(datetime.timezone.utc)})]})
    
    # Requisito: signingCertificateV2 (Hash SHA-256 del certificado)
    cert_hash = hashlib.sha256(cert_der).digest()
    
    # Construcción directa mediante diccionarios para evitar errores de clases faltantes
    sign_cert_attr = cms.CMSAttribute({
        'type': 'signing_certificate_v2',
        'values': [{
            'certs': [{
                'hash_algorithm': {'algorithm': 'sha256'},
                'cert_hash': cert_hash
            }]
        }]
    })
    
    # Agrupar, forzar etiqueta SET OF (0x31) y calcular el hash a firmar
    signed_attrs_list = [content_type_attr, digest_attr, signing_time_attr, sign_cert_attr]
    signed_attrs = cms.CMSAttributes(signed_attrs_list)
    set_of_bytes = b'\x31' + signed_attrs.dump()[1:]
    attrs_hash = hashlib.sha256(set_of_bytes).digest()

    # 5. FIRMAR con la tarjeta
    priv_keys = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, cert_id)])
    mech = Mechanism(CKM_SHA256_RSA_PKCS, None)
    signature_bytes = bytes(session.sign(priv_keys[0], set_of_bytes, mech))
    
    session.logout()
    session.closeSession()
    print("[+] Atributos firmados con éxito por el DNIe.")

    # 6. Obtener Sello de Tiempo (TSA)
    print("[*] Solicitando sello de tiempo (RFC 3161)...")
    sig_hash = hashlib.sha256(signature_bytes).digest() # Hash de la FIRMA, no del documento
    nonce = int.from_bytes(os.urandom(8), byteorder='big') # Nonce aleatorio
    
    tsa_req = tsp.TimeStampReq({
        'version': 1,
        'message_imprint': tsp.MessageImprint({'hash_algorithm': {'algorithm': 'sha256'}, 'hashed_message': sig_hash}),
        'cert_req': True,
        'nonce': nonce
    })
    
    # Usar TSA por defecto o la pasada por argumento
    tsa_urls = args.tsa if args.tsa else ["https://freetsa.org/tsr"]
    tsa_resp_data = None
    
    for url in tsa_urls:
        try:
            res = requests.post(url, data=tsa_req.dump(), headers={'Content-Type': 'application/timestamp-query'})
            if res.status_code == 200:
                tsa_resp_data = res.content
                print(f"[+] Sello de tiempo obtenido de: {url}")
                break
        except Exception as e:
            print(f"[-] Falló la TSA {url}: {e}")
            
    if not tsa_resp_data:
        print("[-] No se pudo obtener el sello de tiempo de ninguna TSA.")
        return

    # Validar respuesta de la TSA
    tst_resp = tsp.TimeStampResp.load(tsa_resp_data)
    if tst_resp['status']['status'].native != 'granted':
        print(f"[-] La TSA rechazó la petición.")
        return
        
    tst_token = tst_resp['time_stamp_token']
    tst_info = tst_token['content']['encap_content_info']['content'].parsed
    if tst_info['nonce'].native != nonce:
        print("[-] ERROR DE SEGURIDAD: El nonce de la TSA no coincide (Posible ataque de repetición).")
        return

    # 7. Construir CAdES-T y guardar en disco
    print("[*] Empaquetando firma en formato CAdES-T (DER)...")
    
    # Atributo no firmado: Sello de tiempo
    tst_attr = cms.CMSAttribute({'type': 'signature_time_stamp_token', 'values': [tst_token]})
    
    # Construir SignerInfo
    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier({'issuer_and_serial_number': cms.IssuerAndSerialNumber({'issuer': cert_x509.issuer, 'serial_number': cert_x509.serial_number})}),
        'digest_algorithm': {'algorithm': 'sha256'},
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signed_attrs': signed_attrs_list,
        'signature': signature_bytes,
        'unsigned_attrs': [tst_attr]
    })
    
    # Construir SignedData
    signed_data = cms.SignedData({
        'version': 'v3',
        'digest_algorithms': [{'algorithm': 'sha256'}],
        'encap_content_info': {'content_type': 'data', 'content': None}, # None indica formato 'detached'
        'certificates': [cert_x509],
        'signer_infos': [signer_info]
    })
    
    # Construir archivo final
    content_info = cms.ContentInfo({'content_type': 'signed_data', 'content': signed_data})
    
    out_file = args.out if args.out else args.file + ".csig"
    with open(out_file, 'wb') as f:
        f.write(content_info.dump())
        
    print(f"[+] ¡ÉXITO! Documento firmado guardado como: {out_file}")

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