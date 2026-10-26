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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_der_x509_certificate
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import serialization

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

    # ==========================================
    # 2. y 3. Cargar Clave y Certificado (Hardware vs Software)
    # ==========================================
    usar_hardware = not (args.key and args.cert)

    if usar_hardware:
        # --- MODO HARDWARE (DNIe) ---
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
            print("[-] No se encontró el Certificado de Firma Digital en el token.")
            return

        pin = getpass.getpass("    Introduce el PIN de tu DNIe: ")
        try:
            session.login(pin)
        except PyKCS11Error as e:
            print(f"[-] PIN incorrecto: {e}")
            session.closeSession()
            return
    else:
        # --- MODO SOFTWARE (.pem) ---
        print("[*] Usando firma por software (ficheros PEM)...")
        try:
            with open(args.cert, 'rb') as f:
                # Cargar el certificado con cryptography y exportarlo a DER para asn1crypto
                cert_crypto = load_pem_x509_certificate(f.read())
                cert_der = cert_crypto.public_bytes(serialization.Encoding.DER)
                cert_x509 = x509.Certificate.load(cert_der)
                
            with open(args.key, 'rb') as f:
                # Cargar la clave privada
                private_key = serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            print(f"[-] Error cargando la clave o certificado por software: {e}")
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

    # ==========================================
    # 5. FIRMAR (Hardware vs Software)
    # ==========================================
    if usar_hardware:
        priv_keys = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, cert_id)])
        mech = Mechanism(CKM_SHA256_RSA_PKCS, None)
        signature_bytes = bytes(session.sign(priv_keys[0], set_of_bytes, mech))
        
        session.logout()
        session.closeSession()
        print("[+] Atributos firmados con éxito por el DNIe.")
    else:
        signature_bytes = private_key.sign(
            set_of_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("[+] Atributos firmados con éxito por software.") 

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
    
    # Evaluar si es attached o detached
    encap_content_info = {'content_type': 'data', 'content': None}
    if args.format == "attached":
        encap_content_info['content'] = document_data # Inyecta el archivo dentro

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
        'encap_content_info': encap_content_info, # Usamos la variable evaluada
        'signer_infos': [signer_info]
    })
    signed_data['certificates'] = [cert_x509]
    # Construir archivo final
    content_info = cms.ContentInfo({'content_type': 'signed_data', 'content': signed_data})
    
    out_file = args.out if args.out else args.file + ".csig"
    with open(out_file, 'wb') as f:
        f.write(content_info.dump())
        
    print(f"[+] ¡ÉXITO! Documento firmado guardado como: {out_file}")

# ==========================================
# COMANDO: notary verify (Completo)
# ==========================================
def cmd_verify(args):
    print(f"[*] Verificando la prueba: {args.proof}")
    
    # 1. Cargar y Parsear el archivo .csig
    try:
        with open(args.proof, 'rb') as f:
            content_info = cms.ContentInfo.load(f.read())
            signed_data = content_info['content']
    except Exception as e:
        print(f"[-] INVALID: Archivo corrupto o malformado ({e})")
        return

    signer_infos = signed_data['signer_infos']
    if not signer_infos:
        print("[-] INVALID: No hay firmantes.")
        return

    # 2. Obtener documento (Attached vs Detached) y verificar Hash
    encap_content = signed_data['encap_content_info']['content']
    
    if encap_content is not None and getattr(encap_content, 'native', None) is not None:
        document_data = encap_content.native
        print("[1] Formato: CAdES Attached")
    else:
        if not args.content:
            print("[-] INVALID: Falta el documento original (--content) para firma detached")
            return
        with open(args.content, 'rb') as f:
            document_data = f.read()
        print("[1] Formato: CAdES Detached")

    calculated_hash = hashlib.sha256(document_data).digest() 
    
    signer_info = signer_infos[0]
    signed_attrs = signer_info['signed_attrs']
    
    saved_hash = None
    for attr in signed_attrs:
        if attr['type'].native == 'message_digest':
            saved_hash = attr['values'][0].native
            break
            
    print("[2] Document digest (SHA-256)")
    if calculated_hash != saved_hash:
        print("    [-] INVALID: El hash del documento NO coincide (ha sido alterado).")
        return
    print("    matches messageDigest OK")

    # 3. Extraer el Certificado del Firmante
    signer_cert_der = None
    
    # Extraemos el identificador guardado en la firma
    sid = signer_info['sid'].chosen
    
    for cert in signed_data['certificates']:
        cert_x509 = cert.chosen 
        
        # Comparamos su representación binaria pura (.dump) y el valor nativo
        if cert_x509.issuer.dump() == sid['issuer'].dump() and \
           cert_x509.serial_number == sid['serial_number'].native: 
            signer_cert_der = cert_x509.dump()
            break
            
    if not signer_cert_der:
        print("[-] INVALID: No se encontró el certificado del firmante en el archivo.")
        return
        
    signer_cert_crypto = load_der_x509_certificate(signer_cert_der)
    print(f"[3] Signer: {signer_cert_crypto.subject.rfc4514_string()}")

    # 4. Verificar la Firma Criptográfica
    # ATENCIÓN (Pitfall #1): Para validar la firma, hay que recalcular el hash 
    # de los atributos firmados codificados como un SET OF (0x31)
    set_of_bytes = b'\x31' + signed_attrs.dump()[1:]
    
    signature_bytes = signer_info['signature'].native
    public_key = signer_cert_crypto.public_key()
    
    print("[4] Signature value")
    try:
        public_key.verify(
            signature_bytes,
            set_of_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("    RSA PKCS#1 v1.5 / SHA-256 OK")
    except Exception as e:
        print(f"    [-] INVALID: La firma matemática es incorrecta ({e})")
        return

    # 5. Comprobar Sello de Tiempo (TSA)
    # Extraemos el atributo no firmado
    tst_attr = None
    for attr in signer_info['unsigned_attrs']:
        if attr['type'].native == 'signature_time_stamp_token':
            tst_attr = attr['values'][0]
            break
            
    if not tst_attr:
        print("[-] INDETERMINATE: No hay sello de tiempo (TSA). La fecha solo es una reclamación del usuario.")
        # Podrías continuar, pero el enunciado dice que sin TSA, debes avisar.
    else:
        # Extraer la fecha del sello de tiempo
        tst_info = tst_attr['content']['encap_content_info']['content'].parsed
        tsa_time = tst_info['gen_time'].native
        print(f"[5] Timestamp token: {tsa_time.strftime('%Y-%m-%d %H:%M:%S%z')}")
        
        # ATENCIÓN (Pitfall #2): Validar que el sello se calculó sobre la FIRMA, no sobre el documento
        tsa_imprint_hash = tst_info['message_imprint']['hashed_message'].native
        calculated_sig_hash = hashlib.sha256(signature_bytes).digest()
        
        if tsa_imprint_hash != calculated_sig_hash:
            print("    [-] INVALID: El sello de tiempo NO se calculó sobre esta firma.")
            return
        print("    imprint SHA-256 (signature value) OK")
    # ==========================================
    # 5.5 Comprobación de caducidad en el tiempo de firma (--at o TSA)
    # ==========================================
    eval_time = None
    if args.at:
        try:
            eval_time = datetime.datetime.strptime(args.at, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            print("[-] INVALID: Formato de fecha --at incorrecto. Usa YYYY-MM-DD")
            return
    elif tst_attr:
        eval_time = tsa_time
    else:
        eval_time = datetime.datetime.now(datetime.timezone.utc)
        
    # Usamos las propiedades _utc actualizadas de la librería cryptography
    if eval_time < signer_cert_crypto.not_valid_before_utc or eval_time > signer_cert_crypto.not_valid_after_utc:
         print(f"    [-] INVALID: El certificado estaba caducado o no era válido en la fecha de evaluación ({eval_time.strftime('%Y-%m-%d')}).")
         return
    print(f"    [+] Validez temporal: OK en la fecha de evaluación ({eval_time.strftime('%Y-%m-%d')})")

    # ==========================================
    # 6. Verificación de la Cadena de Confianza (--trust)
    # ==========================================
    if args.trust:
        print("\n[*] Validando cadena de confianza...")
        ca_valida_encontrada = False
        
        for trust_file in args.trust:
            try:
                # Leer el archivo de la CA
                with open(trust_file, 'rb') as f:
                    ca_data = f.read()
                
                # Intentar cargar como PEM primero, si falla, como DER
                try:
                    ca_cert = load_pem_x509_certificate(ca_data)
                except ValueError:
                    ca_cert = load_der_x509_certificate(ca_data)
                
                print(f"    [+] Evaluando Trust Anchor: {ca_cert.subject.rfc4514_string()}")
                
                # Comprobar si el sujeto de la CA es el emisor de nuestro certificado
                if signer_cert_crypto.issuer == ca_cert.subject:
                    ca_public_key = ca_cert.public_key()
                    
                    # Verificamos la firma del certificado del firmante usando la clave pública de la CA
                    try:
                        ca_public_key.verify(
                            signer_cert_crypto.signature,
                            signer_cert_crypto.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            signer_cert_crypto.signature_hash_algorithm
                        )
                        print("    [+] Cadena de confianza VÁLIDA: El certificado fue firmado por esta CA.")
                        ca_valida_encontrada = True
                        
                        # ==========================================
                        # 7. Comprobación de Revocación (OCSP)
                        # ==========================================
                        print("\n    [*] Consultando estado de revocación (OCSP)...")
                        ocsp_url = None
                        try:
                            # Buscar la extensión AIA que contiene la URL del servidor OCSP
                            aia_ext = signer_cert_crypto.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                            for description in aia_ext.value:
                                if description.access_method == AuthorityInformationAccessOID.OCSP:
                                    ocsp_url = description.access_location.value
                                    break
                        except Exception:
                            pass

                        if not ocsp_url:
                            print("    [ ] No se encontró URL OCSP en el certificado.")
                        else:
                            # Construir la petición OCSP
                            builder = ocsp.OCSPRequestBuilder()
                            builder = builder.add_certificate(signer_cert_crypto, ca_cert, hashes.SHA256())
                            req = builder.build()
                            
                            try:
                                # Enviar petición vía HTTP
                                resp = requests.post(
                                    ocsp_url,
                                    data=req.public_bytes(serialization.Encoding.DER),
                                    headers={'Content-Type': 'application/ocsp-request'},
                                    timeout=10
                                )
                                
                                if resp.status_code == 200:
                                    ocsp_resp = ocsp.load_der_ocsp_response(resp.content)
                                    if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                                        if ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
                                            print("    [+] Estado OCSP: VÁLIDO (El certificado no está revocado)")
                                        elif ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                                            print(f"    [-] INVALID: Estado OCSP REVOCADO en la fecha {ocsp_resp.revocation_time}")
                                            return
                                        else:
                                            print("    [-] INDETERMINATE: Estado OCSP DESCONOCIDO")
                                            return
                                    else:
                                        print(f"    [-] INDETERMINATE: El servidor OCSP rechazó la petición: {ocsp_resp.response_status}")
                                        return
                                else:
                                    print(f"    [-] INDETERMINATE: Error HTTP al contactar con OCSP: {resp.status_code}")
                                    return
                            except requests.exceptions.RequestException as e:
                                print(f"    [-] INDETERMINATE: Servidor OCSP inalcanzable ({e})")
                                return
                                
                        break # Salimos del bucle de la trust chain
                    except Exception as e:
                        print(f"    [-] INVALID: La firma matemática del certificado no corresponde a esta CA ({e})")
                        return
                else:
                    print("    [ ] Esta CA no es el emisor directo del certificado.")
            except FileNotFoundError:
                print(f"    [-] Error: No se encuentra el archivo de confianza {trust_file}")
                return
            except Exception as e:
                print(f"    [-] Error procesando {trust_file}: {e}")
                return
                
        if not ca_valida_encontrada:
            print("    [-] INVALID: Ninguno de los certificados proporcionados en --trust firmó este certificado.")
            return


    # 7. (Básico) Veredicto y simulación de cadena de confianza
    # Para el nivel estándar completo deberías comprobar --trust y OCSP aquí.
    print(f"\n[+] VERDICT: VALID signed by {signer_cert_crypto.subject.rfc4514_string()}")
    if tst_attr:
         print(f"    no later than {tsa_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

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
    parser_sign.add_argument("--key", help="Clave privada por software (.pem)")
    parser_sign.add_argument("--cert", help="Certificado por software (.pem)")

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