import os
import sys
import argparse
import platform
import getpass
import hashlib
import datetime
import requests

# Librerías criptográficas y de hardware
from PyKCS11 import *
from asn1crypto import cms, tsp, x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate, ocsp
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

def get_pkcs11_module_path():
    """
    Detecta el sistema operativo y devuelve la ruta predeterminada 
    de la librería OpenSC para interactuar con el token PKCS#11 (DNIe).
    """
    os_name = platform.system()
    if os_name == "Windows":
        return r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
    elif os_name == "Darwin":  # macOS
        return "/usr/local/lib/opensc-pkcs11.so"
    else:  # Linux
        return "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"


# ==========================================
# COMANDO: notary info
# ==========================================
def cmd_info(args):
    """
    Lee y muestra información del token hardware insertado (DNIe) 
    y lista los certificados públicos disponibles sin necesidad de PIN.
    """
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
        
        # 1. Comprobar el estado de seguridad del PIN
        flags = token_info.flags
        if flags & CKF_USER_PIN_FINAL_TRY:
            print("    [!] ADVERTENCIA: Último intento del PIN. Si fallas, la tarjeta se bloqueará.")
        elif flags & CKF_USER_PIN_LOCKED:
            print("    [!] ERROR: El PIN está bloqueado.")
        else:
            print("    Estado del PIN: OK")

        # 2. Extraer certificados públicos (Sesión pública, sin login)
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION)
        certs = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
        print(f"\n    Certificados encontrados: {len(certs)}")
        
        for idx, cert_obj in enumerate(certs):
            attributes = session.getAttributeValue(cert_obj, [CKA_LABEL, CKA_VALUE])
            label = attributes[0]
            cert_der = bytes(attributes[1])
            
            # Decodificar información básica del certificado
            cert = x509.Certificate.load(cert_der)
            
            print(f"\n    --- Certificado {idx + 1}: {label} ---")
            print(f"    Sujeto: {cert.subject.human_friendly}")
            print(f"    Emisor: {cert.issuer.human_friendly}")
            print(f"    Válido desde: {cert.not_valid_before}")
            print(f"    Válido hasta: {cert.not_valid_after}")
            
            if cert.key_usage_value:
                print(f"    Uso de la clave: {', '.join(list(cert.key_usage_value.native))}")

        session.closeSession()


# ==========================================
# COMANDO: notary sign
# ==========================================
def cmd_sign(args):
    """
    Firma un documento generando un contenedor CAdES-T. 
    Soporta firmas por hardware (DNIe) y por software (.pem), 
    sellado de tiempo (TSA), firmas paralelas e incrustación LTV (OCSP).
    """
    print(f"[*] Preparando para firmar el archivo: {args.file}")

    # 1. Leer archivo original y calcular su Hash SHA-256
    try:
        with open(args.file, 'rb') as f:
            document_data = f.read()
    except FileNotFoundError:
        print(f"[-] Error: No se encuentra el archivo {args.file}")
        return

    document_hash = hashlib.sha256(document_data).digest()
    usar_hardware = not (args.key and args.cert)

    # 2. Cargar credenciales de firma (Hardware o Software)
    if usar_hardware:
        pkcs11 = PyKCS11Lib()
        pkcs11.load(get_pkcs11_module_path())
        slots = pkcs11.getSlotList(tokenPresent=True)
        
        if not slots:
            print("[-] No hay tarjeta insertada.")
            return

        session = pkcs11.openSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
        certs = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
        cert_der, cert_id, cert_x509 = None, None, None
        
        # Buscar el certificado destinado al No Repudio (Firma Digital)
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
            
        # Comprobación de seguridad para evitar el bloqueo de la tarjeta
        token_info = pkcs11.getTokenInfo(slots[0])
        if token_info.flags & CKF_USER_PIN_FINAL_TRY:
            print("[-] SEGURIDAD: La tarjeta indica que este es el ÚLTIMO INTENTO del PIN.")
            print("[-] Operación cancelada. El programa se niega a probar el PIN para evitar bloquear la tarjeta.")
            session.closeSession()
            return
        elif token_info.flags & CKF_USER_PIN_LOCKED:
            print("[-] ERROR: El PIN ya está bloqueado. Ve a una comisaría para desbloquearlo.")
            session.closeSession()
            return

        pin = getpass.getpass("    Introduce el PIN de tu DNIe: ")
        try:
            session.login(pin)
        except PyKCS11Error as e:
            print(f"[-] PIN incorrecto: {e}")
            session.closeSession()
            return
    else:
        print("[*] Usando firma por software (ficheros PEM)...")
        try:
            with open(args.cert, 'rb') as f:
                cert_crypto = load_pem_x509_certificate(f.read())
                cert_der = cert_crypto.public_bytes(serialization.Encoding.DER)
                cert_x509 = x509.Certificate.load(cert_der)
                
            with open(args.key, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            print(f"[-] Error cargando la clave o certificado por software: {e}")
            return

    # 3. Construir Atributos Firmados (SignedAttributes)
    digest_attr = cms.CMSAttribute({'type': 'message_digest', 'values': [document_hash]})
    content_type_attr = cms.CMSAttribute({'type': 'content_type', 'values': ['data']})
    signing_time_attr = cms.CMSAttribute({'type': 'signing_time', 'values': [cms.Time({'utc_time': datetime.datetime.now(datetime.timezone.utc)})]})
    
    cert_hash = hashlib.sha256(cert_der).digest()
    sign_cert_attr = cms.CMSAttribute({
        'type': 'signing_certificate_v2',
        'values': [{'certs': [{'hash_algorithm': {'algorithm': 'sha256'}, 'cert_hash': cert_hash}]}]
    })
    
    # Agrupar atributos y empaquetarlos en un SET OF (0x31) para calcular el hash a firmar
    signed_attrs_list = [content_type_attr, digest_attr, signing_time_attr, sign_cert_attr]
    signed_attrs = cms.CMSAttributes(signed_attrs_list)
    set_of_bytes = b'\x31' + signed_attrs.dump()[1:]

    # 4. Ejecutar operación criptográfica de firma
    if usar_hardware:
        priv_keys = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, cert_id)])
        mech = Mechanism(CKM_SHA256_RSA_PKCS, None)
        signature_bytes = bytes(session.sign(priv_keys[0], set_of_bytes, mech))
        
        session.logout()
        session.closeSession()
        print("[+] Atributos firmados con éxito por el DNIe.")
    else:
        signature_bytes = private_key.sign(set_of_bytes, padding.PKCS1v15(), hashes.SHA256())
        print("[+] Atributos firmados con éxito por software.") 

    # 5. Obtener Sello de Tiempo de Autoridad Externa (TSA)
    print("[*] Solicitando sello de tiempo (RFC 3161)...")
    sig_hash = document_hash
    nonce = int.from_bytes(os.urandom(8), byteorder='big') 
    
    tsa_req = tsp.TimeStampReq({
        'version': 1,
        'message_imprint': tsp.MessageImprint({'hash_algorithm': {'algorithm': 'sha256'}, 'hashed_message': sig_hash}),
        'cert_req': True,
        'nonce': nonce
    })
    
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

    tst_resp = tsp.TimeStampResp.load(tsa_resp_data)
    if tst_resp['status']['status'].native != 'granted':
        print(f"[-] La TSA rechazó la petición.")
        return
        
    tst_token = tst_resp['time_stamp_token']
    tst_info = tst_token['content']['encap_content_info']['content'].parsed
    
    if tst_info['nonce'].native != nonce:
        print("[-] ERROR DE SEGURIDAD: El nonce de la TSA no coincide (Ataque de repetición).")
        return

    # 6. Recolectar evidencias de Validación a Largo Plazo (LTV - OCSP)
    print("[*] Recopilando evidencias para Validación a Largo Plazo (LTV)...")
    ca_cert_x509 = None
    ocsp_res_data = None

    if args.trust:
        try:
            with open(args.trust, 'rb') as f:
                ca_data = f.read()
                try:
                    ca_cert_crypto = load_pem_x509_certificate(ca_data)
                except ValueError:
                    ca_cert_crypto = load_der_x509_certificate(ca_data)
                
                ca_cert_x509 = x509.Certificate.load(ca_cert_crypto.public_bytes(serialization.Encoding.DER))
                
            # Extraer URL OCSP del certificado usando la extensión AIA
            cert_crypto_eval = load_der_x509_certificate(cert_der)
            ocsp_url = None
            try:
                aia_ext = cert_crypto_eval.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                for description in aia_ext.value:
                    if description.access_method == AuthorityInformationAccessOID.OCSP:
                        ocsp_url = description.access_location.value
                        break
            except Exception:
                pass

            if ocsp_url:
                print(f"    [+] Solicitando evidencia OCSP a {ocsp_url}...")
                builder = ocsp.OCSPRequestBuilder()
                builder = builder.add_certificate(cert_crypto_eval, ca_cert_crypto, hashes.SHA256())
                req = builder.build()
                resp = requests.post(ocsp_url, data=req.public_bytes(serialization.Encoding.DER), headers={'Content-Type': 'application/ocsp-request'}, timeout=10)
                if resp.status_code == 200:
                    ocsp_res_data = resp.content
                    print("    [+] Evidencia OCSP obtenida e incrustada correctamente.")
        except Exception as e:
            print(f"    [-] Error obteniendo LTV: {e}")
    
    # 7. Construcción Final del Contenedor CMS/CAdES
    print("[*] Empaquetando firma en formato CAdES-T (DER)...")
    encap_content_info = {'content_type': 'data', 'content': None}
    if args.format == "attached":
        encap_content_info['content'] = document_data 

    tst_attr = cms.CMSAttribute({'type': 'signature_time_stamp_token', 'values': [tst_token]})
    
    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier({'issuer_and_serial_number': cms.IssuerAndSerialNumber({'issuer': cert_x509.issuer, 'serial_number': cert_x509.serial_number})}),
        'digest_algorithm': {'algorithm': 'sha256'},
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signed_attrs': signed_attrs_list,
        'signature': signature_bytes,
        'unsigned_attrs': [tst_attr]
    })
    
    certs_list = [cert_x509]
    if ca_cert_x509:
        certs_list.append(ca_cert_x509)
        
    crls_list = []
    if ocsp_res_data:
        from asn1crypto import ocsp as asn1_ocsp
        ocsp_parsed = asn1_ocsp.OCSPResponse.load(ocsp_res_data)
        rev_info = cms.OtherRevocationInfoFormat({
            'other_rev_info_format': '1.3.6.1.5.5.7.48.1.1',
            'other_rev_info': ocsp_parsed
        })
        crls_list.append(cms.RevocationInfoChoice({'other': rev_info}))

    out_file = args.out if args.out else args.file + ".csig"

    # Lógica para Múltiples Firmantes (Several Signers)
    if os.path.exists(out_file):
        print(f"[*] El archivo {out_file} ya existe. Añadiendo firma paralela...")
        with open(out_file, 'rb') as f:
            content_info = cms.ContentInfo.load(f.read())
            signed_data = content_info['content']
            
        signed_data['signer_infos'].append(signer_info)
        for c in certs_list:
            signed_data['certificates'].append(c)
            
        if crls_list:
            if signed_data['crls'] is None:
                signed_data['crls'] = crls_list
            else:
                for crl in crls_list:
                    signed_data['crls'].append(crl)
    else:
        signed_data = cms.SignedData({
            'version': 'v3',
            'digest_algorithms': [{'algorithm': 'sha256'}],
            'encap_content_info': encap_content_info,
            'certificates': certs_list,
            'crls': crls_list if crls_list else None,
            'signer_infos': [signer_info]
        })
        content_info = cms.ContentInfo({'content_type': 'signed_data', 'content': signed_data})

    # Guardado definitivo
    with open(out_file, 'wb') as f:
        f.write(content_info.dump())
        
    print(f"[+] ¡ÉXITO! Documento firmado guardado en: {out_file}")


# ==========================================
# COMANDO: notary verify
# ==========================================
def cmd_verify(args):
    """
    Verifica un archivo .csig validando matemáticamente todas las firmas contenidas, 
    sus sellos de tiempo, la integridad del documento, caducidad y cadena de confianza LTV.
    """
    print(f"[*] Verificando la prueba: {args.proof}")
    
    # 1. Cargar archivo de firma
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

    # 2. Cargar documento original
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
    print(f"[*] Se encontraron {len(signer_infos)} firma(s) en el documento.")
    
    # 3. Iterar y evaluar de forma independiente a cada firmante
    for idx, signer_info in enumerate(signer_infos):
        print(f"\n==========================================")
        print(f"[*] EVALUANDO FIRMANTE {idx + 1}")
        print(f"==========================================")
        
        signed_attrs = signer_info['signed_attrs']
        
        # Validar Hash del Documento
        saved_hash = None
        for attr in signed_attrs:
            if attr['type'].native == 'message_digest':
                saved_hash = attr['values'][0].native
                break
                
        print("[2] Document digest (SHA-256)")
        if calculated_hash != saved_hash:
            print("    [-] INVALID: El hash del documento NO coincide (ha sido alterado).")
            continue
        print("    matches messageDigest OK")

        # Localizar certificado del firmante dentro del contenedor
        signer_cert_der = None
        sid = signer_info['sid'].chosen
        
        for cert in signed_data['certificates']:
            cert_x509 = cert.chosen 
            if cert_x509.issuer.dump() == sid['issuer'].dump() and cert_x509.serial_number == sid['serial_number'].native: 
                signer_cert_der = cert_x509.dump()
                break
                
        if not signer_cert_der:
            print("    [-] INVALID: No se encontró el certificado del firmante en el archivo.")
            continue
            
        signer_cert_crypto = load_der_x509_certificate(signer_cert_der)
        print(f"[3] Signer: {signer_cert_crypto.subject.rfc4514_string()}")

        # Validar la Firma RSA Matemática
        set_of_bytes = b'\x31' + signed_attrs.dump()[1:]
        signature_bytes = signer_info['signature'].native
        public_key = signer_cert_crypto.public_key()
        
        print("[4] Signature value")
        try:
            public_key.verify(signature_bytes, set_of_bytes, padding.PKCS1v15(), hashes.SHA256())
            print("    RSA PKCS#1 v1.5 / SHA-256 OK")
        except Exception as e:
            print(f"    [-] INVALID: La firma matemática es incorrecta ({e})")
            continue

        # Validar Sello de Tiempo (TSA)
        tst_attr = None
        for attr in signer_info['unsigned_attrs']:
            if attr['type'].native == 'signature_time_stamp_token':
                tst_attr = attr['values'][0]
                break
                
        if not tst_attr:
            print("    [-] INDETERMINATE: No hay sello de tiempo (TSA). La fecha es una reclamación del usuario.")
        else:
            tst_info = tst_attr['content']['encap_content_info']['content'].parsed
            tsa_time = tst_info['gen_time'].native
            print(f"[5] Timestamp token: {tsa_time.strftime('%Y-%m-%d %H:%M:%S%z')}")
            
            tsa_imprint_hash = tst_info['message_imprint']['hashed_message'].native
            calculated_sig_hash = hashlib.sha256(signature_bytes).digest()
            
            if tsa_imprint_hash != calculated_sig_hash:
                print("    [-] INVALID: El sello de tiempo NO se calculó sobre esta firma.")
                continue
            print("    imprint SHA-256 (signature value) OK")

        # Comprobación de Caducidad Temporal
        eval_time = None
        if args.at:
            try:
                eval_time = datetime.datetime.strptime(args.at, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                print("    [-] INVALID: Formato de fecha --at incorrecto.")
                continue
        elif tst_attr:
            eval_time = tsa_time
        else:
            eval_time = datetime.datetime.now(datetime.timezone.utc)
            
        if eval_time < signer_cert_crypto.not_valid_before_utc or eval_time > signer_cert_crypto.not_valid_after_utc:
             print(f"    [-] INVALID: Certificado caducado o inválido en la fecha de evaluación ({eval_time.strftime('%Y-%m-%d')}).")
             continue
        print(f"    [+] Validez temporal: OK en la fecha de evaluación ({eval_time.strftime('%Y-%m-%d')})")

        # Validación de Cadena de Confianza y LTV Offline
        if args.trust:
            print("\n    [*] Validando cadena de confianza...")
            ca_valida_encontrada = False
            for trust_file in args.trust:
                try:
                    with open(trust_file, 'rb') as f:
                        ca_data = f.read()
                    try:
                        ca_cert = load_pem_x509_certificate(ca_data)
                    except ValueError:
                        ca_cert = load_der_x509_certificate(ca_data)
                    
                    if signer_cert_crypto.issuer == ca_cert.subject:
                        ca_public_key = ca_cert.public_key()
                        try:
                            ca_public_key.verify(signer_cert_crypto.signature, signer_cert_crypto.tbs_certificate_bytes, padding.PKCS1v15(), signer_cert_crypto.signature_hash_algorithm)
                            print("        [+] Cadena de confianza VÁLIDA.")
                            ca_valida_encontrada = True
                            
                            # Comprobación OCSP Incrustada (LTV)
                            print("        [*] Consultando estado de revocación (OFFLINE LTV)...")
                            ocsp_offline_found = False
                            if signed_data['crls']:
                                for crl_choice in signed_data['crls']:
                                    if crl_choice.name == 'other' and crl_choice.chosen['other_rev_info_format'].native == '1.3.6.1.5.5.7.48.1.1':
                                        ocsp_resp = ocsp.load_der_ocsp_response(crl_choice.chosen['other_rev_info'].dump())
                                        ocsp_offline_found = True
                                        if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL and ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
                                            print("        [+] Estado OCSP (Incrustado): VÁLIDO")
                                        else:
                                            print("        [-] INVALID / INDETERMINATE: Estado OCSP revocado o desconocido.")
                                        break
                            if not ocsp_offline_found:
                                print("        [ ] No se encontró evidencia OCSP incrustada.")
                            break
                        except Exception:
                            print(f"        [-] INVALID: La firma del certificado no corresponde a esta CA.")
                            continue
                except Exception:
                    pass
            
            if not ca_valida_encontrada:
                print("    [-] INVALID: Ninguno de los certificados en --trust firmó este certificado.")
                continue

        print(f"\n    [+] VERDICT (Firmante {idx + 1}): VALID signed by {signer_cert_crypto.subject.rfc4514_string()}")


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
    parser_sign.add_argument("--trust", help="Certificado de la CA (para incrustar evidencias LTV)")

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