from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import datetime

# Generar clave privada
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open("clave_prueba.pem", "wb") as f:
    f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))

# Generar certificado autofirmado válido por 1 día
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Firmante Software")])
cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc)).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=2)).sign(private_key, hashes.SHA256())

with open("cert_prueba.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
print("Claves generadas con éxito.")