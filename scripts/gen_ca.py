#!/usr/bin/env python3
"""
Generate Root CA certificate and private key for SecureChat PKI
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import os


def main():
    # Create certs directory if it doesn't exist
    os.makedirs("certs", exist_ok=True)
    
    print("Generating Root CA...")
    
    # Generate 2048-bit RSA private key
    print("  - Generating 2048-bit RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create subject for CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "securechat-root-ca"),
    ])
    
    # Build self-signed certificate
    print("  - Creating self-signed X.509 certificate...")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    
    # Save private key (unencrypted)
    print("  - Saving private key to certs/ca.key...")
    with open("certs/ca.key", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Save certificate
    print("  - Saving certificate to certs/ca.crt...")
    with open("certs/ca.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("\n✓ Root CA successfully generated!")
    print("  Private Key: certs/ca.key")
    print("  Certificate: certs/ca.crt")


if __name__ == "__main__":
    main()
