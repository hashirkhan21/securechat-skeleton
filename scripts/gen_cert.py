#!/usr/bin/env python3
"""
Generate entity certificate signed by Root CA for SecureChat PKI
Usage: python scripts/gen_cert.py <name>
Example: python scripts/gen_cert.py client
         python scripts/gen_cert.py server
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import sys
import os


def main():
    # Check command line arguments
    if len(sys.argv) != 2:
        print("Usage: python scripts/gen_cert.py <name>")
        print("Example: python scripts/gen_cert.py client")
        print("         python scripts/gen_cert.py server")
        sys.exit(1)
    
    entity_name = sys.argv[1]
    
    # Check if CA files exist
    if not os.path.exists("certs/ca.key"):
        print("Error: certs/ca.key not found. Run gen_ca.py first.")
        sys.exit(1)
    
    if not os.path.exists("certs/ca.crt"):
        print("Error: certs/ca.crt not found. Run gen_ca.py first.")
        sys.exit(1)
    
    print(f"Generating certificate for '{entity_name}'...")
    
    # Load CA private key
    print("  - Loading CA private key...")
    with open("certs/ca.key", "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    # Load CA certificate
    print("  - Loading CA certificate...")
    with open("certs/ca.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    # Generate 2048-bit RSA private key for entity
    print(f"  - Generating 2048-bit RSA private key for {entity_name}...")
    entity_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create subject for entity
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST SecureChat User"),
        x509.NameAttribute(NameOID.COMMON_NAME, entity_name),
    ])
    
    # Build certificate signed by CA
    print(f"  - Creating X.509 certificate signed by CA...")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(entity_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_private_key, hashes.SHA256())
    )
    
    # Save entity private key (unencrypted)
    key_path = f"certs/{entity_name}.key"
    print(f"  - Saving private key to {key_path}...")
    with open(key_path, "wb") as f:
        f.write(
            entity_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Save entity certificate
    cert_path = f"certs/{entity_name}.crt"
    print(f"  - Saving certificate to {cert_path}...")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"\n✓ Certificate for '{entity_name}' successfully generated!")
    print(f"  Private Key: {key_path}")
    print(f"  Certificate: {cert_path}")


if __name__ == "__main__":
    main()
