"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
import datetime


def load_ca():
    """Load CA certificate from certs/ca.crt."""
    with open("certs/ca.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_cert


def verify_cert(cert_pem: str) -> x509.Certificate:
    """
    Verify that a certificate is signed by the CA.
    Returns the certificate object if valid.
    Raises exception if verification fails.
    """
    # Load the certificate from PEM string
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    
    # Load CA certificate
    ca_cert = load_ca()
    
    # Verify signature using CA's public key
    ca_public_key = ca_cert.public_key()
    
    try:
        # Verify the certificate was signed by the CA
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except Exception as e:
        raise ValueError(f"Certificate signature verification failed: {e}")
    
    return cert


def verify_expiry(cert: x509.Certificate):
    """
    Verify that the certificate is within its validity period.
    Raises exception if expired or not yet valid.
    """
    now = datetime.datetime.utcnow()
    
    if now < cert.not_valid_before:
        raise ValueError("Certificate not yet valid")
    
    if now > cert.not_valid_after:
        raise ValueError("Certificate has expired")


def get_cn(cert: x509.Certificate) -> str:
    """Extract the Common Name (CN) from the certificate."""
    try:
        cn_list = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_list:
            return cn_list[0].value
        else:
            raise ValueError("Certificate has no CN")
    except Exception as e:
        raise ValueError(f"Failed to extract CN: {e}")


def load_own_cert(name: str) -> str:
    """Load own certificate and return as PEM string."""
    with open(f"certs/{name}.crt", "rb") as f:
        cert_pem = f.read().decode('utf-8')
    return cert_pem
