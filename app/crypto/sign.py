"""RSA signing and verification for message authentication."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509


def load_private_key(key_path):
    """Load RSA private key from file."""
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return private_key


def sign_data(private_key, data):
    """
    Sign data using RSA private key with PKCS1v15 and SHA256.
    Returns: signature bytes
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, signature, data):
    """
    Verify RSA signature using public key.
    Returns: True if valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def get_cert_fingerprint(cert):
    """
    Get SHA256 fingerprint of certificate.
    Returns: hex string
    """
    cert_bytes = cert.public_bytes(serialization.Encoding.DER)
    import hashlib
    return hashlib.sha256(cert_bytes).hexdigest()
