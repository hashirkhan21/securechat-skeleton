"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import os
import hashlib


def dh_generate_private():
    """Generate a random 256-bit private key for DH."""
    return int.from_bytes(os.urandom(32), 'big')


def dh_generate_public(g, p, a):
    """Compute public key A = g^a mod p."""
    return pow(g, a, p)


def dh_compute_shared(B, a, p):
    """
    Compute shared secret from peer's public key B.
    Returns first 16 bytes of SHA256(Ks) as AES key.
    """
    Ks = pow(B, a, p)
    Ks_bytes = Ks.to_bytes((Ks.bit_length() + 7) // 8, 'big')
    # Derive AES key: first 16 bytes of SHA256(Ks)
    aes_key = hashlib.sha256(Ks_bytes).digest()[:16]
    return aes_key


def get_dh_parameters():
    """
    Return safe DH parameters (p, g).
    Using a 2048-bit safe prime from RFC 3526.
    """
    # 2048-bit MODP Group (RFC 3526 Group 14)
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    g = 2
    return p, g
