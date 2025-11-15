"""AES-128 CBC + PKCS#7 helpers."""

import os
from Crypto.Cipher import AES


def pad_pkcs7(data):
    """Apply PKCS#7 padding to data."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def unpad_pkcs7(data):
    """Remove PKCS#7 padding from data."""
    pad_len = data[-1]
    return data[:-pad_len]


def aes_encrypt(key, plaintext):
    """
    Encrypt plaintext using AES-128 CBC mode with PKCS#7 padding.
    Returns: iv || ciphertext (both as bytes)
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad_pkcs7(plaintext)
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return iv + ciphertext


def aes_decrypt(key, data):
    """
    Decrypt data (iv || ciphertext) using AES-128 CBC mode.
    Returns: plaintext bytes
    """
    iv = data[:16]
    ciphertext = data[16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad_pkcs7(padded_plaintext)
    
    return plaintext
