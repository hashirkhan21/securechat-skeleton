import os, hashlib
from Crypto.Cipher import AES


def dh_generate_private():
    return int.from_bytes(os.urandom(32), 'big')

def dh_generate_public(g, p, a):
    return pow(g, a, p)

def dh_compute_shared(B, a, p):
    Ks = pow(B, a, p)
    Ks_bytes = Ks.to_bytes((Ks.bit_length() + 7) // 8, 'big')
    return hashlib.sha256(Ks_bytes).digest()[:16]

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext))
    return iv + ct

def aes_decrypt(key, data):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct))
