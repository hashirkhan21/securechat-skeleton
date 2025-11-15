"""Message creation, verification, and transcript management for secure chat."""

import json
import hashlib
import os
from pathlib import Path

from app.common.utils import b64e, b64d, now_ms, sha256_hex
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import sign_data, verify_signature, get_cert_fingerprint, load_private_key
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def make_msg(seqno, plaintext_bytes, aes_key, signer_priv_key):
    """
    Create a signed encrypted message.
    
    Args:
        seqno: Sequence number (must be strictly increasing)
        plaintext_bytes: Message content as bytes
        aes_key: AES-128 key for encryption
        signer_priv_key: RSA private key for signing
    
    Returns:
        JSON string of message: {"type":"msg","seqno":n,"ts":unix_ms,"ct":base64,"sig":base64}
    """
    # Get current timestamp
    ts = now_ms()
    
    # Encrypt plaintext with AES-128 CBC
    ciphertext = aes_encrypt(aes_key, plaintext_bytes)
    ct_b64 = b64e(ciphertext)
    
    # Create signature payload: seqno || ts || ct
    sig_payload = f"{seqno}|{ts}|{ct_b64}".encode('utf-8')
    
    # Sign with RSA (PKCS1v15 + SHA256)
    signature = sign_data(signer_priv_key, sig_payload)
    sig_b64 = b64e(signature)
    
    # Create message
    msg = {
        "type": "msg",
        "seqno": seqno,
        "ts": ts,
        "ct": ct_b64,
        "sig": sig_b64
    }
    
    return json.dumps(msg)


def verify_and_decrypt(msg_json, aes_key, sender_cert, expected_seqno):
    """
    Verify signature and decrypt message.
    
    Args:
        msg_json: JSON string or dict of message
        aes_key: AES-128 key for decryption
        sender_cert: X.509 certificate of sender (for signature verification)
        expected_seqno: Expected next sequence number
    
    Returns:
        Tuple (ok: bool, data_or_reason: bytes/str, new_seqno: int)
        - If ok=True: data_or_reason is decrypted plaintext bytes
        - If ok=False: data_or_reason is error reason string
    """
    try:
        # Parse message
        if isinstance(msg_json, str):
            msg = json.loads(msg_json)
        else:
            msg = msg_json
        
        seqno = msg['seqno']
        ts = msg['ts']
        ct_b64 = msg['ct']
        sig_b64 = msg['sig']
        
        # Check sequence number (must be strictly increasing)
        if seqno != expected_seqno:
            if seqno < expected_seqno:
                return False, "REPLAY", expected_seqno
            else:
                return False, f"SEQNO GAP: expected {expected_seqno}, got {seqno}", expected_seqno
        
        # Verify signature
        sig_payload = f"{seqno}|{ts}|{ct_b64}".encode('utf-8')
        signature = b64d(sig_b64)
        
        sender_public_key = sender_cert.public_key()
        if not verify_signature(sender_public_key, signature, sig_payload):
            return False, "SIG FAIL", expected_seqno
        
        # Decrypt ciphertext
        ciphertext = b64d(ct_b64)
        plaintext = aes_decrypt(aes_key, ciphertext)
        
        # Return success with incremented seqno
        return True, plaintext, seqno + 1
        
    except Exception as e:
        return False, f"ERROR: {e}", expected_seqno


def append_transcript_line(transcript_path, seqno, ts, ct_b64, sig_b64, peer_cert):
    """
    Append a message to the session transcript file.
    
    Format: seqno|ts|ct|sig|peer_cert_fingerprint
    """
    # Get certificate fingerprint
    cert_fp = get_cert_fingerprint(peer_cert)
    
    # Create transcript line
    line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{cert_fp}\n"
    
    # Ensure transcript directory exists
    Path(transcript_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Append to file
    with open(transcript_path, 'a') as f:
        f.write(line)


def compute_transcript_hash(transcript_path):
    """
    Compute SHA256 hash of entire transcript file.
    
    Returns:
        Hex string of SHA256 hash, or empty string if file doesn't exist
    """
    if not os.path.exists(transcript_path):
        return ""
    
    with open(transcript_path, 'rb') as f:
        transcript_data = f.read()
    
    return sha256_hex(transcript_data)


def make_session_receipt(transcript_path, my_priv_key, peer_label):
    """
    Create a signed session receipt for the transcript.
    
    Args:
        transcript_path: Path to transcript file
        my_priv_key: My RSA private key for signing
        peer_label: Label/identifier of peer (e.g., "server" or "client")
    
    Returns:
        Dict: {
            "type": "receipt",
            "peer": peer_label,
            "transcript_hash": hex_string,
            "signature": base64_signature
        }
    """
    # Compute transcript hash
    transcript_hash = compute_transcript_hash(transcript_path)
    
    if not transcript_hash:
        raise ValueError("Transcript file not found or empty")
    
    # Sign the transcript hash
    signature = sign_data(my_priv_key, transcript_hash.encode('utf-8'))
    sig_b64 = b64e(signature)
    
    receipt = {
        "type": "receipt",
        "peer": peer_label,
        "transcript_hash": transcript_hash,
        "signature": sig_b64
    }
    
    return receipt


def verify_session_receipt(receipt, transcript_path, peer_cert):
    """
    Verify a session receipt against the transcript.
    
    Args:
        receipt: Receipt dict from make_session_receipt
        transcript_path: Path to transcript file
        peer_cert: Peer's X.509 certificate
    
    Returns:
        Tuple (ok: bool, message: str)
    """
    try:
        # Compute local transcript hash
        local_hash = compute_transcript_hash(transcript_path)
        
        if not local_hash:
            return False, "Local transcript not found"
        
        # Compare hashes
        if local_hash != receipt['transcript_hash']:
            return False, "Transcript hash mismatch"
        
        # Verify signature
        signature = b64d(receipt['signature'])
        peer_public_key = peer_cert.public_key()
        
        if not verify_signature(peer_public_key, signature, local_hash.encode('utf-8')):
            return False, "Receipt signature verification failed"
        
        return True, "Receipt verified successfully"
        
    except Exception as e:
        return False, f"Verification error: {e}"


def load_cert_from_pem(cert_pem):
    """Load X.509 certificate from PEM string."""
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode('utf-8')
    return x509.load_pem_x509_certificate(cert_pem)


def log_message_sent(seqno, plaintext):
    """Log sent message details."""
    preview = plaintext[:50] if len(plaintext) <= 50 else plaintext[:50] + "..."
    print(f"  → Sent message #{seqno}")
    print(f"    Content: {preview}")


def log_message_received(seqno, plaintext):
    """Log received message details."""
    preview = plaintext[:50] if len(plaintext) <= 50 else plaintext[:50] + "..."
    print(f"  ← Received message #{seqno}")
    print(f"    Content: {preview}")


def log_verification_failure(reason):
    """Log verification failure."""
    print(f"  ✗ Verification failed: {reason}")

