Step 1 — PKI Setup

This project uses a custom Certificate Authority (CA) to issue X.509 certificates for the client and server.

Generate root CA
python scripts/gen_ca.py


This creates:
certs/ca.key — CA private key
certs/ca.crt — CA certificate

Generate client/server certificates
python scripts/gen_cert.py client
python scripts/gen_cert.py server


This produces:

certs/client.key, certs/client.crt
certs/server.key, certs/server.crt

Security Note

Private keys and certificates are ignored in Git:

certs/*.key
certs/*.crt


Users must generate their own.

Step 2 — Certificate Verification

After exchanging certificates during the hello phase, the client and server
mutually authenticate each other by:

1. Loading the Root CA certificate
2. Verifying the peer certificate signature using the CA public key
3. Checking certificate validity dates
4. Validating Common Name (CN)
   - Client expects CN = "server"
   - Server expects CN = "client"
5. Rejecting invalid, expired or untrusted certificates with "BAD CERT"

This ensures only trusted parties participate in registration, login and chat.

Step 3 — Registration & Login (MySQL + AES + DH)

The client and server derive a temporary AES-128 key using Diffie–Hellman to encrypt all credential messages.

Create database

CREATE DATABASE securechat;
USE securechat;

CREATE TABLE users (
    email VARCHAR(255),
    username VARCHAR(255) UNIQUE,
    salt VARBINARY(16),
    pwd_hash CHAR(64)
);

Registration

Client and server run temporary DH
Client encrypts credentials using AES

Server stores:
email
username
random salt
SHA256(salt||password)

Login
Client sends AES-encrypted credentials
Server recomputes hash and verifies

Credentials are never transmitted or stored in plaintext.

## Step 4 — Encrypted Chat + Signatures + Integrity

Message format (JSON):
{
 "type":"msg",
 "seqno": <int>,
 "ts": <unix_ms>,
 "ct": "<base64 iv+ciphertext>",
 "sig": "<base64 RSA-signature(SHA256(seqno||ts||ct))>"
}

- Messages are encrypted with AES-128-CBC (IV prefix) and PKCS#7 padding.
- Each message is signed with the sender's RSA private key (PKCS#1 v1.5 + SHA-256).
- Receiver verifies signature and sequence number before decrypting.
- All messages appended to session transcript file for non-repudiation.
- At session end, transcript SHA256 is signed to produce a SessionReceipt.
