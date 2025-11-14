"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import sys

from app.common.protocol import HelloMessage, ServerHelloMessage
from app.common.utils import b64e, b64d
from app.crypto.pki import load_own_cert, verify_cert, verify_expiry, get_cn


def send_message(sock, message_dict):
    """Send a JSON message over the socket."""
    message_json = json.dumps(message_dict)
    sock.sendall(message_json.encode('utf-8') + b'\n')


def receive_message(sock):
    """Receive a JSON message from the socket."""
    buffer = b''
    while b'\n' not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed")
        buffer += chunk
    
    message_json = buffer.split(b'\n', 1)[0]
    return json.loads(message_json.decode('utf-8'))


def perform_certificate_exchange(sock):
    """
    Perform certificate exchange with server.
    Returns True if successful, False otherwise.
    """
    print("Starting certificate exchange...")
    
    # Load client certificate
    try:
        client_cert_pem = load_own_cert("client")
    except Exception as e:
        print(f"BAD CERT: Failed to load client certificate: {e}")
        return False
    
    # Generate random nonce
    client_nonce = os.urandom(32)
    client_nonce_b64 = b64e(client_nonce)
    
    # Send hello message with client certificate
    hello_msg = HelloMessage(
        client_cert=client_cert_pem,
        nonce=client_nonce_b64
    )
    print("Sending client certificate...")
    send_message(sock, hello_msg.dict())
    
    # Receive server hello with server certificate
    print("Waiting for server certificate...")
    try:
        server_hello_data = receive_message(sock)
        server_hello = ServerHelloMessage(**server_hello_data)
    except Exception as e:
        print(f"BAD CERT: Failed to receive server hello: {e}")
        return False
    
    print("Received certificate from server")
    
    # Verify server certificate
    try:
        # Verify CA signature
        server_cert = verify_cert(server_hello.server_cert)
        print("Certificate signature verified")
        
        # Verify expiry
        verify_expiry(server_cert)
        print("Certificate validity period verified")
        
        # Verify CN is "server"
        cn = get_cn(server_cert)
        if cn != "server":
            print(f"BAD CERT: wrong CN (expected 'server', got '{cn}')")
            return False
        print(f"Certificate CN verified: {cn}")
        
    except ValueError as e:
        print(f"BAD CERT: {e}")
        return False
    except Exception as e:
        print(f"BAD CERT: invalid signature or format: {e}")
        return False
    
    print("✓ Certificate verified successfully")
    return True


def main():
    """Main client workflow."""
    HOST = '127.0.0.1'
    PORT = 8888
    
    print(f"Connecting to server at {HOST}:{PORT}...")
    
    try:
        # Create socket and connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        print("Connected to server")
        
        # STEP 1: Certificate exchange (BEFORE anything else)
        if not perform_certificate_exchange(sock):
            print("Certificate verification failed. Closing connection.")
            sock.close()
            return
        
        print("\n" + "="*50)
        print("Certificate exchange complete. Ready for secure communication.")
        print("="*50 + "\n")
        
        # TODO: Students implement remaining protocol steps:
        # - User registration/login
        # - DH key exchange
        # - AES encrypted messaging
        
        print("Remaining protocol steps not yet implemented.")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'sock' in locals():
            sock.close()
            print("Connection closed")


if __name__ == "__main__":
    main()
