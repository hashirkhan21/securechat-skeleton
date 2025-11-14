"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import sys
import threading

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


def perform_certificate_exchange(client_sock, client_addr):
    """
    Perform certificate exchange with client.
    Returns True if successful, False otherwise.
    """
    print(f"[{client_addr}] Starting certificate exchange...")
    
    # Receive client hello with certificate
    print(f"[{client_addr}] Waiting for client certificate...")
    try:
        hello_data = receive_message(client_sock)
        hello_msg = HelloMessage(**hello_data)
    except Exception as e:
        print(f"[{client_addr}] BAD CERT: Failed to receive client hello: {e}")
        return False
    
    print(f"[{client_addr}] Received certificate from client")
    
    # Verify client certificate
    try:
        # Verify CA signature
        client_cert = verify_cert(hello_msg.client_cert)
        print(f"[{client_addr}] Certificate signature verified")
        
        # Verify expiry
        verify_expiry(client_cert)
        print(f"[{client_addr}] Certificate validity period verified")
        
        # Verify CN is "client"
        cn = get_cn(client_cert)
        if cn != "client":
            print(f"[{client_addr}] BAD CERT: wrong CN (expected 'client', got '{cn}')")
            return False
        print(f"[{client_addr}] Certificate CN verified: {cn}")
        
    except ValueError as e:
        print(f"[{client_addr}] BAD CERT: {e}")
        return False
    except Exception as e:
        print(f"[{client_addr}] BAD CERT: invalid signature or format: {e}")
        return False
    
    print(f"[{client_addr}] ✓ Certificate verified successfully")
    
    # Load server certificate
    try:
        server_cert_pem = load_own_cert("server")
    except Exception as e:
        print(f"[{client_addr}] BAD CERT: Failed to load server certificate: {e}")
        return False
    
    # Generate random nonce
    server_nonce = os.urandom(32)
    server_nonce_b64 = b64e(server_nonce)
    
    # Send server hello with certificate
    server_hello = ServerHelloMessage(
        server_cert=server_cert_pem,
        nonce=server_nonce_b64
    )
    print(f"[{client_addr}] Sending server certificate...")
    send_message(client_sock, server_hello.dict())
    
    print(f"[{client_addr}] Certificate exchange complete")
    return True


def handle_client(client_sock, client_addr):
    """Handle a single client connection."""
    print(f"\n[{client_addr}] New client connected")
    
    try:
        # STEP 1: Certificate exchange (BEFORE anything else)
        if not perform_certificate_exchange(client_sock, client_addr):
            print(f"[{client_addr}] Certificate verification failed. Closing connection.")
            client_sock.close()
            return
        
        print(f"\n[{client_addr}] " + "="*50)
        print(f"[{client_addr}] Certificate exchange complete. Ready for secure communication.")
        print(f"[{client_addr}] " + "="*50 + "\n")
        
        # TODO: Students implement remaining protocol steps:
        # - User registration/login
        # - DH key exchange
        # - AES encrypted messaging
        # - Message storage and retrieval
        
        print(f"[{client_addr}] Remaining protocol steps not yet implemented.")
        
    except Exception as e:
        print(f"[{client_addr}] Error: {e}")
    finally:
        client_sock.close()
        print(f"[{client_addr}] Connection closed")


def main():
    """Main server workflow."""
    HOST = '0.0.0.0'
    PORT = 8888
    
    print("="*60)
    print("SecureChat Server - Starting...")
    print("="*60)
    
    # Create server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)
    
    print(f"Server listening on {HOST}:{PORT}")
    print("Waiting for clients...\n")
    
    try:
        while True:
            # Accept new client connection
            client_sock, client_addr = server_sock.accept()
            
            # Handle client in a separate thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server_sock.close()
        print("Server stopped")


if __name__ == "__main__":
    main()
