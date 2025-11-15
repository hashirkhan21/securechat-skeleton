"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import sys
import threading

from app.common.protocol import (
    HelloMessage, ServerHelloMessage,
    DHClientMessage, DHServerMessage,
    RegisterMessage, RegisterResponse,
    LoginMessage, LoginResponse
)
from app.common.utils import b64e, b64d
from app.crypto.pki import load_own_cert, verify_cert, verify_expiry, get_cn
from app.crypto.dh import dh_generate_private, dh_generate_public, dh_compute_shared
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.storage.db import register_user, login_user


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
    print(f"[{client_addr}] " + "="*50)
    print(f"[{client_addr}] STEP 1: Certificate Exchange")
    print(f"[{client_addr}] " + "="*50)
    
    # Receive client hello with certificate
    print(f"[{client_addr}] ← Waiting for client certificate...")
    try:
        hello_data = receive_message(client_sock)
        hello_msg = HelloMessage(**hello_data)
    except Exception as e:
        print(f"[{client_addr}] BAD CERT: Failed to receive client hello: {e}")
        return False
    
    print(f"[{client_addr}] ← Received certificate from client")
    
    # Verify client certificate
    try:
        # Verify CA signature
        client_cert = verify_cert(hello_msg.client_cert)
        print(f"[{client_addr}]   ✓ Certificate signature verified")
        
        # Verify expiry
        verify_expiry(client_cert)
        print(f"[{client_addr}]   ✓ Certificate validity period verified")
        
        # Verify CN is "client"
        cn = get_cn(client_cert)
        if cn != "client":
            print(f"[{client_addr}] BAD CERT: wrong CN (expected 'client', got '{cn}')")
            return False
        print(f"[{client_addr}]   ✓ Certificate CN verified: {cn}")
        
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
    print(f"[{client_addr}] → Sending server certificate...")
    send_message(client_sock, server_hello.model_dump())
    
    print(f"[{client_addr}] ✓ Certificate exchange complete\n")
    return True


def perform_dh_exchange(client_sock, client_addr):
    """
    Perform Diffie-Hellman key exchange.
    Returns AES key if successful, None otherwise.
    """
    print(f"[{client_addr}] " + "="*50)
    print(f"[{client_addr}] STEP 2: Diffie-Hellman Key Exchange")
    print(f"[{client_addr}] " + "="*50)
    
    try:
        # Receive DH client message with p, g, A
        print(f"[{client_addr}] ← Waiting for client DH parameters...")
        dh_client_data = receive_message(client_sock)
        dh_client = DHClientMessage(**dh_client_data)
        
        p = dh_client.p
        g = dh_client.g
        A = dh_client.A
        
        print(f"[{client_addr}] ← Received DH parameters: p (2048-bit), g = {g}")
        print(f"[{client_addr}] ← Received client public key A")
        
        # Generate server's private key
        b = dh_generate_private()
        print(f"[{client_addr}] → Generated server private key (256-bit)")
        
        # Compute server's public key B = g^b mod p
        B = dh_generate_public(g, p, b)
        print(f"[{client_addr}] → Computed server public key B")
        
        # Send DH server message
        dh_server_msg = DHServerMessage(B=B)
        print(f"[{client_addr}] → Sending server public key...")
        send_message(client_sock, dh_server_msg.model_dump())
        
        # Compute shared secret and derive AES key
        aes_key = dh_compute_shared(A, b, p)
        print(f"[{client_addr}] ✓ Computed shared secret Ks")
        print(f"[{client_addr}] ✓ Derived AES key: first 16 bytes of SHA256(Ks)")
        print(f"[{client_addr}]   AES Key: {aes_key.hex()[:32]}...\n")
        
        return aes_key
        
    except Exception as e:
        print(f"[{client_addr}] ✗ DH exchange failed: {e}")
        return None


def handle_registration(client_sock, client_addr, aes_key):
    """Handle user registration with encrypted credentials."""
    print(f"[{client_addr}] " + "="*50)
    print(f"[{client_addr}] STEP 3: User Registration")
    print(f"[{client_addr}] " + "="*50)
    
    try:
        # The registration message was already received by the caller
        # We need to receive it here
        print(f"[{client_addr}] ← Receiving encrypted registration data...")
        reg_data = receive_message(client_sock)
        reg_msg = RegisterMessage(**reg_data)
        
        # Decrypt registration data
        print(f"[{client_addr}] → Decrypting credentials...")
        encrypted_bytes = b64d(reg_msg.encrypted_data)
        decrypted_data = aes_decrypt(aes_key, encrypted_bytes)
        credentials = json.loads(decrypted_data.decode('utf-8'))
        
        email = credentials['email']
        username = credentials['username']
        password = credentials['password']
        
        print(f"[{client_addr}]   Email: {email}")
        print(f"[{client_addr}]   Username: {username}")
        
        # Register user in database
        print(f"[{client_addr}] → Registering user in database...")
        success, message = register_user(email, username, password)
        
        # Send response
        response = RegisterResponse(success=success, message=message)
        send_message(client_sock, response.model_dump())
        
        if success:
            print(f"[{client_addr}] ✓ {message}\n")
        else:
            print(f"[{client_addr}] ✗ {message}\n")
        
        return success
        
    except Exception as e:
        print(f"[{client_addr}] ✗ Registration failed: {e}")
        response = RegisterResponse(success=False, message=f"Registration error: {e}")
        send_message(client_sock, response.model_dump())
        return False


def handle_login(client_sock, client_addr, aes_key):
    """Handle user login with encrypted credentials."""
    print(f"[{client_addr}] " + "="*50)
    print(f"[{client_addr}] STEP 3: User Login")
    print(f"[{client_addr}] " + "="*50)
    
    try:
        # Receive login message
        print(f"[{client_addr}] ← Receiving encrypted login data...")
        login_data = receive_message(client_sock)
        login_msg = LoginMessage(**login_data)
        
        # Decrypt login data
        print(f"[{client_addr}] → Decrypting credentials...")
        encrypted_bytes = b64d(login_msg.encrypted_data)
        decrypted_data = aes_decrypt(aes_key, encrypted_bytes)
        credentials = json.loads(decrypted_data.decode('utf-8'))
        
        email = credentials['email']
        password = credentials['password']
        
        print(f"[{client_addr}]   Email: {email}")
        
        # Verify login credentials
        print(f"[{client_addr}] → Verifying credentials...")
        success, message, username = login_user(email, password)
        
        # Send response
        response = LoginResponse(success=success, message=message, username=username)
        send_message(client_sock, response.model_dump())
        
        if success:
            print(f"[{client_addr}] ✓ {message} - User: {username}\n")
        else:
            print(f"[{client_addr}] ✗ {message}\n")
        
        return success, username
        
    except Exception as e:
        print(f"[{client_addr}] ✗ Login failed: {e}")
        response = LoginResponse(success=False, message=f"Login error: {e}", username=None)
        send_message(client_sock, response.model_dump())
        return False, None


def handle_client(client_sock, client_addr):
    """Handle a single client connection."""
    print(f"\n[{client_addr}] ========================================")
    print(f"[{client_addr}] New client connected")
    print(f"[{client_addr}] ========================================\n")
    
    try:
        # STEP 1: Certificate exchange (BEFORE anything else)
        if not perform_certificate_exchange(client_sock, client_addr):
            print(f"[{client_addr}] Certificate verification failed. Closing connection.")
            client_sock.close()
            return
        
        # STEP 2: DH key exchange (BEFORE registration/login)
        aes_key = perform_dh_exchange(client_sock, client_addr)
        if not aes_key:
            print(f"[{client_addr}] DH key exchange failed. Closing connection.")
            client_sock.close()
            return
        
        # STEP 3: Handle registration or login
        # Wait for first message to determine action
        first_msg = receive_message(client_sock)
        msg_type = first_msg.get('type')
        
        if msg_type == 'register':
            # Put the message back by creating the RegisterMessage directly
            reg_msg = RegisterMessage(**first_msg)
            
            # Decrypt and register
            encrypted_bytes = b64d(reg_msg.encrypted_data)
            decrypted_data = aes_decrypt(aes_key, encrypted_bytes)
            credentials = json.loads(decrypted_data.decode('utf-8'))
            
            email = credentials['email']
            username = credentials['username']
            password = credentials['password']
            
            print(f"[{client_addr}] " + "="*50)
            print(f"[{client_addr}] STEP 3: User Registration")
            print(f"[{client_addr}] " + "="*50)
            print(f"[{client_addr}] ← Received encrypted registration data")
            print(f"[{client_addr}] → Decrypting credentials...")
            print(f"[{client_addr}]   Email: {email}")
            print(f"[{client_addr}]   Username: {username}")
            
            print(f"[{client_addr}] → Registering user in database...")
            success, message = register_user(email, username, password)
            
            response = RegisterResponse(success=success, message=message)
            send_message(client_sock, response.model_dump())
            
            if success:
                print(f"[{client_addr}] ✓ {message}\n")
            else:
                print(f"[{client_addr}] ✗ {message}\n")
                
        elif msg_type == 'login':
            login_msg = LoginMessage(**first_msg)
            
            # Decrypt and login
            encrypted_bytes = b64d(login_msg.encrypted_data)
            decrypted_data = aes_decrypt(aes_key, encrypted_bytes)
            credentials = json.loads(decrypted_data.decode('utf-8'))
            
            email = credentials['email']
            password = credentials['password']
            
            print(f"[{client_addr}] " + "="*50)
            print(f"[{client_addr}] STEP 3: User Login")
            print(f"[{client_addr}] " + "="*50)
            print(f"[{client_addr}] ← Received encrypted login data")
            print(f"[{client_addr}] → Decrypting credentials...")
            print(f"[{client_addr}]   Email: {email}")
            
            print(f"[{client_addr}] → Verifying credentials...")
            success, message, username = login_user(email, password)
            
            response = LoginResponse(success=success, message=message, username=username)
            send_message(client_sock, response.model_dump())
            
            if success:
                print(f"[{client_addr}] ✓ {message} - User: {username}\n")
            else:
                print(f"[{client_addr}] ✗ {message}\n")
        else:
            print(f"[{client_addr}] Unknown message type: {msg_type}")
            return
        
        print(f"[{client_addr}] " + "="*50)
        print(f"[{client_addr}] Ready for secure messaging (not yet implemented)")
        print(f"[{client_addr}] " + "="*50 + "\n")
        
        # TODO: Step 4 - Handle encrypted messaging
        
    except Exception as e:
        print(f"[{client_addr}] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client_sock.close()
        print(f"[{client_addr}] Connection closed\n")


def main():
    """Main server workflow."""
    HOST = '0.0.0.0'
    PORT = 8888
    
    print("\n" + "="*60)
    print("SecureChat Server - Starting...")
    print("="*60)
    print("Make sure MySQL is running and database is initialized!")
    print("Run: python -c 'from app.storage.db import init_database; init_database()'")
    print("="*60 + "\n")
    
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
