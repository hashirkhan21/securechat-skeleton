"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import sys

from app.common.protocol import (
    HelloMessage, ServerHelloMessage,
    DHClientMessage, DHServerMessage,
    RegisterMessage, RegisterResponse,
    LoginMessage, LoginResponse
)
from app.common.utils import b64e, b64d
from app.crypto.pki import load_own_cert, verify_cert, verify_expiry, get_cn
from app.crypto.dh import dh_generate_private, dh_generate_public, dh_compute_shared, get_dh_parameters
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import load_private_key
from app.common.message_utils import (
    make_msg, verify_and_decrypt, append_transcript_line,
    compute_transcript_hash, make_session_receipt,
    log_message_sent, log_message_received, log_verification_failure,
    load_cert_from_pem
)
import threading


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
    print("="*60)
    print("STEP 1: Certificate Exchange")
    print("="*60)
    
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
    print("→ Sending client certificate...")
    send_message(sock, hello_msg.model_dump())
    
    # Receive server hello with server certificate
    print("← Waiting for server certificate...")
    try:
        server_hello_data = receive_message(sock)
        server_hello = ServerHelloMessage(**server_hello_data)
    except Exception as e:
        print(f"BAD CERT: Failed to receive server hello: {e}")
        return False
    
    print("← Received certificate from server")
    
    # Verify server certificate
    try:
        # Verify CA signature
        server_cert = verify_cert(server_hello.server_cert)
        print("  ✓ Certificate signature verified")
        
        # Verify expiry
        verify_expiry(server_cert)
        print("  ✓ Certificate validity period verified")
        
        # Verify CN is "server"
        cn = get_cn(server_cert)
        if cn != "server":
            print(f"BAD CERT: wrong CN (expected 'server', got '{cn}')")
            return False
        print(f"  ✓ Certificate CN verified: {cn}")
        
    except ValueError as e:
        print(f"BAD CERT: {e}")
        return False
    except Exception as e:
        print(f"BAD CERT: invalid signature or format: {e}")
        return False
    
    print("✓ Certificate verified successfully\n")
    return True


def perform_dh_exchange(sock):
    """
    Perform Diffie-Hellman key exchange.
    Returns AES key if successful, None otherwise.
    """
    print("="*60)
    print("STEP 2: Diffie-Hellman Key Exchange")
    print("="*60)
    
    try:
        # Get DH parameters
        p, g = get_dh_parameters()
        print(f"Using DH parameters: p (2048-bit), g = {g}")
        
        # Generate client's private key
        a = dh_generate_private()
        print("→ Generated client private key (256-bit)")
        
        # Compute client's public key A = g^a mod p
        A = dh_generate_public(g, p, a)
        print(f"→ Computed client public key A")
        
        # Send DH client message
        dh_client_msg = DHClientMessage(p=p, g=g, A=A)
        print("→ Sending DH parameters and public key to server...")
        send_message(sock, dh_client_msg.model_dump())
        
        # Receive DH server message
        print("← Waiting for server's public key...")
        dh_server_data = receive_message(sock)
        dh_server = DHServerMessage(**dh_server_data)
        B = dh_server.B
        print(f"← Received server public key B")
        
        # Compute shared secret and derive AES key
        aes_key = dh_compute_shared(B, a, p)
        print("✓ Computed shared secret Ks")
        print("✓ Derived AES key: first 16 bytes of SHA256(Ks)")
        print(f"  AES Key: {aes_key.hex()[:32]}...\n")
        
        return aes_key
        
    except Exception as e:
        print(f"✗ DH exchange failed: {e}")
        return None


def register_user(sock, aes_key):
    """Register a new user with encrypted credentials."""
    print("="*60)
    print("STEP 3: User Registration")
    print("="*60)
    
    email = input("Enter email: ")
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    # Prepare registration data
    reg_data = json.dumps({
        "email": email,
        "username": username,
        "password": password
    }).encode('utf-8')
    
    print("\n→ Encrypting credentials with AES-128 CBC...")
    encrypted_data = aes_encrypt(aes_key, reg_data)
    encrypted_b64 = b64e(encrypted_data)
    
    # Send registration message
    reg_msg = RegisterMessage(encrypted_data=encrypted_b64)
    print("→ Sending encrypted registration data...")
    send_message(sock, reg_msg.model_dump())
    
    # Receive response
    print("← Waiting for registration response...")
    response_data = receive_message(sock)
    response = RegisterResponse(**response_data)
    
    if response.success:
        print(f"✓ {response.message}\n")
        return True
    else:
        print(f"✗ {response.message}\n")
        return False


def login_user(sock, aes_key):
    """Login with existing credentials."""
    print("="*60)
    print("STEP 3: User Login")
    print("="*60)
    
    email = input("Enter email: ")
    password = input("Enter password: ")
    
    # Prepare login data
    login_data = json.dumps({
        "email": email,
        "password": password
    }).encode('utf-8')
    
    print("\n→ Encrypting credentials with AES-128 CBC...")
    encrypted_data = aes_encrypt(aes_key, login_data)
    encrypted_b64 = b64e(encrypted_data)
    
    # Send login message
    login_msg = LoginMessage(encrypted_data=encrypted_b64)
    print("→ Sending encrypted login data...")
    send_message(sock, login_msg.model_dump())
    
    # Receive response
    print("← Waiting for login response...")
    response_data = receive_message(sock)
    response = LoginResponse(**response_data)
    
    if response.success:
        print(f"✓ {response.message}")
        print(f"  Welcome, {response.username}!\n")
        return True, response.username
    else:
        print(f"✗ {response.message}\n")
        return False, None


def start_messaging(sock, aes_key, username):
    """
    Start secure messaging session.
    Implements Step 4: Signed encrypted messages with transcript.
    """
    print("="*60)
    print("STEP 4: Secure Messaging")
    print("="*60)
    print("Type messages to send. Type '/quit' to exit.\n")
    
    # Load client private key and server certificate
    try:
        client_priv_key = load_private_key("certs/client.key")
        server_cert_pem = load_own_cert("server")  # We received this during handshake
        # Actually, we need to store it from the handshake - for now load from file
        server_cert = verify_cert(server_cert_pem)
    except Exception as e:
        print(f"✗ Failed to load keys/certificates: {e}")
        return
    
    # Initialize sequence numbers
    send_seqno = 1
    recv_seqno = 1
    
    # Transcript file
    transcript_path = f"transcripts/client_session_{username}.txt"
    
    # Flag to control receive thread
    running = True
    
    def receive_messages():
        """Background thread to receive messages."""
        nonlocal recv_seqno, running
        
        while running:
            try:
                # Set timeout so we can check running flag
                sock.settimeout(0.5)
                msg_data = receive_message(sock)
                
                if msg_data.get('type') == 'msg':
                    print("\n" + "="*60)
                    print(f"← Incoming Message")
                    print("="*60)
                    
                    # Verify and decrypt
                    ok, result, new_seqno = verify_and_decrypt(
                        msg_data, aes_key, server_cert, recv_seqno
                    )
                    
                    if ok:
                        plaintext = result.decode('utf-8')
                        log_message_received(msg_data['seqno'], plaintext)
                        recv_seqno = new_seqno
                        
                        # Append to transcript
                        append_transcript_line(
                            transcript_path,
                            msg_data['seqno'],
                            msg_data['ts'],
                            msg_data['ct'],
                            msg_data['sig'],
                            server_cert
                        )
                        print(f"\n{plaintext}\n")
                        print("Type your message (or /quit to exit):")
                    else:
                        log_verification_failure(result)
                        if result == "REPLAY":
                            print("  ✗ REPLAY attack detected!")
                        elif result == "SIG FAIL":
                            print("  ✗ SIG FAIL: Signature verification failed!")
                        else:
                            print(f"  ✗ {result}")
                        
            except socket.timeout:
                continue
            except Exception as e:
                if running:
                    print(f"\n✗ Error receiving message: {e}")
                break
    
    # Start receive thread
    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()
    
    try:
        while True:
            # Get user input
            user_input = input()
            
            if user_input.strip() == '/quit':
                print("\nEnding session...")
                running = False
                break
            
            if not user_input.strip():
                continue
            
            # Create and send message
            print("\n" + "="*60)
            print(f"→ Sending Message #{send_seqno}")
            print("="*60)
            
            plaintext = user_input.encode('utf-8')
            msg_json = make_msg(send_seqno, plaintext, aes_key, client_priv_key)
            
            # Send message
            sock.sendall(msg_json.encode('utf-8') + b'\n')
            
            # Parse to get details for transcript
            msg_dict = json.loads(msg_json)
            
            log_message_sent(send_seqno, user_input)
            
            # Append to transcript
            append_transcript_line(
                transcript_path,
                msg_dict['seqno'],
                msg_dict['ts'],
                msg_dict['ct'],
                msg_dict['sig'],
                server_cert
            )
            
            send_seqno += 1
            print()
            
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        running = False
    finally:
        running = False
        
        # Generate session receipt
        try:
            print("\n" + "="*60)
            print("Generating Session Receipt")
            print("="*60)
            
            receipt = make_session_receipt(transcript_path, client_priv_key, "server")
            print(f"✓ Transcript hash: {receipt['transcript_hash'][:32]}...")
            print(f"✓ Receipt signature generated")
            print(f"✓ Transcript saved to: {transcript_path}\n")
        except Exception as e:
            print(f"✗ Failed to generate receipt: {e}\n")


def main():
    """Main client workflow."""
    HOST = '127.0.0.1'
    PORT = 8888
    
    print("\n" + "="*60)
    print("SecureChat Client")
    print("="*60 + "\n")
    
    print(f"Connecting to server at {HOST}:{PORT}...\n")
    
    try:
        # Create socket and connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        print("✓ Connected to server\n")
        
        # STEP 1: Certificate exchange (BEFORE anything else)
        if not perform_certificate_exchange(sock):
            print("Certificate verification failed. Closing connection.")
            sock.close()
            return
        
        # STEP 2: DH key exchange (BEFORE registration/login)
        aes_key = perform_dh_exchange(sock)
        if not aes_key:
            print("DH key exchange failed. Closing connection.")
            sock.close()
            return
        
        # STEP 3: Registration or Login
        action = input("Choose action: (r)egister or (l)ogin? ").lower().strip()
        
        if action == 'r':
            success = register_user(sock, aes_key)
            if not success:
                sock.close()
                return
        elif action == 'l':
            success, username = login_user(sock, aes_key)
            if not success:
                sock.close()
                return
        else:
            print("Invalid action. Closing connection.")
            sock.close()
            return
        
        # STEP 4: Secure Messaging
        start_messaging(sock, aes_key, username if action == 'l' else "user")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if 'sock' in locals():
            sock.close()
            print("Connection closed")


if __name__ == "__main__":
    main()
