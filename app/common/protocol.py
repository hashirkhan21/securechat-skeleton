"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel
from typing import Optional


class HelloMessage(BaseModel):
    """Client hello message with certificate."""
    type: str = "hello"
    client_cert: str
    nonce: str


class ServerHelloMessage(BaseModel):
    """Server hello response with certificate."""
    type: str = "server_hello"
    server_cert: str
    nonce: str


class DHClientMessage(BaseModel):
    """Diffie-Hellman client message with parameters and public key."""
    type: str = "dh_client"
    p: int
    g: int
    A: int


class DHServerMessage(BaseModel):
    """Diffie-Hellman server response with public key."""
    type: str = "dh_server"
    B: int


class RegisterMessage(BaseModel):
    """User registration message (encrypted)."""
    type: str = "register"
    encrypted_data: str  # base64 encoded encrypted payload


class LoginMessage(BaseModel):
    """User login message (encrypted)."""
    type: str = "login"
    encrypted_data: str  # base64 encoded encrypted payload


class RegisterResponse(BaseModel):
    """Registration response."""
    type: str = "register_response"
    success: bool
    message: str


class LoginResponse(BaseModel):
    """Login response."""
    type: str = "login_response"
    success: bool
    message: str
    username: Optional[str] = None


class ChatMessage(BaseModel):
    """Encrypted chat message."""
    type: str = "msg"
    ciphertext: str
    iv: str


class ReceiptMessage(BaseModel):
    """Message receipt confirmation."""
    type: str = "receipt"
    msg_id: str
