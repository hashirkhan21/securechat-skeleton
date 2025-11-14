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


class RegisterMessage(BaseModel):
    """User registration message."""
    type: str = "register"
    username: str
    password: str


class LoginMessage(BaseModel):
    """User login message."""
    type: str = "login"
    username: str
    password: str


class DHClientMessage(BaseModel):
    """Diffie-Hellman client public key."""
    type: str = "dh_client"
    public_key: str


class DHServerMessage(BaseModel):
    """Diffie-Hellman server public key."""
    type: str = "dh_server"
    public_key: str


class ChatMessage(BaseModel):
    """Encrypted chat message."""
    type: str = "msg"
    ciphertext: str
    iv: str


class ReceiptMessage(BaseModel):
    """Message receipt confirmation."""
    type: str = "receipt"
    msg_id: str
