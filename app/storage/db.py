"""MySQL users table + salted hashing (no chat storage)."""

import mysql.connector
import hashlib
import os


def get_db_connection():
    """
    Get MySQL database connection.
    Configure these settings for your MySQL instance.
    """
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="1234",  # Update with your MySQL password
        database="securechat",
        autocommit=False
    )


def init_database():
    """
    Initialize the database and users table.
    Call this once to set up the database.
    """
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="1234",  # Update with your MySQL password
        autocommit=True
    )
    cursor = conn.cursor()
    
    # Create database if not exists
    cursor.execute("CREATE DATABASE IF NOT EXISTS securechat")
    cursor.execute("USE securechat")
    
    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash VARBINARY(32) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    """)
    
    conn.close()
    print("Database initialized successfully")


def hash_password(salt, password):
    """Compute SHA256(salt || password)."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    return hashlib.sha256(salt + password).digest()


def register_user(email, username, password):
    """
    Register a new user with salted password hash.
    Returns: (success: bool, message: str)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Generate 16-byte salt
        salt = os.urandom(16)
        
        # Compute SHA256(salt || password)
        pwd_hash = hash_password(salt, password)
        
        # Insert into database
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return True, "Registration successful"
        
    except mysql.connector.IntegrityError as e:
        if "email" in str(e):
            return False, "Email already exists"
        elif "username" in str(e):
            return False, "Username already exists"
        else:
            return False, f"Registration failed: {e}"
    except Exception as e:
        return False, f"Database error: {e}"


def login_user(email, password):
    """
    Verify user login credentials.
    Returns: (success: bool, message: str, username: str or None)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Retrieve salt and pwd_hash for email
        cursor.execute(
            "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
            (email,)
        )
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if not result:
            return False, "Invalid email or password", None
        
        username, salt, stored_hash = result
        
        # Compute SHA256(salt || password) and compare
        computed_hash = hash_password(salt, password)
        
        if computed_hash == stored_hash:
            return True, "Login successful", username
        else:
            return False, "Invalid email or password", None
            
    except Exception as e:
        return False, f"Database error: {e}", None
