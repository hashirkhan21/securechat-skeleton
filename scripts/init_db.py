#!/usr/bin/env python3
"""
Initialize MySQL database for SecureChat
Creates the database and users table
"""

import sys
sys.path.insert(0, '.')

from app.storage.db import init_database

if __name__ == "__main__":
    print("Initializing SecureChat database...")
    print("Note: Make sure MySQL is running and credentials in app/storage/db.py are correct")
    print()
    
    try:
        init_database()
        print("\n✓ Database initialization complete!")
        print("  Database: securechat")
        print("  Table: users (id, email, username, salt, pwd_hash, created_at)")
    except Exception as e:
        print(f"\n✗ Database initialization failed: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure MySQL is running")
        print("2. Update credentials in app/storage/db.py")
        print("3. Check that you have permissions to create databases")
        sys.exit(1)

