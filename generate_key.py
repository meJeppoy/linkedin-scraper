from cryptography.fernet import Fernet

def generate_key():
    """Generate a valid Fernet key and print it."""
    key = Fernet.generate_key()
    print("\nYour generated Fernet key:")
    print(key.decode())

if __name__ == "__main__":
    generate_key()

import os
salt = os.urandom(16).hex()
print(salt)  # Copy this value into your .env file