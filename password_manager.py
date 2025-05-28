#!/usr/bin/env python3
"""
Simple Password Manager
A secure password manager built with Python using encryption for data protection.
"""
import os
import json
import getpass
import hashlib
import secrets
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class PasswordManager:
    def __init__(self, data_file="passwords.enc"):
        self.data_file = data_file
        self.key = None
        self.passwords = {}

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def _get_salt(self) -> bytes:
        """Get or create salt for key derivation"""
        salt_file = "salt.key"
        if os.path.exists(salt_file):
            with open(salt_file, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(16)
            with open(salt_file, 'wb') as f:
                f.write(salt)
            return salt

    def authenticate(self) -> bool:
        """Authenticate user with master password"""
        salt = self._get_salt()
        master_password = getpass.getpass("Enter master password: ")
        self.key = self._derive_key(master_password, salt)

        if os.path.exists(self.data_file):
            try:
                self._load_passwords()
                return True
            except Exception:
                print("Invalid master password!")
                return False
        else:
            print("Creating new password vault...")
            self.passwords = {}
            self._save_passwords()
            return True

    def _load_passwords(self):
        """Load and decrypt passwords from file"""
        with open(self.data_file, 'rb') as f:
            encrypted_data = f.read()

        fernet = Fernet(self.key)
        decrypted_data = fernet.decrypt(encrypted_data)
        self.passwords = json.loads(decrypted_data.decode())

    def _save_passwords(self):
        """Encrypt and save passwords to file"""
        fernet = Fernet(self.key)
        data = json.dumps(self.passwords).encode()
        encrypted_data = fernet.encrypt(data)

        with open(self.data_file, 'wb') as f:
            f.write(encrypted_data)

    def generate_password(self, length=16, include_symbols=True) -> str:
        """Generate a secure random password"""
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password

    def add_password(self, service: str, username: str, password: str = None):
        """Add a new password entry"""
        if password is None:
            choice = input("Generate password? (y/n): ").lower()
            if choice == 'y':
                length = input("Password length (default 16): ")
                length = int(length) if length else 16
                symbols = input("Include symbols? (y/n): ").lower() == 'y'
                password = self.generate_password(length, symbols)
                print(f"Generated password: {password}")
            else:
                password = getpass.getpass("Enter password: ")

        self.passwords[service] = {
            'username': username,
            'password': password
        }
        self._save_passwords()
        print(f"Password for {service} saved successfully!")

    def get_password(self, service: str):
        """Retrieve password for a service"""
        if service in self.passwords:
            entry = self.passwords[service]
            print(f"Service: {service}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
        else:
            print(f"No password found for {service}")

    def list_services(self):
        """List all stored services"""
        if not self.passwords:
            print("No passwords stored yet.")
            return

        print("Stored services:")
        for i, service in enumerate(self.passwords.keys(), 1):
            print(f"{i}. {service}")

    def delete_password(self, service: str):
        """Delete a password entry"""
        if service in self.passwords:
            del self.passwords[service]
            self._save_passwords()
            print(f"Password for {service} deleted successfully!")
        else:
            print(f"No password found for {service}")

    def change_password(self, service: str):
        """Change password for a service"""
        if service in self.passwords:
            username = self.passwords[service]['username']
            choice = input("Generate new password? (y/n): ").lower()
            if choice == 'y':
                length = input("Password length (default 16): ")
                length = int(length) if length else 16
                symbols = input("Include symbols? (y/n): ").lower() == 'y'
                new_password = self.generate_password(length, symbols)
                print(f"Generated password: {new_password}")
            else:
                new_password = getpass.getpass("Enter new password: ")

            self.passwords[service]['password'] = new_password
            self._save_passwords()
            print(f"Password for {service} updated successfully!")
        else:
            print(f"No password found for {service}")


def main():
    pm = PasswordManager()

    print("=== Simple Password Manager ===")

    if not pm.authenticate():
        return

    while True:
        print("\nOptions:")
        print("1. Add password")
        print("2. Get password")
        print("3. List services")
        print("4. Change password")
        print("5. Delete password")
        print("6. Generate password")
        print("7. Exit")

        choice = input("\nSelect option (1-7): ").strip()

        if choice == '1':
            service = input("Service name: ")
            username = input("Username: ")
            pm.add_password(service, username)

        elif choice == '2':
            service = input("Service name: ")
            pm.get_password(service)

        elif choice == '3':
            pm.list_services()

        elif choice == '4':
            service = input("Service name: ")
            pm.change_password(service)

        elif choice == '5':
            service = input("Service name: ")
            confirm = input(f"Delete password for {service}? (y/n): ")
            if confirm.lower() == 'y':
                pm.delete_password(service)

        elif choice == '6':
            length = input("Password length (default 16): ")
            length = int(length) if length else 16
            symbols = input("Include symbols? (y/n): ").lower() == 'y'
            password = pm.generate_password(length, symbols)
            print(f"Generated password: {password}")

        elif choice == '7':
            print("Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()