"""
E2EE Encryption Module for Secure Messaging
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64
import os
import hashlib
import json
import secrets

class E2EEncryption:
    """End-to-End Encryption Handler"""
    
    def __init__(self):
        self.key_cache = {}
        self.salt_size = 16
        self.iterations = 100000
    
    def generate_key_pair(self, user_id, password):
        """
        Generate RSA key pair for user
        Returns: (public_key_pem, encrypted_private_key_pem)
        """
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Encrypt private key with user's password
        salt = os.urandom(self.salt_size)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        fernet = Fernet(key)
        encrypted_private = fernet.encrypt(private_key_pem.encode())
        
        return {
            'public_key': base64.b64encode(public_key_pem.encode()).decode(),
            'encrypted_private': base64.b64encode(encrypted_private).decode(),
            'salt': base64.b64encode(salt).decode(),
            'key_id': hashlib.sha256(public_key_pem.encode()).hexdigest()[:16]
        }
    
    def encrypt_message(self, message, receiver_public_key):
        """
        Encrypt message with receiver's public key
        """
        try:
            # Decode public key
            public_key_pem = base64.b64decode(receiver_public_key.encode()).decode()
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            
            # Generate random symmetric key for message
            message_key = Fernet.generate_key()
            fernet = Fernet(message_key)
            
            # Encrypt message with symmetric key
            encrypted_message = fernet.encrypt(message.encode())
            
            # Encrypt symmetric key with RSA public key
            encrypted_key = public_key.encrypt(
                message_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Combine encrypted key and message
            result = {
                'key': base64.b64encode(encrypted_key).decode(),
                'message': base64.b64encode(encrypted_message).decode(),
                'key_id': hashlib.sha256(public_key_pem.encode()).hexdigest()[:16]
            }
            
            return base64.b64encode(json.dumps(result).encode()).decode()
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_message(self, encrypted_package, private_key_encrypted, password, salt):
        """
        Decrypt message with private key
        """
        try:
            # Decode package
            package = json.loads(base64.b64decode(encrypted_package).decode())
            
            # Derive key from password to decrypt private key
            salt_bytes = base64.b64decode(salt.encode())
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=self.iterations,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Decrypt private key
            fernet = Fernet(key)
            private_key_pem = fernet.decrypt(
                base64.b64decode(private_key_encrypted.encode())
            ).decode()
            
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
            
            # Decrypt symmetric key
            encrypted_key = base64.b64decode(package['key'].encode())
            message_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message
            fernet = Fernet(message_key)
            decrypted = fernet.decrypt(
                base64.b64decode(package['message'].encode())
            )
            
            return decrypted.decode()
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def generate_chat_id(self, user1_uid, user2_uid):
        """
        Generate unique E2EE chat ID
        """
        # Sort UIDs to ensure same chat ID regardless of order
        sorted_uids = sorted([user1_uid, user2_uid])
        combined = f"{sorted_uids[0]}:{sorted_uids[1]}:{secrets.token_hex(8)}"
        
        # Create hash
        chat_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        # Format: E2EE_ + timestamp + hash
        timestamp = int(datetime.utcnow().timestamp())
        return f"E2EE_{timestamp}_{chat_hash[:20]}"
    
    def sign_message(self, message, private_key_encrypted, password, salt):
        """
        Sign message with private key
        """
        try:
            # Decrypt private key
            salt_bytes = base64.b64decode(salt.encode())
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=self.iterations,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            fernet = Fernet(key)
            private_key_pem = fernet.decrypt(
                base64.b64decode(private_key_encrypted.encode())
            ).decode()
            
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
            
            # Sign message
            signature = private_key.sign(
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode()
            
        except Exception as e:
            raise Exception(f"Signing failed: {str(e)}")
    
    def verify_signature(self, message, signature, sender_public_key):
        """
        Verify message signature
        """
        try:
            # Decode public key
            public_key_pem = base64.b64decode(sender_public_key.encode()).decode()
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            
            # Verify signature
            signature_bytes = base64.b64decode(signature.encode())
            
            public_key.verify(
                signature_bytes,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception:
            return False
    
    def encrypt_file(self, file_data, receiver_public_key):
        """
        Encrypt file for secure transfer
        """
        try:
            # Generate file key
            file_key = Fernet.generate_key()
            fernet = Fernet(file_key)
            
            # Encrypt file
            encrypted_file = fernet.encrypt(file_data)
            
            # Encrypt file key with receiver's public key
            public_key_pem = base64.b64decode(receiver_public_key.encode()).decode()
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            
            encrypted_key = public_key.encrypt(
                file_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Return encrypted package
            result = {
                'file': base64.b64encode(encrypted_file).decode(),
                'key': base64.b64encode(encrypted_key).decode()
            }
            
            return base64.b64encode(json.dumps(result).encode()).decode()
            
        except Exception as e:
            raise Exception(f"File encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_package, private_key_encrypted, password, salt):
        """
        Decrypt received file
        """
        try:
            # Decode package
            package = json.loads(base64.b64decode(encrypted_package).decode())
            
            # Decrypt private key
            salt_bytes = base64.b64decode(salt.encode())
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=self.iterations,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            fernet = Fernet(key)
            private_key_pem = fernet.decrypt(
                base64.b64decode(private_key_encrypted.encode())
            ).decode()
            
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
            
            # Decrypt file key
            encrypted_key = base64.b64decode(package['key'].encode())
            file_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt file
            fernet = Fernet(file_key)
            decrypted_file = fernet.decrypt(
                base64.b64decode(package['file'].encode())
            )
            
            return decrypted_file
            
        except Exception as e:
            raise Exception(f"File decryption failed: {str(e)}")

# Global encryption instance
e2ee = E2EEncryption()
