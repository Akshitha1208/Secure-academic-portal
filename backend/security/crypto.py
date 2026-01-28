"""
Cryptography Manager
Implements all cryptographic operations

Features:
1. RSA key pair generation (2048-bit)
2. AES-256 encryption/decryption
3. RSA encryption/decryption for key exchange
4. Digital signatures using RSA
5. SHA-256 hashing for file integrity
6. Base64 encoding/decoding
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import hashlib
import base64


class CryptoManager:
    
    
    def __init__(self):
        self.rsa_key_size = 2048
        self.aes_key_size = 32  # 256 bits
    
    # ==================== RSA KEY MANAGEMENT ====================
    
    def generate_rsa_keypair(self):
        """
        Generate RSA-2048 key pair
        
        Returns:
            tuple: (private_key_pem, public_key_pem)
        """
        # Generate RSA key pair
        key = RSA.generate(self.rsa_key_size)
        
        # Export private key
        private_key_pem = key.export_key('PEM').decode('utf-8')
        
        # Export public key
        public_key_pem = key.publickey().export_key('PEM').decode('utf-8')
        
        return private_key_pem, public_key_pem
    
    # ==================== AES ENCRYPTION ====================
    
    def generate_aes_key(self):
        """
        Generate AES-256 key
        
        Returns:
            bytes: 256-bit AES key
        """
        return get_random_bytes(self.aes_key_size)
    
    def encrypt_aes(self, data, key):
        """
        Encrypt data using AES-256 in CBC mode
        
        Args:
            data (bytes): Data to encrypt
            key (bytes): AES key
            
        Returns:
            tuple: (encrypted_data, iv)
        """
        # Create AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC)
        
        # Pad data to multiple of 16 bytes
        padded_data = self._pad(data)
        
        # Encrypt
        encrypted_data = cipher.encrypt(padded_data)
        
        return encrypted_data, cipher.iv
    
    def decrypt_aes(self, encrypted_data, key, iv):
        """
        Decrypt data using AES-256
        
        Args:
            encrypted_data (bytes): Encrypted data
            key (bytes): AES key
            iv (bytes): Initialization vector
            
        Returns:
            bytes: Decrypted data
        """
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt
        decrypted_padded = cipher.decrypt(encrypted_data)
        
        # Remove padding
        decrypted_data = self._unpad(decrypted_padded)
        
        return decrypted_data
    
    def _pad(self, data):
        """PKCS7 padding"""
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)
    
    def _unpad(self, data):
        """Remove PKCS7 padding"""
        padding_length = data[-1]
        return data[:-padding_length]
    
    # ==================== RSA ENCRYPTION (KEY EXCHANGE) ====================
    
    def encrypt_rsa(self, data, public_key_pem):
        """
        Encrypt data using RSA public key (for key exchange)
        
        Args:
            data (bytes): Data to encrypt (typically AES key)
            public_key_pem (str): Public key in PEM format
            
        Returns:
            bytes: Encrypted data
        """
        # Import public key
        public_key = RSA.import_key(public_key_pem)
        
        # Create cipher
        cipher = PKCS1_OAEP.new(public_key)
        
        # Encrypt
        encrypted_data = cipher.encrypt(data)
        
        return encrypted_data
    
    def decrypt_rsa(self, encrypted_data, private_key_pem):
        """
        Decrypt data using RSA private key
        
        Args:
            encrypted_data (bytes): Encrypted data
            private_key_pem (str): Private key in PEM format
            
        Returns:
            bytes: Decrypted data
        """
        # Import private key
        private_key = RSA.import_key(private_key_pem)
        
        # Create cipher
        cipher = PKCS1_OAEP.new(private_key)
        
        # Decrypt
        decrypted_data = cipher.decrypt(encrypted_data)
        
        return decrypted_data
    
    # ==================== DIGITAL SIGNATURES ====================
    
    def sign_data(self, data, private_key_pem):
        """
        Create digital signature
        Process: Hash data -> Encrypt hash with private key
        
        Args:
            data (bytes): Data to sign
            private_key_pem (str): Private key in PEM format
            
        Returns:
            bytes: Digital signature
        """
        # Import private key
        private_key = RSA.import_key(private_key_pem)
        
        # Create hash of data
        hash_obj = SHA256.new(data)
        
        # Sign hash
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        
        return signature
    
    def verify_signature(self, data, signature, public_key_pem):
        """
        Verify digital signature
        Process: Decrypt signature with public key -> Compare with hash
        
        Args:
            data (bytes): Original data
            signature (bytes): Digital signature
            public_key_pem (str): Public key in PEM format
            
        Returns:
            bool: True if signature is valid
        """
        try:
            # Import public key
            public_key = RSA.import_key(public_key_pem)
            
            # Create hash of data
            hash_obj = SHA256.new(data)
            
            # Verify signature
            pkcs1_15.new(public_key).verify(hash_obj, signature)
            
            return True
        except (ValueError, TypeError):
            return False
    
    # ==================== HASHING ====================
    
    def calculate_hash(self, data):
        """
        Calculate SHA-256 hash of data
        Used for file integrity verification
        
        Args:
            data (bytes): Data to hash
            
        Returns:
            str: Hex digest of hash
        """
        hash_obj = hashlib.sha256(data)
        return hash_obj.hexdigest()
    
    def calculate_hash_with_salt(self, data, salt):
        """
        Calculate SHA-256 hash with salt
        
        Args:
            data (bytes): Data to hash
            salt (str): Salt
            
        Returns:
            str: Hex digest of hash
        """
        salted_data = data + salt.encode('utf-8')
        hash_obj = hashlib.sha256(salted_data)
        return hash_obj.hexdigest()
    
    # ==================== ENCODING ====================
    
    def encode_base64(self, data):
        """
        Base64 encode data
        
        Args:
            data (bytes): Data to encode
            
        Returns:
            str: Base64 encoded string
        """
        return base64.b64encode(data).decode('utf-8')
    
    def decode_base64(self, encoded_data):
        """
        Base64 decode data
        
        Args:
            encoded_data (str): Base64 encoded string
            
        Returns:
            bytes: Decoded data
        """
        return base64.b64decode(encoded_data)
