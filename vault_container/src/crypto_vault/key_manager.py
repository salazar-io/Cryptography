# src/crypto_vault/key_manager.py
# Clase key_manager para generar y cargar llaves
# Version 2.0 con soporte para ECIES

import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class KeyManager:
    ITERATIONS = 600000  # Recomendado por OWASP/NIST para PBKDF2-SHA256

    @staticmethod
    def _derive_kek(password: str, salt: bytes) -> bytes:
        """Deriva una Key Encryption Key (KEK) usando PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KeyManager.ITERATIONS,
        )
        return kdf.derive(password.encode())

    @staticmethod
    def generate_key_file(path: str, password: str) -> bytes:
        """
        Genera una Master Key (MK) de 256 bits, la cifra con una KEK 
        derivada de la contraseña y la guarda en un archivo JSON.
        """
        master_key = os.urandom(32)  # La clave real que cifra los archivos
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        # Derivar KEK y cifrar la MK
        kek = KeyManager._derive_kek(password, salt)
        aesgcm = AESGCM(kek)
        
        # Los metadatos de la llave (vacíos por ahora, pero protegidos por AAD)
        aad = b"key_protection_v1"
        encrypted_mk_with_tag = aesgcm.encrypt(nonce, master_key, aad)
        
        # Estructura del archivo de llave
        key_data = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "iterations": KeyManager.ITERATIONS,
            "encrypted_mk": base64.b64encode(encrypted_mk_with_tag).decode('utf-8'),
            "aad": base64.b64encode(aad).decode('utf-8')
        }
        
        with open(path, "w") as f:
            json.dump(key_data, f, indent=4)
            
        return master_key

    @staticmethod
    def load_key_file(path: str, password: str) -> bytes:
        """
        Carga el archivo JSON, deriva la KEK con la contraseña y 
        descifra la Master Key.
        """
        try:
            with open(path, "r") as f:
                key_data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError(f"El archivo de llave '{path}' no tiene el formato esperado (JSON). "
                             "Probablemente sea una llave antigua o incompatible. "
                             "Por favor, elimina el archivo y genera una llave nueva.")
            
        salt = base64.b64decode(key_data["salt"])
        nonce = base64.b64decode(key_data["nonce"])
        encrypted_mk_with_tag = base64.b64decode(key_data["encrypted_mk"])
        aad = base64.b64decode(key_data["aad"])
        
        # Derivar KEK y descifrar
        kek = KeyManager._derive_kek(password, salt)
        aesgcm = AESGCM(kek)
        
        try:
            master_key = aesgcm.decrypt(nonce, encrypted_mk_with_tag, aad)
            return master_key
        except Exception:
            raise ValueError("Contraseña incorrecta o archivo de llave corrupto.")

    @staticmethod
    def generate_ecc_key_pair():
        """Genera un par de claves ECC (privada y pública)."""
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def save_ecc_key(key, path: str, password: str = None):
        """Guarda una clave ECC en formato PEM, opcionalmente cifrada."""
        if isinstance(key, ec.EllipticCurvePrivateKey):
            encryption_algorithm = (
                serialization.BestAvailableEncryption(password.encode())
                if password
                else serialization.NoEncryption()
            )
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            raise TypeError("Tipo de clave no soportado para guardar.")

        with open(path, "wb") as f:
            f.write(pem)

    @staticmethod
    def load_ecc_key(path: str, password: str = None, is_public: bool = False):
        """Carga una clave ECC desde un archivo PEM."""
        with open(path, "rb") as f:
            pem_data = f.read()

        if is_public:
            return serialization.load_pem_public_key(pem_data)
        else:
            password_bytes = password.encode() if password else None
            return serialization.load_pem_private_key(pem_data, password=password_bytes)
