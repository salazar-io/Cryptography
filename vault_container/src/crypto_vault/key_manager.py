# src/crypto_vault/key_manager.py
# Clase key_manager para generar y cargar llaves
# Version 3.0 con soporte para Keystore y Argon2id

import os
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization

class KeyManager:
    ITERATIONS = 600000  # Recomendado por OWASP/NIST para PBKDF2-SHA256
    
    # Parámetros Argon2id
    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 65536 # 64 MB
    ARGON2_PARALLELISM = 4

    @staticmethod
    def _derive_kek(password: str, salt: bytes) -> bytes:
        """Deriva una Key Encryption Key (KEK) usando PBKDF2. (Legacy)"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KeyManager.ITERATIONS,
        )
        return kdf.derive(password.encode())

    @staticmethod
    def _derive_kek_argon2(password: str, salt: bytes, time_cost: int, memory_cost: int, parallelism: int) -> bytes:
        """Deriva una KEK usando Argon2id."""
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=time_cost,
            lanes=parallelism,
            memory_cost=memory_cost,
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def save_keystore(private_key, sign_private_key, path: str, password: str):
        """Guarda las claves privadas en un keystore seguro usando Argon2id y AES-GCM."""
        os.makedirs(path, exist_ok=True)
        
        salt = os.urandom(16)
        nonce_ecc = os.urandom(12)
        nonce_sign = os.urandom(12)
        
        kek = KeyManager._derive_kek_argon2(
            password, 
            salt, 
            KeyManager.ARGON2_TIME_COST, 
            KeyManager.ARGON2_MEMORY_COST, 
            KeyManager.ARGON2_PARALLELISM
        )
        
        aesgcm = AESGCM(kek)
        
        # Serializar claves en PEM (sin cifrar, ya que AESGCM lo cifrará)
        ecc_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        sign_pem = sign_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        aad = b"keystore_v1"
        encrypted_ecc = aesgcm.encrypt(nonce_ecc, ecc_pem, aad)
        encrypted_sign = aesgcm.encrypt(nonce_sign, sign_pem, aad)
        
        # Escribir kdf_parameters.json
        kdf_params = {
            "algorithm": "argon2id",
            "salt": base64.b64encode(salt).decode('utf-8'),
            "time_cost": KeyManager.ARGON2_TIME_COST,
            "memory_cost": KeyManager.ARGON2_MEMORY_COST,
            "parallelism": KeyManager.ARGON2_PARALLELISM
        }
        with open(os.path.join(path, "kdf_parameters.json"), "w") as f:
            json.dump(kdf_params, f, indent=4)
            
        # Escribir claves cifradas. Prependemos el nonce para simplificar.
        with open(os.path.join(path, "encrypted_private_key"), "wb") as f:
            f.write(nonce_ecc + encrypted_ecc)
            
        with open(os.path.join(path, "encrypted_sign_key"), "wb") as f:
            f.write(nonce_sign + encrypted_sign)
            
        # Escribir metadata
        metadata = {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat()
        }
        with open(os.path.join(path, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=4)

    @staticmethod
    def load_keystore(path: str, password: str):
        """Carga y descifra las claves privadas desde un keystore. Retorna (private_key, sign_private_key)."""
        try:
            with open(os.path.join(path, "kdf_parameters.json"), "r") as f:
                kdf_params = json.load(f)
                
            if kdf_params["algorithm"] != "argon2id":
                raise ValueError("KDF no soportado.")
                
            salt = base64.b64decode(kdf_params["salt"])
            time_cost = kdf_params["time_cost"]
            memory_cost = kdf_params["memory_cost"]
            parallelism = kdf_params["parallelism"]
            
            with open(os.path.join(path, "encrypted_private_key"), "rb") as f:
                ecc_data = f.read()
            with open(os.path.join(path, "encrypted_sign_key"), "rb") as f:
                sign_data = f.read()
                
        except FileNotFoundError:
            raise ValueError("Keystore incompleto o no encontrado.")
            
        kek = KeyManager._derive_kek_argon2(password, salt, time_cost, memory_cost, parallelism)
        aesgcm = AESGCM(kek)
        aad = b"keystore_v1"
        
        nonce_ecc = ecc_data[:12]
        ct_ecc = ecc_data[12:]
        nonce_sign = sign_data[:12]
        ct_sign = sign_data[12:]
        
        try:
            ecc_pem = aesgcm.decrypt(nonce_ecc, ct_ecc, aad)
            sign_pem = aesgcm.decrypt(nonce_sign, ct_sign, aad)
        except Exception:
            raise ValueError("Contraseña incorrecta o keystore corrupto.")
            
        private_key = serialization.load_pem_private_key(ecc_pem, password=None)
        sign_private_key = serialization.load_pem_private_key(sign_pem, password=None)
        
        return private_key, sign_private_key

    @staticmethod
    def generate_key_file(path: str, password: str) -> bytes:
        """Legacy."""
        master_key = os.urandom(32)
        salt = os.urandom(16)
        nonce = os.urandom(12)
        kek = KeyManager._derive_kek(password, salt)
        aesgcm = AESGCM(kek)
        aad = b"key_protection_v1"
        encrypted_mk_with_tag = aesgcm.encrypt(nonce, master_key, aad)
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
        """Legacy."""
        try:
            with open(path, "r") as f:
                key_data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Formato de llave antiguo o incompatible.")
        salt = base64.b64decode(key_data["salt"])
        nonce = base64.b64decode(key_data["nonce"])
        encrypted_mk_with_tag = base64.b64decode(key_data["encrypted_mk"])
        aad = base64.b64decode(key_data["aad"])
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
    def generate_ed25519_key_pair():
        """Genera un par de claves Ed25519 (privada y pública) para firmas."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def save_asymmetric_key(key, path: str, password: str = None):
        """Guarda una clave asimétrica (ECC o Ed25519) en formato PEM, opcionalmente cifrada."""
        if isinstance(key, (ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
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
        elif isinstance(key, (ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            raise TypeError("Tipo de clave no soportado para guardar.")

        with open(path, "wb") as f:
            f.write(pem)

    @staticmethod
    def load_asymmetric_key(path: str, password: str = None, is_public: bool = False):
        """Carga una clave asimétrica desde un archivo PEM."""
        with open(path, "rb") as f:
            pem_data = f.read()

        if is_public:
            return serialization.load_pem_public_key(pem_data)
        else:
            password_bytes = password.encode() if password else None
            return serialization.load_pem_private_key(pem_data, password=password_bytes)