# src/crypto_vault/vault.py
# Clase vault para cifrar y descifrar datos 
# Version 2.0 con soporte para ECIES y multiples usuarios

import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Vault:
    @staticmethod
    def _encrypt_ecies(public_key: ec.EllipticCurvePublicKey, data: bytes) -> bytes:
        """Cifra datos usando un esquema ECIES simplificado."""
        # 1. Generar clave efímera
        ephemeral_private_key = ec.generate_private_key(public_key.curve)
        ephemeral_public_key_bytes = ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

        # 2. Derivar secreto compartido
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

        # 3. Derivar claves de cifrado y MAC
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=48,  # 32 para cifrado, 16 para MAC
            salt=None,
            info=b'ecies-encryption',
        )
        derived_key = hkdf.derive(shared_secret)
        encryption_key = derived_key[:32]
        mac_key = derived_key[32:]

        # 4. Cifrar los datos (AES-GCM)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag

        # Retornar: PubKey Efímera + IV + Tag + Ciphertext
        return ephemeral_public_key_bytes + iv + tag + ciphertext

    @staticmethod
    def _decrypt_ecies(private_key: ec.EllipticCurvePrivateKey, encrypted_data: bytes) -> bytes:
        """Descifra datos usando un esquema ECIES simplificado."""
        # 1. Calcular longitud de la clave pública comprimida y extraer componentes
        # Para SECP384R1, la clave comprimida es 1 (prefijo) + 48 bytes (coord x) = 49 bytes
        pub_key_len = (private_key.curve.key_size + 7) // 8 + 1
        ephemeral_public_key_bytes = encrypted_data[:pub_key_len]
        iv = encrypted_data[pub_key_len : pub_key_len + 12]
        tag = encrypted_data[pub_key_len + 12 : pub_key_len + 28]
        ciphertext = encrypted_data[pub_key_len + 28 :]

        # 2. Reconstruir la clave pública efímera desde los bytes
        try:
            ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                private_key.curve, ephemeral_public_key_bytes
            )
        except Exception as e:
            raise ValueError(f"Invalid public bytes for the given curve: {e}")

        # 3. Derivar secreto y claves (igual que en cifrado)
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=48,
            salt=None,
            info=b'ecies-encryption',
        )
        derived_key = hkdf.derive(shared_secret)
        encryption_key = derived_key[:32]
        
        # 4. Descifrar
        cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        
        try:
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            raise ValueError(f"Error de descifrado ECIES (posiblemente tag inválido): {e}")

    @staticmethod
    def encrypt(data: bytes, recipients: list, metadata: dict = None) -> dict:
        """Cifrado híbrido para múltiples destinatarios."""
        file_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(file_key)
        nonce = os.urandom(12)

        if metadata is None:
            metadata = {}
        
        recipient_list = []
        for recipient in recipients:
            recipient_id = recipient['id']
            public_key = recipient['public_key']
            encrypted_file_key = Vault._encrypt_ecies(public_key, file_key)
            recipient_list.append({
                "id": recipient_id,
                "encrypted_key": encrypted_file_key
            })

        metadata.update({
            "version": "2.0",
            "algorithm": "AES-256-GCM_ECIES",
            "timestamp": datetime.now().isoformat(),
            "recipients": [r['id'] for r in recipient_list]
        })
        
        aad = json.dumps(metadata, sort_keys=True).encode('utf-8')
        ciphertext_with_tag = aesgcm.encrypt(nonce, data, aad)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        return {
            "header": metadata,
            "recipients": recipient_list,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "authentication_tag": tag
        }

    @staticmethod
    def decrypt(vault_container: dict, recipient_id: str, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """Descifrado híbrido para un destinatario."""
        # Encontrar la clave cifrada para el destinatario
        encrypted_file_key = None
        for recipient in vault_container['recipients']:
            if recipient['id'] == recipient_id:
                encrypted_file_key = recipient['encrypted_key']
                break
        
        if not encrypted_file_key:
            raise ValueError(f"Destinatario '{recipient_id}' no encontrado.")

        # Descifrar la clave del archivo
        file_key = Vault._decrypt_ecies(private_key, encrypted_file_key)

        # Descifrar los datos del vault
        aesgcm = AESGCM(file_key)
        nonce = vault_container["nonce"]
        header = vault_container["header"]
        ciphertext = vault_container["ciphertext"]
        tag = vault_container["authentication_tag"]
        
        aad = json.dumps(header, sort_keys=True).encode('utf-8')
        ciphertext_with_tag = ciphertext + tag
        
        try:
            return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except Exception as e:
            raise ValueError(f"Error durante el descifrado del vault: {e}")
