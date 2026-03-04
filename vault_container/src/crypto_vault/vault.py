# src/crypto_vault/vault.py
# Clase vault para cifrar y descifrar datos 
# Version 1.0

import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime

class Vault:
    @staticmethod
    def encrypt(data: bytes, key: bytes, metadata: dict = None) -> dict:
        """
        Cifrado de los datos usando AES-GCM y devuelve un diccionario con los componentes del vault.
        Args:
            data (bytes): Los datos a cifrar.
            key (bytes): La llave de cifrado (debe ser de 256 bits).
            metadata (dict, opcional): Metadatos adicionales para incluir en el header del vault
        Returns:
            dict: Un diccionario con las claves "header", "nonce", "ciphertext" y "authentication_tag".
        """
        aesgcm = AESGCM(key) # AES-GCM es un modo de operación de cifrado autenticado que proporciona confidencialidad e integridad de los datos. AESGCM es una clase proporcionada por la biblioteca cryptography que implementa este modo de cifrado.
        nonce = os.urandom(12)  # nonce de 96 bits  
        #El NIST recomienda una longitud de IV de 96 bits para un mejor rendimiento, pero puede ser de hasta 264 - 1 bits. NUNCA REUTILIZAR UN NONCE con la misma llave.
        
        # Preparar metadatos para AAD (authenticated additional data)
        if metadata is None:
            metadata = {}
        # Agregar metadatos al vault
        metadata.update({
            "version": "1.0",
            "algorithm": "AES-256-GCM",
            "timestamp": datetime.now().isoformat()
        })
        
        aad = json.dumps(metadata, sort_keys=True).encode('utf-8')
        
        # Cifrado con AES-GCM, el resultado incluye el tag de autenticación al final del ciphertext
        try:
            ciphertext_with_tag = aesgcm.encrypt(nonce, data, aad)
        except Exception as e:
            raise ValueError(f"Error durante el cifrado: {e}")
        # Separar el tag del ciphertext (los últimos 16 bytes son el tag de autenticación)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        return {
            "header": metadata,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "authentication_tag": tag
        }

    @staticmethod
    def decrypt(vault_container: dict, key: bytes) -> bytes:
        """
        Descifra los datos del vault usando AES-GCM.
        Args:
            vault_container (dict): Un diccionario con las claves "header", "nonce", "ciphertext" y "authentication_tag".
            key (bytes): La llave de descifrado ( debe ser la misma que se usó para cifrar).
        Returns:
            bytes: Los datos descifrados.
        Raises:
                ValueError: Si la autenticación falla o si el formato del vault es incorrecto.    
        """
        aesgcm = AESGCM(key)
        nonce = vault_container["nonce"]
        header = vault_container["header"]
        ciphertext = vault_container["ciphertext"]
        tag = vault_container["tag"]
        
        aad = json.dumps(header, sort_keys=True).encode('utf-8')
        ciphertext_with_tag = ciphertext + tag
        
        try:
            return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except Exception as e:
            raise ValueError(f"Error durante el descifrado: {e}")
