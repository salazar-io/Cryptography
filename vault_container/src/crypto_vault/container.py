# src/crypto_vault/container.py
# Clase Container para guardar y cargar los componentes del vault 
# Version 2.0 con soporte para multiples usuarios

import os
import json
import base64

class Container:
    """Clase para manejar la estructura de almacenamiento del vault."""
    @staticmethod
    def save(vault_dict: dict, file_path: str) -> None:
        """Guarda el diccionario del vault en un único archivo JSON.
        Los datos binarios se codifican en base64.
        Args:
            vault_dict (dict): Diccionario del vault.
            file_path (str): Ruta al archivo de salida.
        """
        # Crear una copia para no modificar el diccionario original
        serializable_vault = vault_dict.copy()

        # Codificar datos binarios a base64
        serializable_vault['nonce'] = base64.b64encode(vault_dict['nonce']).decode('utf-8')
        serializable_vault['ciphertext'] = base64.b64encode(vault_dict['ciphertext']).decode('utf-8')
        serializable_vault['authentication_tag'] = base64.b64encode(vault_dict['authentication_tag']).decode('utf-8')

        if 'signature' in vault_dict:
            serializable_vault['signature'] = base64.b64encode(vault_dict['signature']).decode('utf-8')

        if 'recipients' in serializable_vault:
            for recipient in serializable_vault['recipients']:
                recipient['encrypted_key'] = base64.b64encode(recipient['encrypted_key']).decode('utf-8')

        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            json.dump(serializable_vault, f, indent=4)

    @staticmethod
    def load(file_path: str) -> dict:
        """Carga el diccionario del vault desde un archivo JSON.
        Los datos en base64 se decodifican a binario.
        Args:
            file_path (str): Ruta al archivo del vault.
        Returns:
            dict: Diccionario del vault.
        """
        with open(file_path, "r") as f:
            serializable_vault = json.load(f)

        # Decodificar datos base64 a binario
        vault_dict = serializable_vault.copy()
        vault_dict['nonce'] = base64.b64decode(serializable_vault['nonce'])
        vault_dict['ciphertext'] = base64.b64decode(serializable_vault['ciphertext'])
        vault_dict['authentication_tag'] = base64.b64decode(serializable_vault['authentication_tag'])

        if 'signature' in serializable_vault:
            vault_dict['signature'] = base64.b64decode(serializable_vault['signature'])

        if 'recipients' in vault_dict:
            for recipient in vault_dict['recipients']:
                recipient['encrypted_key'] = base64.b64decode(recipient['encrypted_key'])
                
        return vault_dict