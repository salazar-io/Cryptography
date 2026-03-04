# src/crypto_vault/container.py
# Clase Container para guardar y cargar los componentes del vault 
# Version 1.0

import os
import json

class Container:
    """Clase para manejar la estructura de almacenamiento del vault."""
    @staticmethod
    def save(vault_dict: dict, base_path: str) -> None:
        """guarda los componentes del vault en una estructura de directorios.
        Args:
            vault_dict (dict): Un diccionario con las claves "header", "nonce", "ciphertext" y "authentication_tag".
            base_path (str): La ruta base donde se guardarán los componentes del vault.
        """

        os.makedirs(base_path, exist_ok=True) #crea el directorio si no existe
        
        with open(os.path.join(base_path, "header"), "w") as f: 
            json.dump(vault_dict["header"], f, indent=4) 
            
        with open(os.path.join(base_path, "nonce"), "wb") as f:
            f.write(vault_dict["nonce"])
            
        with open(os.path.join(base_path, "ciphertext"), "wb") as f:
            f.write(vault_dict["ciphertext"])
            
        with open(os.path.join(base_path, "authentication_tag"), "wb") as f:
            f.write(vault_dict["authentication_tag"])

    @staticmethod
    def load(base_path: str) -> dict:
        """Carga los componentes del vault desde una estructura de directorios.
        Args:
            base_path (str): La ruta base donde se encuentran los componentes del vault.
        Returns:
            dict: Un diccionario con las claves "header", "nonce", "ciphertext" y "authentication_tag".

        """
        with open(os.path.join(base_path, "header"), "r") as f:
            header = json.load(f)
            
        with open(os.path.join(base_path, "nonce"), "rb") as f:
            nonce = f.read()
            
        with open(os.path.join(base_path, "ciphertext"), "rb") as f:
            ciphertext = f.read()
            
        with open(os.path.join(base_path, "authentication_tag"), "rb") as f:
            tag = f.read()
            
        return {
            "header": header,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "authentication_tag": tag
        }
