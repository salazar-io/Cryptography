# src/crypto_vault/key_manager.py
# Clase key_manager para generar y cargar llaves
# Version 1.0

import os

class KeyManager:
    @staticmethod
    def generate_key_file(path: str) -> bytes:
        """Genera una llave de 256 bits y la guarda en un archivo.

        Args:
            path (str): La ruta donde se guardará la llave.
        Returns:
            bytes: La llave generada.
        """
        key = os.urandom(32)  # 256 bits
        with open(path, "wb") as f:
            f.write(key)
        return key

    @staticmethod
    def load_key_file(path: str) -> bytes:
        """Carga una llave de 256 bits desde un archivo.
        
        Args:
            path (str): La ruta donde se encuentra la llave.
        Returns:
            bytes: La llave cargada.
        """
        #lectura en modo binario (lee bytes)
        with open(path, "rb") as f:
            key = f.read()
			
        if len(key) != 32:
            raise ValueError("La llave debe ser de 256 bits (32 bytes).")
        return key