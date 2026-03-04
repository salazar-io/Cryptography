# Caso de uso del vault: cifrado archivos de la carpeta "plaintext" y guardado en "encrypted_vault" usando la llave "vault.key"
# Version 1.0
# Fecha: 2026/03/4

import os
from src.crypto_vault.vault import Vault
from src.crypto_vault.key_manager import KeyManager
from src.crypto_vault.container import Container

def bulk_encrypt(input_dir: str, output_parent_dir: str, key_path: str) -> None:
    """
    Cifra todos los archivos en la carpeta de entrada y guarda cada vault en una subcarpeta dentro de la carpeta de salida.
    Args:
        input_dir (str): La carpeta que contiene los archivos de texto claro a cifrar.
        output_parent_dir (str): La carpeta donde se crearán subcarpetas para cada archivo cifrado.
        key_path (str): La ruta del archivo de la llave de cifrado (se generará si no existe).
    """

    # 1. Cargar o generar la llave
    if os.path.exists(key_path):
        key = KeyManager.load_key_file(key_path)
    else:
        key = KeyManager.generate_key_file(key_path)

    # 2. Asegurar que la carpeta de destino existe
    if not os.path.exists(output_parent_dir):
        os.makedirs(output_parent_dir)

    # 3. Iterar sobre los archivos en la carpeta de texto claro
    files_processed = 0
    for filename in os.listdir(input_dir):
        file_path = os.path.join(input_dir, filename)
        
        # Saltarse carpetas, solo procesar archivos
        if os.path.isfile(file_path):
            print(f"Procesando: {filename}...")
            
            # Leer datos
            with open(file_path, "rb") as f:
                data = f.read()
            
            # Cifrar con metadatos específicos del archivo
            metadata = {"original_name": filename, "type": filename.split(".")[-1]}
            vault_dict = Vault.encrypt(data, key, metadata)
            
            # Crear un nombre de carpeta único para este archivo dentro de la carpeta de salida
            container_path = os.path.join(output_parent_dir, f"vault_{filename}")
            
            # Guardar el contenedor
            Container.save(vault_dict, container_path)
            files_processed += 1

    print(f"\nProceso terminado. Se cifraron {files_processed} archivos en '{output_parent_dir}'.")

if __name__ == "__main__":
    try:
        bulk_encrypt(input_dir="plaintext", output_parent_dir="encrypted_vault", key_path="vault.key")
    except Exception as e:
        print(f"Error durante el proceso de cifrado: {e}")