import os
import getpass
from src.crypto_vault.vault import Vault
from src.crypto_vault.key_manager import KeyManager
from src.crypto_vault.container import Container

def decrypt_file(container_path, output_dir, key_path, password):
    print(f"--- Decodificando Contenedor ---")
    
    if not os.path.exists(container_path):
        print(f"Error: El contenedor '{container_path}' no existe.")
        return

    # 1. Cargar la llave con la contraseña
    try:
        if not os.path.exists(key_path):
            print(f"Error: No se encontró el archivo de llave '{key_path}'.")
            return
            
        key = KeyManager.load_key_file(key_path, password)
    except Exception as e:
        print(f"Error al cargar la llave: {e}")
        return

    # 2. Cargar el contenedor
    try:
        vault_container = Container.load(container_path)
        
        # 3. Descifrar
        decrypted_data = Vault.decrypt(vault_container, key)
        
        # 4. Recuperar nombre original desde los metadatos (header)
        original_name = vault_container.get("header", {}).get("original_name", "recovered_file")
        
        # 5. Guardar el resultado
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        output_path = os.path.join(output_dir, original_name)
        
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
            
        print(f"\n[ÉXITO] Archivo descifrado y restaurado en: {output_path}")
        
    except Exception as e:
        print(f"\n[ERROR] No se pudo descifrar el archivo: {e}")
        print("Asegúrate de que la contraseña sea correcta y el archivo no esté corrupto.")

if __name__ == "__main__":
    # Facilitar al usuario encontrar los contenedores
    print("Contenedores disponibles en 'encrypted_vault/':")
    if os.path.exists("encrypted_vault"):
        dirs = [d for d in os.listdir("encrypted_vault") if os.path.isdir(os.path.join("encrypted_vault", d))]
        for d in dirs:
            print(f" - {d}")
    
    ruta = input("\nIntroduce el nombre o ruta del contenedor (ej: vault_archivo.txt): ")

    if not os.path.exists(ruta):
        opcion_default = os.path.join("encrypted_vault", ruta)
        if os.path.exists(opcion_default):
            ruta = opcion_default
        elif os.path.exists(os.path.join("encrypted_vault", f"vault_{ruta}")):
            ruta = os.path.join("encrypted_vault", f"vault_{ruta}")

    pwd = getpass.getpass("Introduce la contraseña de la llave: ")
    decrypt_file(ruta, "plaintext", "vault.key", pwd)
