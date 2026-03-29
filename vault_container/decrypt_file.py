import os
import getpass
from src.crypto_vault.vault import Vault
from src.crypto_vault.key_manager import KeyManager
from src.crypto_vault.container import Container

def decrypt_file_for_recipient(vault_path: str, output_dir: str, recipient_id: str, private_key_path: str):
    """
    Descifra un archivo de un vault para un destinatario específico.
    """
    # 1. Asegurar que el vault existe
    if not os.path.isfile(vault_path):
        print(f"[ERROR] El archivo de vault '{vault_path}' no existe.")
        return

    print(f"--- Descifrando {os.path.basename(vault_path)} para '{recipient_id}' ---")

    # 2. Solicitar contraseña de la clave privada (si es necesaria)
    password = None
    try:
        # Un pequeño truco para ver si la clave está cifrada sin cargarla
        with open(private_key_path, "r") as f:
            if "ENCRYPTED" in f.read():
                password = getpass.getpass(f"Introduce la contraseña para la clave privada de '{recipient_id}': ")
    except Exception:
        pass # La clave puede ser binaria, no importa si falla

    # 3. Cargar la clave privada
    try:
        private_key = KeyManager.load_ecc_key(private_key_path, password=password)
    except Exception as e:
        print(f"[ERROR] No se pudo cargar la clave privada: {e}")
        return

    # 4. Cargar el contenedor y descifrar
    try:
        vault_container = Container.load(vault_path)
        
        # Descifrar los datos
        decrypted_data = Vault.decrypt(vault_container, recipient_id, private_key)
        
        # Recuperar nombre original y guardar
        original_name = vault_container.get("header", {}).get("original_name", f"decrypted_{os.path.basename(vault_path)}")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, original_name)
        
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
            
        print(f"\n[ÉXITO] Archivo descifrado y guardado en: {output_path}")
        
    except Exception as e:
        print(f"\n[ERROR] Falló el proceso de descifrado: {e}")
        print("Verifica que eres un destinatario válido y que tu clave privada es correcta.")

def list_vaults(directory="encrypted_vault"):
    """Lista los archivos .vault en un directorio."""
    if not os.path.exists(directory):
        return []
    return [f for f in os.listdir(directory) if f.endswith(".vault")]

if __name__ == "__main__":
    # 1. Listar y seleccionar vault
    available_vaults = list_vaults()
    if not available_vaults:
        print("No se encontraron archivos .vault en la carpeta 'encrypted_vault'.")
    else:
        print("Vaults disponibles:")
        for i, v_name in enumerate(available_vaults):
            print(f"  [{i+1}] {v_name}")
        
        try:
            choice = int(input("Elige el número del vault a descifrar: ")) - 1
            if not 0 <= choice < len(available_vaults):
                raise ValueError()
            vault_file_path = os.path.join("encrypted_vault", available_vaults[choice])
        except (ValueError, IndexError):
            print("Selección no válida.")
            exit()

    # 2. Solicitar información del destinatario
    user_id = input("Introduce tu ID de destinatario: ")
    priv_key_path = input(f"Introduce la ruta a tu clave privada (para '{user_id}'): ")

    if not os.path.exists(priv_key_path):
        print(f"[ERROR] La clave privada en '{priv_key_path}' no existe.")
    else:
        #  Ejecutar descifrado
        decrypt_file_for_recipient(vault_file_path, "decrypted_files", user_id, priv_key_path)
