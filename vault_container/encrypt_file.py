import os
import getpass
from src.crypto_vault.vault import Vault
from src.crypto_vault.key_manager import KeyManager
from src.crypto_vault.container import Container

# --- Códigos de color ANSI ---
C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_BLUE = '\033[94m'
C_MAGENTA = '\033[95m'
C_END = '\033[0m'
C_YELLOW = '\033[93m'

def encrypt_file_for_recipients(file_path: str, output_dir: str, recipients: list):
    """
    Cifra un archivo para una lista de destinatarios usando cifrado híbrido.
    """
    # 1. Asegurar que la carpeta de destino existe
    os.makedirs(output_dir, exist_ok=True)

    # 2. Procesar el archivo
    if not os.path.isfile(file_path):
        print(f"{C_RED}[ERROR] El archivo '{file_path}' no existe.{C_END}")
        return

    filename = os.path.basename(file_path)
    print(f"Cifrando: {C_BLUE}{filename}{C_END} para {len(recipients)} destinatario(s)...")
    
    try:
        # Leer el contenido del archivo
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Preparar metadatos y cifrar
        metadata = {"original_name": filename}
        vault_dict = Vault.encrypt(data, recipients, metadata)
        
        # Guardar el vault en un único archivo .vault
        output_filename = f"{os.path.splitext(filename)[0]}.vault"
        container_path = os.path.join(output_dir, output_filename)
        Container.save(vault_dict, container_path)
        
        print(f"\n{C_GREEN}[ÉXITO] Archivo cifrado guardado en: {C_BLUE}{container_path}{C_END}")
        
    except Exception as e:
        print(f"\n{C_RED}[ERROR] Falló el proceso de cifrado: {e}{C_END}")
        print("El archivo original se mantuvo intacto por seguridad.")

if __name__ == "__main__":
    # 1. Solicitar archivo a cifrar
    archivo_path = input("Introduce la ruta del archivo a cifrar (ej: plaintext/poema.txt): ")
    if not os.path.exists(archivo_path):
        print(f"{C_RED}El archivo '{archivo_path}' no se encontró.{C_END}")
    else:
        # 2. Recopilar destinatarios
        recipients_list = []
        print(f"\n{C_MAGENTA}--- Añadir Destinatarios ---{C_END}")
        while True:
            user_id = input("Introduce el ID del destinatario (o presiona Enter para terminar): ")
            if not user_id:
                break
            
            pub_key_path = input(f"Introduce la ruta a la clave pública de '{user_id}': ")
            
            if not os.path.exists(pub_key_path):
                print(f"{C_RED}[ERROR] La clave pública en '{pub_key_path}' no existe.{C_END}")
                continue
            
            try:
                public_key = KeyManager.load_ecc_key(pub_key_path, is_public=True)
                recipients_list.append({"id": user_id, "public_key": public_key})
                print(f"  {C_GREEN}[OK]{C_END} Destinatario '{user_id}' añadido.")
            except Exception as e:
                print(f"{C_RED}[ERROR] No se pudo cargar la clave pública: {e}{C_END}")

        # 3. Ejecutar cifrado si hay destinatarios
        if recipients_list:
            encrypt_file_for_recipients(archivo_path, "encrypted_vault", recipients_list)
        else:
            print(f"\n{C_YELLOW}No se añadieron destinatarios. Proceso cancelado.{C_END}")


