import os
import getpass
from src.crypto_vault.vault import Vault
from src.crypto_vault.key_manager import KeyManager
from src.crypto_vault.container import Container

# --- Códigos de color ANSI ---
C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_MAGENTA = '\033[95m'
C_END = '\033[0m'

def decrypt_file_for_recipient(vault_path: str, output_dir: str, recipient_id: str, private_key_path: str):
    """
    Descifra un archivo de un vault para un destinatario específico.
    """
    # 1. Asegurar que el vault existe
    if not os.path.isfile(vault_path):
        # CORRECCIÓN: Fuga de información mitigada en ruta de vault
        print(f"{C_RED}[ERROR] El archivo de vault especificado no existe o el acceso fue denegado.{C_END}")
        return

    print(f"{C_MAGENTA}--- Descifrando {os.path.basename(vault_path)} para '{C_BLUE}{recipient_id}{C_END}' ---{C_END}")

    # 2 y 3. Cargar la clave privada (CORRECCIÓN: Se elimina el Fail-Open y la comparación insegura de texto)
    private_key = None
    password = None
    try:
        # Intentar cargar sin contraseña primero
        private_key = KeyManager.load_asymmetric_key(private_key_path)
    except TypeError:
        # La librería indica criptográficamente que se requiere una contraseña
        password = getpass.getpass(f"Introduce la contraseña para la clave privada de '{C_BLUE}{recipient_id}{C_END}': ")
        try:
            private_key = KeyManager.load_asymmetric_key(private_key_path, password=password)
        except Exception:
            # CORRECCIÓN: Fuga de información mitigada
            print(f"{C_RED}[ERROR] Acceso denegado: Fallo en la autenticación de la clave.{C_END}")
            return
    except Exception:
        # Falla segura (Fail-Closed) para cualquier otro error
        print(f"{C_RED}[ERROR] Acceso denegado: Fallo al cargar el material criptográfico.{C_END}")
        return

    # 4. Cargar el contenedor y descifrar
    try:
        print("  Cargando vault...")
        vault_container = Container.load(vault_path)
        
        signer_public_key = None
        if "signer_id" in vault_container:
            signer_id = vault_container["signer_id"]
            print(f"\n{C_MAGENTA}--- Verificación de Origen (Firma) ---{C_END}")
            print(f"Este archivo afirma estar firmado por: {C_BLUE}{signer_id}{C_END}")
            pub_key_path = input(f"Introduce la ruta a la clave pública de firma de '{signer_id}' (ej: user_keys/{signer_id}/sign_public_key.pem): ")
            try:
                signer_public_key = KeyManager.load_asymmetric_key(pub_key_path, is_public=True)
            except Exception:
                # CORRECCIÓN: Fuga de información mitigada al cargar clave pública
                print(f"{C_RED}[ERROR] Operación abortada: No se pudo verificar la clave de firma.{C_END}")
                return
        
        # Descifrar los datos
        print("  Verificando integridad y descifrando contenido...")
        decrypted_data = Vault.decrypt(vault_container, recipient_id, private_key, signer_public_key)
        
        # CORRECCIÓN: Prevención de Path Traversal mediante os.path.basename
        raw_original_name = vault_container.get("header", {}).get("original_name", f"decrypted_{os.path.basename(vault_path)}")
        safe_original_name = os.path.basename(raw_original_name)
        
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, safe_original_name)
        
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
            
        print(f"\n{C_GREEN}[ÉXITO] Archivo descifrado y guardado en: {C_YELLOW}{output_path}{C_END}")
        
    except Exception:
        # CORRECCIÓN: Fuga de información mitigada, se elimina la impresión de la excepción explícita 'e'
        print(f"\n{C_RED}[ERROR] Proceso abortado: Datos del vault no válidos, corruptos o autorización denegada.{C_END}")

def list_vaults(directory="encrypted_vault"):
    """Lista los archivos .vault en un directorio."""
    if not os.path.exists(directory):
        return []
    return [f for f in os.listdir(directory) if f.endswith(".vault")]

if __name__ == "__main__":
    # 1. Listar y seleccionar vault
    available_vaults = list_vaults()
    if not available_vaults:
        print(f"{C_YELLOW}No se encontraron archivos .vault en la carpeta 'encrypted_vault'.{C_END}")
    else:
        print(f"{C_MAGENTA}--- Descifrar un Archivo ---{C_END}")
        print("Vaults disponibles:")
        for i, v_name in enumerate(available_vaults):
            print(f"  [{i+1}] {C_BLUE}{v_name}{C_END}")
        
        try:
            choice = int(input("Elige el número del vault a descifrar: ")) - 1
            if not 0 <= choice < len(available_vaults):
                raise ValueError()
            vault_file_path = os.path.join("encrypted_vault", available_vaults[choice])
        except (ValueError, IndexError):
            print(f"{C_RED}Selección no válida.{C_END}")
            exit()

    # 2. Solicitar información del destinatario
    print(f"\n{C_MAGENTA}--- Identificación del Destinatario ---{C_END}")
    user_id = input("Introduce tu ID de destinatario: ")
    priv_key_path = input(f"Introduce la ruta a tu clave privada de cifrado (para '{C_BLUE}{user_id}{C_END}'): ")

    if not os.path.exists(priv_key_path):
        # CORRECCIÓN: Fuga de información (no confirmar si el archivo exacto existe a nivel de sistema)
        print(f"{C_RED}[ERROR] Operación abortada. Credenciales no válidas.{C_END}")
    else:
        #  Ejecutar descifrado
        output_folder = "decrypted_files"
        os.makedirs(output_folder, exist_ok=True)
        decrypt_file_for_recipient(vault_file_path, output_folder, user_id, priv_key_path)