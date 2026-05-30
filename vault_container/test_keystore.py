import sys
import os
import getpass

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

#colores para la terminal 
C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_MAGENTA = '\033[95m'
C_END = '\033[0m'

try:
    from src.crypto_vault.key_manager import KeyManager 
except ImportError:
    print(f"{C_RED} Error: Verifica las rutas de importación de tu módulo.{C_END}")
    sys.exit(1)

def simular_acceso():
    print(f"{C_MAGENTA}--- SIMULACIÓN DE ACCESO AL KEYSTORE ---")
    user_id = "edgar"
    keystore_path = "/home/crypto/Cryptography/vault_container/user_keys/edgar/keystore"
    
    if not os.path.exists(keystore_path):
        print(f"{C_RED} No se encontró el Keystore{C_END}")
        print(f"{C_RED}Por favor, genera primero las llaves con 'generate_user_keys.py'.{C_END}")
        return

    password = getpass.getpass(f"Introduce la contraseña para desbloquear el Keystore de [{user_id}]: ")
    
    print(f"{C_BLUE} Derivando clave con Argon2id e intentando descifrar con AES-GCM...{C_END}")
    try:
        manager = KeyManager()
        llaves_desbloqueadas = manager.load_keystore(keystore_path, password) 
        
        print(f"{C_GREEN}  Autenticación correcta. La etiqueta (Tag) GCM coincidió.{C_END}")
        print(f"{C_GREEN} Las llaves elípticas (P-384) y Ed25519 se han cargado de forma segura en la memoria RAM.{C_END}")
        
    except Exception as e:
        print(f"{C_RED}  Acceso Denegado.{C_END}")
        print(f"{C_RED} La etiqueta de autenticación AES-GCM no coincide o los bytes están corruptos.{C_END}")
        print(f"Detalle del error interceptado: {type(e).__name__} - {e}")

if __name__ == "__main__":
    simular_acceso()