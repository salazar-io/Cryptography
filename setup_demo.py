import os
import sys
import subprocess

#add colors to the terminal
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def install_dependencies():
    print(Colors.HEADER + "=== Paso 1: Instalando Dependencias ===" + Colors.ENDC)
    try:
        import cryptography
        import pytest
        print(Colors.OKGREEN + "  [OK] Las dependencias ('cryptography', 'pytest') ya están instaladas." + Colors.ENDC)
    except ImportError:
        print(Colors.WARNING + "  [!] Faltan dependencias. Instalando 'cryptography' y 'pytest'..." + Colors.ENDC)
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "pytest"])
            print(Colors.OKGREEN + "  [OK] Dependencias instaladas correctamente." + Colors.ENDC)
        except subprocess.CalledProcessError as e:
            print(Colors.FAIL + f"  [ERROR] Falló la instalación de dependencias: {e}" + Colors.ENDC)
            print(Colors.FAIL + "  Por favor, instálalas manualmente con: pip install cryptography pytest" + Colors.ENDC)
            sys.exit(1)


#install_dependencies()
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'vault_container')))

#def setup_user(user_id, password, base_path="vault_container/user_keys"):
#    """Genera pares de claves ECC y Ed25519 para un usuario y las guarda en un keystore cifrado."""

#    print(f"Configurando claves para {user_id}...")
#    user_key_dir = os.path.join(base_path, user_id)
#    os.makedirs(user_key_dir, exist_ok=True)
#    keystore_dir = os.path.join(user_key_dir, "keystore")
    
#    private_key, public_key = KeyManager.generate_ecc_key_pair()
#    sign_private_key, sign_public_key = KeyManager.generate_ed25519_key_pair()
    
#    public_key_path = os.path.join(user_key_dir, "public_key.pem")
#    KeyManager.save_asymmetric_key(public_key, public_key_path)
    
#    sign_public_key_path = os.path.join(user_key_dir, "sign_public_key.pem")
#    KeyManager.save_asymmetric_key(sign_public_key, sign_public_key_path)
    
#    KeyManager.save_keystore(private_key, sign_private_key, keystore_dir, password)
#    print(f"  [OK] Claves para {user_id} generadas con éxito. (Contraseña: {password})")

def setup_directories_and_files():
    """Crea la estructura de directorios necesaria y los archivos de prueba."""
    print(Colors.HEADER + "\n=== Paso 2: Configurando Directorios y Archivos de Prueba ===" + Colors.ENDC)
    os.makedirs("vault_container/plaintext", exist_ok=True)
    os.makedirs("vault_container/encrypted_vault", exist_ok=True)
    os.makedirs("vault_container/decrypted_files", exist_ok=True)
    
    # Archivo original usado en demo_script.md
    poema_path = "vault_container/plaintext/poema.txt"
    if not os.path.exists(poema_path):
        with open(poema_path, "w", encoding="utf-8") as f:
            f.write("Puedo escribir los versos más tristes esta noche.\nEscribir, por ejemplo: 'La noche está estrellada,\ny tiritan, azules, los astros, a lo lejos'.\n")
        print(Colors.OKGREEN + f"  [OK] Archivo de prueba creado")
    else:
        print(Colors.OKGREEN + f"  [OK] El archivo poema.txt ya existe.")
        
    # Segundo archivo de prueba genérico (por si acaso se requiere otro)
    prueba_path = "vault_container/plaintext/documento_prueba.txt"
    if not os.path.exists(prueba_path):
        with open(prueba_path, "w", encoding="utf-8") as f:
            f.write("ESTE ES UN DOCUMENTO DE PRUEBA ALTAMENTE CONFIDENCIAL.\nSi puedes leer esto, el descifrado ha sido exitoso.\n")
        print(Colors.OKGREEN + f"  [OK] Archivo de prueba creado")
    else:
        print(Colors.OKGREEN + f"  [OK] El archivo ya existe.")

if __name__ == "__main__":
    print(Colors.HEADER + "\n=== Iniciando Configuración para la Demo ===" + Colors.ENDC)
    setup_directories_and_files()
    
    print(Colors.HEADER + "\n=== Configuración Completada Exitósamente ===" + Colors.ENDC)