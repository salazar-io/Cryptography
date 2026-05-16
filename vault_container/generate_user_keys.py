# vault_container/generate_user_keys.py
# Script para generar pares de claves ECC para los usuarios.

import os
import getpass
from src.crypto_vault.key_manager import KeyManager

# --- Códigos de color ANSI ---
C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_MAGENTA = '\033[95m'
C_END = '\033[0m'

def generate_keys_for_user(user_id: str, base_path: str = "user_keys"):
    """
    Genera y guarda un par de claves ECC para un usuario.
    La clave privada se guarda en un keystore cifrado con Argon2id.
    """
    print(f"{C_MAGENTA}--- Generando claves para el usuario: {user_id} ---{C_END}")
    
    # 1. Solicitar contraseña para la clave privada
    try:
        password = getpass.getpass(f"Introduce una contraseña para proteger la clave privada de {user_id}: ")
        password_confirm = getpass.getpass("Confirma la contraseña: ")
        if password != password_confirm:
            print(f"{C_RED}[ERROR] Las contraseñas no coinciden.{C_END}")
            return
        if len(password) < 6:
            print(f"{C_YELLOW}[ADVERTENCIA] Contraseña muy corta. Se recomienda usar contraseñas robustas.{C_END}")
        if not password:
            print(f"{C_RED}[ERROR] El Keystore requiere obligatoriamente una contraseña.{C_END}")
            return
    except Exception as e:
        print(f"{C_RED}[ERROR] No se pudo leer la contraseña: {e}{C_END}")
        return

    # 2. Generar pares de claves
    try:
        # Claves para Cifrado (ECDH)
        private_key, public_key = KeyManager.generate_ecc_key_pair()
        # Claves para Firma (Ed25519)
        sign_private_key, sign_public_key = KeyManager.generate_ed25519_key_pair()
        print(f"  {C_GREEN}[OK]{C_END} Pares de claves ECC y Ed25519 generados.")
    except Exception as e:
        print(f"{C_RED}[ERROR] Falló la generación de claves: {e}{C_END}")
        return

    # 3. Crear directorio para el usuario
    user_key_dir = os.path.join(base_path, user_id)
    os.makedirs(user_key_dir, exist_ok=True)
    keystore_dir = os.path.join(user_key_dir, "keystore")

    # 4. Guardar las claves
    try:
        # Guardar claves públicas (en texto plano PEM para ser compartidas fácilmente)
        public_key_path = os.path.join(user_key_dir, "public_key.pem")
        KeyManager.save_asymmetric_key(public_key, public_key_path)
        print(f"  {C_GREEN}[OK]{C_END} Clave pública de cifrado en: {C_BLUE}{public_key_path}{C_END}")

        sign_public_key_path = os.path.join(user_key_dir, "sign_public_key.pem")
        KeyManager.save_asymmetric_key(sign_public_key, sign_public_key_path)
        print(f"  {C_GREEN}[OK]{C_END} Clave pública de firma en: {C_BLUE}{sign_public_key_path}{C_END}")
        
        # Guardar claves privadas en el Keystore
        KeyManager.save_keystore(private_key, sign_private_key, keystore_dir, password)
        print(f"  {C_GREEN}[OK]{C_END} Claves privadas guardadas de forma segura en Keystore: {C_BLUE}{keystore_dir}{C_END}")
        
        print(f"\n{C_GREEN}[ÉXITO] Claves para '{user_id}' generadas correctamente.{C_END}")

    except Exception as e:
        print(f"{C_RED}[ERROR] No se pudieron guardar las claves: {e}{C_END}")

if __name__ == "__main__":
    user = input("Introduce el ID del usuario (ej: alice, bob): ")
    if user:
        generate_keys_for_user(user)
    else:
        print(f"{C_RED}ID de usuario no válido.{C_END}")
