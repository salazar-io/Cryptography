# vault_container/generate_user_keys.py
# Script para generar pares de claves ECC para los usuarios.

import os
import getpass
from src.crypto_vault.key_manager import KeyManager

def generate_keys_for_user(user_id: str, base_path: str = "user_keys"):
    """
    Genera y guarda un par de claves ECC para un usuario.
    La clave privada se guarda cifrada con una contraseña.
    """
    print(f"--- Generando claves para el usuario: {user_id} ---")
    
    # 1. Solicitar contraseña para la clave privada
    try:
        password = getpass.getpass(f"Introduce una contraseña para proteger la clave privada de {user_id}: ")
        password_confirm = getpass.getpass("Confirma la contraseña: ")
        if password != password_confirm:
            print("[ERROR] Las contraseñas no coinciden.")
            return
        if not password:
            print("[ADVERTENCIA] Se generará una clave privada sin protección por contraseña.")
            password = None
    except Exception as e:
        print(f"[ERROR] No se pudo leer la contraseña: {e}")
        return

    # 2. Generar el par de claves
    try:
        private_key, public_key = KeyManager.generate_ecc_key_pair()
        print("  [OK] Par de claves ECC generado.")
    except Exception as e:
        print(f"[ERROR] Falló la generación de claves: {e}")
        return

    # 3. Crear directorio para el usuario
    user_key_dir = os.path.join(base_path, user_id)
    os.makedirs(user_key_dir, exist_ok=True)

    # 4. Guardar las claves
    try:
        private_key_path = os.path.join(user_key_dir, "private_key.pem")
        public_key_path = os.path.join(user_key_dir, "public_key.pem")

        KeyManager.save_ecc_key(private_key, private_key_path, password=password)
        print(f"  [OK] Clave privada guardada en: {private_key_path}")

        KeyManager.save_ecc_key(public_key, public_key_path)
        print(f"  [OK] Clave pública guardada en: {public_key_path}")
        
        print(f"\n[ÉXITO] Claves para '{user_id}' generadas correctamente.")

    except Exception as e:
        print(f"[ERROR] No se pudieron guardar las claves: {e}")

if __name__ == "__main__":
    user = input("Introduce el ID del usuario (ej: alice, bob): ")
    if user:
        generate_keys_for_user(user)
    else:
        print("ID de usuario no válido.")
