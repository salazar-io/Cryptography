# vault_container/backup_recovery.py
# Script para respaldar y recuperar el Keystore de un usuario.

import os
import zipfile
import shutil
import argparse

# --- Códigos de color ANSI ---
C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_MAGENTA = '\033[95m'
C_END = '\033[0m'

def backup_keystore(user_id: str, dest_dir: str = "."):
    """
    Empaqueta el keystore de un usuario en un archivo ZIP seguro.
    Como las claves privadas están cifradas, el ZIP en sí no requiere cifrado extra.
    """
    user_key_dir = os.path.join("user_keys", user_id)
    keystore_dir = os.path.join(user_key_dir, "keystore")
    
    if not os.path.exists(keystore_dir):
        print(f"{C_RED}[ERROR] El usuario '{user_id}' no tiene un Keystore en '{keystore_dir}'.{C_END}")
        return

    os.makedirs(dest_dir, exist_ok=True)
    zip_filename = os.path.join(dest_dir, f"{user_id}_keystore_backup.zip")
    
    print(f"{C_MAGENTA}--- Creando respaldo para '{user_id}' ---{C_END}")
    try:
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(user_key_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Añadir al ZIP manteniendo la estructura relativa desde user_keys
                    arcname = os.path.relpath(file_path, "user_keys")
                    zipf.write(file_path, arcname)
                    print(f"  Añadido: {arcname}")
                    
        print(f"\n{C_GREEN}[ÉXITO] Respaldo creado en: {C_BLUE}{zip_filename}{C_END}")
        print(f"{C_YELLOW}Guarda este archivo en un lugar seguro (USB, Nube, etc).{C_END}")
    except Exception as e:
        print(f"{C_RED}[ERROR] Falló la creación del respaldo: {e}{C_END}")


def restore_keystore(zip_path: str, dest_dir: str = "user_keys"):
    """
    Restaura un keystore desde un archivo ZIP de respaldo.
    """
    if not os.path.exists(zip_path):
        print(f"{C_RED}[ERROR] El archivo de respaldo '{zip_path}' no existe.{C_END}")
        return

    print(f"{C_MAGENTA}--- Restaurando respaldo desde '{zip_path}' ---{C_END}")
    try:
        os.makedirs(dest_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(dest_dir)
            
        print(f"\n{C_GREEN}[ÉXITO] Keystore restaurado en el directorio '{C_BLUE}{dest_dir}{C_END}'.")
    except Exception as e:
        print(f"{C_RED}[ERROR] Falló la restauración del respaldo: {e}{C_END}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gestor de Respaldos de Keystore")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Comando backup
    backup_parser = subparsers.add_parser("backup", help="Crea un respaldo de un Keystore de usuario")
    backup_parser.add_argument("user_id", help="ID del usuario a respaldar")
    
    # Comando restore
    restore_parser = subparsers.add_parser("restore", help="Restaura un Keystore desde un archivo ZIP")
    restore_parser.add_argument("zip_path", help="Ruta al archivo ZIP de respaldo")
    
    args = parser.parse_args()
    
    if args.command == "backup":
        backup_keystore(args.user_id)
    elif args.command == "restore":
        restore_keystore(args.zip_path)
