# vault_container/share_vault.py
# Script para añadir nuevos destinatarios a un vault existente.

import os
import getpass
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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

def list_vaults(directory="encrypted_vault"):
    """Lista los archivos .vault en un directorio."""
    if not os.path.exists(directory):
        return []
    return [f for f in os.listdir(directory) if f.endswith(".vault")]

def add_recipients_to_vault(vault_path: str, existing_recipient_id: str, existing_private_key_path: str, new_recipients_info: list, signer_private_key):
    """Añade nuevos destinatarios a un vault existente y lo refirma."""
    # --- 1. Cargar credenciales del usuario existente ---
    password = None
    try:
        with open(existing_private_key_path, "r") as f:
            if "ENCRYPTED" in f.read():
                password = getpass.getpass(f"Introduce la contraseña de tu clave privada ('{existing_recipient_id}'): ")
    except Exception:
        pass

    try:
        existing_private_key = KeyManager.load_asymmetric_key(existing_private_key_path, password=password)
    except Exception as e:
        print(f"{C_RED}[ERROR] No se pudo cargar tu clave privada: {e}{C_END}")
        return

    # --- 2. Cargar el vault y descifrar la clave de archivo ---
    try:
        vault_container = Container.load(vault_path)
        
        # Encontrar la clave cifrada para el usuario existente
        encrypted_file_key = None
        for r in vault_container['recipients']:
            if r['id'] == existing_recipient_id:
                encrypted_file_key = r['encrypted_key']
                break
        
        if not encrypted_file_key:
            raise ValueError(f"No eres un destinatario autorizado de este vault ('{existing_recipient_id}').")

        # Descifrar la clave del archivo
        file_key = Vault._decrypt_ecies(existing_private_key, encrypted_file_key)
        print(f"  {C_GREEN}[OK]{C_END} Clave de archivo recuperada con éxito.")

    except Exception as e:
        print(f"{C_RED}[ERROR] Falló la autorización: {e}{C_END}")
        return

    # --- 3. Cifrar la clave de archivo para los nuevos destinatarios ---
    try:
        for new_recipient in new_recipients_info:
            recipient_id = new_recipient['id']
            public_key = new_recipient['public_key']
            
            # Verificar que el destinatario no exista ya
            if any(r['id'] == recipient_id for r in vault_container['recipients']):
                print(f"  {C_YELLOW}[INFO] El usuario '{recipient_id}' ya es un destinatario. Omitiendo.{C_END}")
                continue

            print(f"  Cifrando clave para '{C_BLUE}{recipient_id}{C_END}'...")
            new_encrypted_key = Vault._encrypt_ecies(public_key, file_key)
            
            vault_container['recipients'].append({
                "id": recipient_id,
                "encrypted_key": new_encrypted_key
            })
            print(f"  {C_GREEN}[OK]{C_END} Destinatario '{recipient_id}' añadido al vault.")

        # --- 4. Actualizar metadatos y guardar ---
        # Actualizar la lista de destinatarios en el header para la verificación AAD
        vault_container['header']['recipients'] = [r['id'] for r in vault_container['recipients']]
        
        # Re-cifrar el contenido con el AAD actualizado
        # Esto es CRÍTICO para la seguridad. Si solo actualizamos el header, el tag no coincidirá.
        print("  Actualizando AAD y volviendo a cifrar...")
        aesgcm = AESGCM(file_key)
        new_aad = json.dumps(vault_container['header'], sort_keys=True).encode('utf-8')
        
        # Leemos el contenido descifrado en memoria para volver a cifrarlo
        # (En un sistema real, esto podría ser ineficiente para archivos grandes)
        # CUIDADO: El AAD original debe ser reconstruido exactamente como estaba durante el cifrado inicial.
        original_header = Container.load(vault_path)['header']
        original_aad = json.dumps(original_header, sort_keys=True).encode('utf-8')
        
        temp_decrypted_data = aesgcm.decrypt(
            vault_container['nonce'], 
            vault_container['ciphertext'] + vault_container['authentication_tag'], 
            original_aad
        )

        new_ciphertext_with_tag = aesgcm.encrypt(vault_container['nonce'], temp_decrypted_data, new_aad)
        vault_container['ciphertext'] = new_ciphertext_with_tag[:-16]
        vault_container['authentication_tag'] = new_ciphertext_with_tag[-16:]
        
        # --- 5. Re-firmar el vault ---
        if signer_private_key:
            data_to_sign = new_aad + vault_container['ciphertext'] + vault_container['authentication_tag']
            vault_container['signature'] = signer_private_key.sign(data_to_sign)
            vault_container['signer_id'] = existing_recipient_id
            print(f"  {C_GREEN}[OK]{C_END} Vault re-firmado por '{existing_recipient_id}'.")
        
        Container.save(vault_container, vault_path)
        print(f"\n{C_GREEN}[ÉXITO] Vault '{os.path.basename(vault_path)}' actualizado con los nuevos destinatarios.{C_END}")

    except Exception as e:
        print(f"{C_RED}[ERROR] Falló el proceso de añadir destinatarios: {e}{C_END}")


if _name_ == "_main_":
    # Listar y seleccionar vault
    available_vaults = list_vaults()
    if not available_vaults:
        print(f"{C_YELLOW}No se encontraron archivos .vault en la carpeta 'encrypted_vault'.{C_END}")
    else:
        print(f"{C_MAGENTA}--- Compartir un Vault Existente ---{C_END}")
        print("Vaults disponibles:")
        for i, v_name in enumerate(available_vaults):
            print(f"  [{i+1}] {C_BLUE}{v_name}{C_END}")
        
        try:
            choice = int(input("Elige el número del vault a compartir: ")) - 1
            if not 0 <= choice < len(available_vaults):
                raise ValueError()
            vault_to_share = os.path.join("encrypted_vault", available_vaults[choice])
        except (ValueError, IndexError):
            print(f"{C_RED}Selección no válida.{C_END}")
            exit()

        # Pedir credenciales del usuario actual
        print(f"\n{C_MAGENTA}--- Autorización Requerida ---{C_END}")
        print("Necesitas ser un destinatario existente para poder compartir.")
        current_user_id = input("Introduce tu ID de usuario: ")
        current_user_pk_path = input(f"Introduce la ruta a tu clave privada ('{current_user_id}'): ")

        if not os.path.exists(current_user_pk_path):
            print(f"{C_RED}[ERROR] La clave privada en '{current_user_pk_path}' no existe.{C_END}")
        else:
            print(f"\n{C_MAGENTA}--- Autenticación de Origen (Firma) ---{C_END}")
            print("Al modificar el vault, debes refirmarlo con tu propia clave.")
            signer_key_path = input(f"Introduce la ruta a tu clave privada de firma ('{current_user_id}'): ")
            signer_password = getpass.getpass(f"Introduce la contraseña para tu clave de firma: ")
            
            try:
                signer_private_key = KeyManager.load_asymmetric_key(signer_key_path, password=signer_password)
            except Exception as e:
                print(f"{C_RED}[ERROR] No se pudo cargar la clave de firma: {e}{C_END}")
                exit(1)

            # Recopilar nuevos destinatarios
            new_recipients = []
            print(f"\n{C_MAGENTA}--- Añadir Nuevos Destinatarios ---{C_END}")
            while True:
                user_id = input("Introduce el ID del nuevo destinatario (o presiona Enter para terminar): ")
                if not user_id:
                    break
                
                pub_key_path = input(f"Introduce la ruta a la clave pública de '{user_id}': ")
                
                if not os.path.exists(pub_key_path):
                    print(f"{C_RED}[ERROR] La clave pública en '{pub_key_path}' no existe.{C_END}")
                    continue
                
                try:
                    public_key = KeyManager.load_asymmetric_key(pub_key_path, is_public=True)
                    new_recipients.append({"id": user_id, "public_key": public_key})
                    print(f"  {C_GREEN}[OK]{C_END} Nuevo destinatario '{user_id}' listo para ser añadido.")
                except Exception as e:
                    print(f"{C_RED}[ERROR] No se pudo cargar la clave pública: {e}{C_END}")

            # Ejecutar la lógica si hay nuevos destinatarios
            if new_recipients:
                add_recipients_to_vault(vault_to_share, current_user_id, current_user_pk_path, new_recipients, signer_private_key)
            else:
                print(f"\n{C_YELLOW}No se añadieron nuevos destinatarios. Proceso cancelado.{C_END}")