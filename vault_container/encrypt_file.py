import os
import secrets
import getpass
from src.crypto_vault.vault import Vault
from src.crypto_vault.key_manager import KeyManager
from src.crypto_vault.container import Container

def secure_delete(path, passes=3):
    """Sobrescribe un archivo con datos aleatorios antes de eliminarlo."""
    if not os.path.exists(path):
        return
    try:
        length = os.path.getsize(path)
        with open(path, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(length))
        os.remove(path)
        print(f"  [OK] Archivo original '{path}' eliminado de forma segura.")
    except Exception as e:
        print(f"  [ERROR] No se pudo eliminar de forma segura '{path}': {e}")

def encrypt_file(file_path, output_dir, key_path, password):
    # 1. Cargar o generar la llave
    if os.path.exists(key_path):
        key = KeyManager.load_key_file(key_path, password)
    else:
        print("Generando nueva llave protegida...")
        key = KeyManager.generate_key_file(key_path, password)

    # 2. Asegurar que la carpeta de destino existe
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 3. Procesar el archivo
    if os.path.isfile(file_path):
        filename = os.path.basename(file_path)
        print(f"Cifrando: {filename}...")
        
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            metadata = {"original_name": filename, "type": filename.split(".")[-1]}
            vault_dict = Vault.encrypt(data, key, metadata)
            
            # El contenedor se guarda como una carpeta con el nombre del archivo
            container_path = os.path.join(output_dir, f"vault_{filename}")
            Container.save(vault_dict, container_path)
            
            # 4. VERIFICACIÓN CRÍTICA antes del borrado
            loaded = Container.load(container_path)
            Vault.decrypt(loaded, key)
            
            # 5. Borrado Seguro
            secure_delete(file_path)
            print(f"\n[ÉXITO] Archivo cifrado y original eliminado en: {container_path}")
            
        except Exception as e:
            print(f"\n[ERROR] Falló el proceso: {e}")
            print("El archivo original se mantuvo intacto por seguridad.")
    else:
        print(f"Error: El archivo '{file_path}' no existe.")

if __name__ == "__main__":
    archivo = input("Introduce la ruta del archivo a cifrar: ")
    if not os.path.exists(archivo):
        # Intentar buscarlo en la carpeta plaintext por comodidad
        archivo_buscado = os.path.join("plaintext", archivo)
        if os.path.exists(archivo_buscado):
            archivo = archivo_buscado

    pwd = getpass.getpass("Introduce la contraseña de la llave: ")
    encrypt_file(archivo, "encrypted_vault", "vault.key", pwd)


