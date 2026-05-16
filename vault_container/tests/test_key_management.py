import unittest
import os
import shutil
import tempfile
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from src.crypto_vault.key_manager import KeyManager

class TestKeyManagement(unittest.TestCase):

    def setUp(self):
        # Crear un directorio temporal para las pruebas
        self.test_dir = tempfile.mkdtemp()
        self.keystore_path = os.path.join(self.test_dir, "keystore")
        self.password = "ContrasenaSuperSegura123!"
        
        # Generar claves de prueba
        self.priv_ecc, _ = KeyManager.generate_ecc_key_pair()
        self.priv_sign, _ = KeyManager.generate_ed25519_key_pair()

        # Guardarlas
        KeyManager.save_keystore(self.priv_ecc, self.priv_sign, self.keystore_path, self.password)

    def tearDown(self):
        # Limpiar el directorio temporal
        shutil.rmtree(self.test_dir)

    def test_a_correct_password_grants_access(self):
        """a) Correct password -> access granted"""
        loaded_ecc, loaded_sign = KeyManager.load_keystore(self.keystore_path, self.password)
        
        # Verificar que las claves cargadas sean válidas y coincidan en tipo
        self.assertIsInstance(loaded_ecc, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(loaded_sign, ed25519.Ed25519PrivateKey)

    def test_b_wrong_password_denies_access(self):
        """b) Wrong password -> access denied"""
        with self.assertRaises(ValueError) as context:
            KeyManager.load_keystore(self.keystore_path, "ContrasenaIncorrecta")
        
        self.assertIn("Contraseña incorrecta", str(context.exception))

    def test_c_modified_keystore_fails(self):
        """c) Modified keystore -> failure"""
        # Modificar el archivo encrypted_private_key (alterar un byte)
        enc_priv_path = os.path.join(self.keystore_path, "encrypted_private_key")
        with open(enc_priv_path, "rb") as f:
            data = bytearray(f.read())
        
        # Corromper el último byte (parte del GCM tag o ciphertext)
        data[-1] ^= 0xFF
        
        with open(enc_priv_path, "wb") as f:
            f.write(data)
            
        with self.assertRaises(ValueError) as context:
            KeyManager.load_keystore(self.keystore_path, self.password)
            
        self.assertIn("Contraseña incorrecta o keystore corrupto", str(context.exception))

    def test_d_backup_restore_works(self):
        """d) Backup -> restore works"""
        backup_path = os.path.join(self.test_dir, "backup_keystore")
        
        # Simular backup copiando el directorio
        shutil.copytree(self.keystore_path, backup_path)
        
        # Borrar el original
        shutil.rmtree(self.keystore_path)
        
        # Cargar desde el backup
        loaded_ecc, loaded_sign = KeyManager.load_keystore(backup_path, self.password)
        self.assertIsInstance(loaded_ecc, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(loaded_sign, ed25519.Ed25519PrivateKey)

    def test_e_stolen_keystore_without_password_fails(self):
        """e) Stolen keystore alone -> cannot decrypt"""
        # Intento sin password (None)
        with self.assertRaises(AttributeError):
            # Argon2id intentará hacer encode() a un None y lanzará AttributeError/TypeError
            # o si pasamos "" (string vacío) lanzará ValueError de auth
            KeyManager.load_keystore(self.keystore_path, None)
            
        # Intento con string vacío
        with self.assertRaises(ValueError):
             KeyManager.load_keystore(self.keystore_path, "")

if __name__ == '__main__':
    unittest.main()
