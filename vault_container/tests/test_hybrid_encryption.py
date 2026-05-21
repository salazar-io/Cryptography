import unittest
from src.crypto_vault.key_manager import KeyManager
from src.crypto_vault.vault import Vault

class TestVaultSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Genera claves para 3 usuarios: Alice, Bob (autorizados) y Eve (atacante)
        cls.alice_priv, cls.alice_pub = KeyManager.generate_ecc_key_pair()
        cls.bob_priv, cls.bob_pub = KeyManager.generate_ecc_key_pair()
        cls.eve_priv, cls.eve_pub = KeyManager.generate_ecc_key_pair()
        
        cls.plaintext = b"Este es un archivo ultra secreto."
        cls.recipients = [
            {"id": "alice", "public_key": cls.alice_pub},
            {"id": "bob", "public_key": cls.bob_pub}
        ]
        
        # Cifra el archivo una sola vez
        cls.vault_data = Vault.encrypt(cls.plaintext, cls.recipients, metadata={"filename": "secreto.txt"})

    def test_1_authorized_users_can_decrypt(self):
        """Si el archivo se comparte con dos usuarios, ambos podrán descifrarlo."""
        decrypted_alice = Vault.decrypt(self.vault_data, "alice", self.alice_priv)
        decrypted_bob = Vault.decrypt(self.vault_data, "bob", self.bob_priv)
        
        self.assertEqual(decrypted_alice, self.plaintext)
        self.assertEqual(decrypted_bob, self.plaintext)

    def test_2_unauthorized_user_cannot_decrypt(self):
        """El usuario no autorizado no puede descifrar."""
        # Eve intenta descifrar pero su ID no está en el vault
        with self.assertRaisesRegex(ValueError, "Destinatario 'eve' no encontrado"):
            Vault.decrypt(self.vault_data, "eve", self.eve_priv)

    def test_3_tampered_recipient_list_fails(self):
        """Si la lista de destinatarios ha sido manipulada, el descifrado falla por el AAD."""
        tampered_vault = dict(self.vault_data)
        # Un atacante intenta añadir a Eve modificando el header (AAD)
        tampered_vault["header"]["recipients"].append("eve")
        
        # Aunque Alice intente descifrar con su clave válida, el tag GCM no coincidirá
        with self.assertRaises(ValueError):
            Vault.decrypt(tampered_vault, "alice", self.alice_priv)

    def test_4_wrong_private_key_fails(self):
        """Si se introduce una clave privada incorrecta, se producirá un fallo."""
        # Eve intenta hacerse pasar por Alice usando el ID de Alice pero su propia clave privada
        with self.assertRaises(ValueError):
            Vault.decrypt(self.vault_data, "alice", self.eve_priv)

    def test_5_removed_recipient_breaks_access(self):
        """Eliminar una entrada de destinatario interrumpe el acceso."""
        tampered_vault = dict(self.vault_data)
        # Eliminamos la entrada cifrada de Bob
        tampered_vault["recipients"] = [r for r in tampered_vault["recipients"] if r["id"] != "bob"]
        
        with self.assertRaisesRegex(ValueError, "Destinatario 'bob' no encontrado"):
            Vault.decrypt(tampered_vault, "bob", self.bob_priv)

if __name__ == '__main__':
    unittest.main()