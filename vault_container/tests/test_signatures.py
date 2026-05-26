import unittest
import copy

from src.crypto_vault.key_manager import KeyManager
from src.crypto_vault.vault import Vault


class TestDigitalSignatures(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Llaves de cifrado (ECC)
        cls.alice_priv, cls.alice_pub = KeyManager.generate_ecc_key_pair()
        cls.bob_priv, cls.bob_pub = KeyManager.generate_ecc_key_pair()

        # Llaves de firma (Ed25519)
        cls.alice_sign_priv, cls.alice_sign_pub = KeyManager.generate_ed25519_key_pair()
        cls.eve_sign_priv, cls.eve_sign_pub = KeyManager.generate_ed25519_key_pair()

        # Datos
        cls.data = b"Mensaje secreto firmado"

        # Destinatarios
        cls.recipients = [
            {"id": "bob", "public_key": cls.bob_pub}
        ]

        # Vault firmado por Alice
        cls.vault = Vault.encrypt(
            cls.data,
            cls.recipients,
            metadata={"file": "test.txt"},
            signer_private_key=cls.alice_sign_priv,
            signer_id="alice"
        )

    # 1. Firma válida → debe aceptar
    def test_valid_signature(self):
        decrypted = Vault.decrypt(
            self.vault,
            "bob",
            self.bob_priv,
            signer_public_key=self.alice_sign_pub
        )
        self.assertEqual(decrypted, self.data)

    # 2. Ciphertext modificado → debe rechazar
    def test_modified_ciphertext_fails(self):
        tampered = copy.deepcopy(self.vault)
        tampered["ciphertext"] = tampered["ciphertext"][:-1] + b'\x00'

        with self.assertRaises(ValueError):
            Vault.decrypt(
                tampered,
                "bob",
                self.bob_priv,
                signer_public_key=self.alice_sign_pub
            )

    # 3. Metadata modificada → debe rechazar
    def test_modified_metadata_fails(self):
        tampered = copy.deepcopy(self.vault)
        tampered["header"]["file"] = "hacked.txt"

        with self.assertRaises(ValueError):
            Vault.decrypt(
                tampered,
                "bob",
                self.bob_priv,
                signer_public_key=self.alice_sign_pub
            )

    # 4. Llave pública incorrecta → debe rechazar
    def test_wrong_public_key_fails(self):
        with self.assertRaises(ValueError):
            Vault.decrypt(
                self.vault,
                "bob",
                self.bob_priv,
                signer_public_key=self.eve_sign_pub
            )

    # 5. Firma eliminada → debe rechazar
    def test_removed_signature_fails(self):
        tampered = copy.deepcopy(self.vault)
        tampered.pop("signature")
        tampered.pop("signer_id")

        with self.assertRaises(ValueError):
            Vault.decrypt(
                tampered,
                "bob",
                self.bob_priv,
                signer_public_key=self.alice_sign_pub
            )


if __name__ == "__main__":
    unittest.main()