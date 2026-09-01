import unittest
from cryptography.exceptions import InvalidTag

from password_manager import PasswordManager


class PasswordManagerTests(unittest.TestCase):
    MASTER = "master1234"
    ALT_MASTER = "4321retsam"

    PASSWORDS = {
        "domainA": "passwordA",
        "domainB": "passwordB",
        "domainC": "passwordC",
        "veryVeryVeryLongDomainNameOfOneHundredTwentyEightPlusCharactersReVeryVeryVeryLongDomainNameOfOneHundredTwentyEightPlusCharacters": "veryVeryLongDomainNamePassword",
        "domainE": "passwordE",
    }

    def create_manager(self, entries=None, master=None):
        manager = PasswordManager(master or self.MASTER)

        for domain, password in (entries or self.PASSWORDS).items():
            manager.set(domain, password)

        return manager

    # ------------------------------------------------------------------
    # Basic password-manager behavior
    # ------------------------------------------------------------------

    def test_set_and_get(self):
        manager = self.create_manager()

        for domain, password in self.PASSWORDS.items():
            self.assertEqual(manager.get(domain), password)

    def test_set_updates_existing_password(self):
        manager = PasswordManager(self.MASTER)

        manager.set("example.com", "oldPassword")
        self.assertEqual(manager.get("example.com"), "oldPassword")

        manager.set("example.com", "newPassword")
        self.assertEqual(manager.get("example.com"), "newPassword")

    def test_get_missing_domain_returns_none(self):
        manager = PasswordManager(self.MASTER)

        self.assertIsNone(manager.get("does-not-exist.com"))

    def test_remove_existing_domain(self):
        manager = self.create_manager()

        self.assertTrue(manager.remove("domainA"))
        self.assertIsNone(manager.get("domainA"))

    def test_remove_missing_domain_returns_false(self):
        manager = PasswordManager(self.MASTER)

        self.assertFalse(manager.remove("does-not-exist.com"))

    def test_remove_does_not_affect_other_domains(self):
        manager = self.create_manager()

        manager.remove("domainA")

        self.assertIsNone(manager.get("domainA"))
        self.assertEqual(manager.get("domainB"), "passwordB")
        self.assertEqual(manager.get("domainC"), "passwordC")

    # ------------------------------------------------------------------
    # Password length and generation
    # ------------------------------------------------------------------

    def test_set_accepts_maximum_password_length(self):
        manager = PasswordManager(self.MASTER)
        password = "a" * manager.MAX_PASSWORD_LEN

        manager.set("example.com", password)

        self.assertEqual(manager.get("example.com"), password)

    def test_set_rejects_password_longer_than_maximum(self):
        manager = PasswordManager(self.MASTER)
        password = "a" * (manager.MAX_PASSWORD_LEN + 1)

        with self.assertRaises(ValueError):
            manager.set("example.com", password)

    def test_generate_new_creates_password_of_requested_length(self):
        manager = PasswordManager(self.MASTER)

        password = manager.generate_new("example.com", 16)

        self.assertEqual(len(password), 16)
        self.assertTrue(password.isalnum())
        self.assertEqual(manager.get("example.com"), password)

    def test_generate_new_accepts_maximum_password_length(self):
        manager = PasswordManager(self.MASTER)

        password = manager.generate_new(
            "example.com",
            manager.MAX_PASSWORD_LEN,
        )

        self.assertEqual(len(password), manager.MAX_PASSWORD_LEN)
        self.assertTrue(password.isalnum())
        self.assertEqual(manager.get("example.com"), password)

    def test_generate_new_rejects_password_longer_than_maximum(self):
        manager = PasswordManager(self.MASTER)

        with self.assertRaises(ValueError):
            manager.generate_new(
                "example.com",
                manager.MAX_PASSWORD_LEN + 1,
            )

    def test_generate_new_rejects_existing_domain(self):
        manager = PasswordManager(self.MASTER)
        manager.set("example.com", "existingPassword")

        with self.assertRaises(ValueError):
            manager.generate_new("example.com", 16)

    def test_generate_new_creates_different_passwords_for_different_domains(self):
        manager = PasswordManager(self.MASTER)

        password_a = manager.generate_new("domainA", 32)
        password_b = manager.generate_new("domainB", 32)

        self.assertNotEqual(password_a, password_b)

    def test_non_ascii_master_password_is_rejected(self):
        with self.assertRaises(ValueError):
            PasswordManager("pässwörd123")

    def test_non_ascii_domain_is_rejected(self):
        manager = PasswordManager(self.MASTER)
        with self.assertRaises(ValueError):
            manager.set("exämple.com", "password")

    def test_non_ascii_password_is_rejected(self):
        manager = PasswordManager(self.MASTER)
        with self.assertRaises((ValueError, UnicodeEncodeError)):
            manager.set("example.com", "pässwörd")

    # ------------------------------------------------------------------
    # Serialization and reconstruction
    # ------------------------------------------------------------------

    def test_dump_and_reconstruct(self):
        manager = self.create_manager()

        data, checksum = manager.dump()
        reconstructed = PasswordManager(self.MASTER, data, checksum)

        for domain, password in self.PASSWORDS.items():
            self.assertEqual(reconstructed.get(domain), password)

    def test_reconstructed_manager_can_be_modified(self):
        manager = self.create_manager()

        data, checksum = manager.dump()
        reconstructed = PasswordManager(self.MASTER, data, checksum)

        reconstructed.set("new-domain.com", "newPassword")

        self.assertEqual(
            reconstructed.get("new-domain.com"),
            "newPassword",
        )

    def test_reconstructed_manager_can_remove_entries(self):
        manager = self.create_manager()

        data, checksum = manager.dump()
        reconstructed = PasswordManager(self.MASTER, data, checksum)

        self.assertTrue(reconstructed.remove("domainA"))
        self.assertIsNone(reconstructed.get("domainA"))

        self.assertEqual(
            reconstructed.get("domainB"),
            "passwordB",
        )

    def test_wrong_master_password_is_rejected(self):
        manager = self.create_manager()

        data, checksum = manager.dump()

        with self.assertRaises(ValueError):
            PasswordManager(self.ALT_MASTER, data, checksum)

    def test_swap_attack_detected_after_round_trip(self):
        manager = PasswordManager(self.MASTER)
        manager.set("domainA", "passwordA")
        manager.set("domainB", "passwordB")

        data, checksum = manager.dump()
        reconstructed = PasswordManager(self.MASTER, data, checksum)

        key_a = reconstructed._hash_domain("domainA")
        key_b = reconstructed._hash_domain("domainB")
        reconstructed._kvs[key_a], reconstructed._kvs[key_b] = (
            reconstructed._kvs[key_b],
            reconstructed._kvs[key_a],
        )

        with self.assertRaises(ValueError):
            reconstructed.get("domainA")

    # ------------------------------------------------------------------
    # Serialization integrity
    # ------------------------------------------------------------------

    def test_two_dumps_of_same_manager_are_different(self):
        manager = self.create_manager()

        data1, checksum1 = manager.dump()
        data2, checksum2 = manager.dump()

        self.assertNotEqual(data1, data2)
        self.assertNotEqual(checksum1, checksum2)

    def test_two_managers_with_same_contents_have_different_dumps(self):
        manager1 = self.create_manager()
        manager2 = self.create_manager()

        data1, checksum1 = manager1.dump()
        data2, checksum2 = manager2.dump()

        self.assertNotEqual(data1, data2)
        self.assertNotEqual(checksum1, checksum2)

    def test_checksum_changes_when_vault_changes(self):
        manager = PasswordManager(self.MASTER)
        manager.set("example.com", "password")

        _, checksum1 = manager.dump()

        manager.set("example.com", "differentPassword")

        _, checksum2 = manager.dump()

        self.assertNotEqual(checksum1, checksum2)

    def test_checksum_detects_modified_serialized_data(self):
        manager = self.create_manager()

        data, checksum = manager.dump()

        data_bytes = bytearray.fromhex(data)
        data_bytes[-1] ^= 0x01
        modified_data = bytes(data_bytes).hex()

        with self.assertRaises(ValueError):
            PasswordManager(self.MASTER, modified_data, checksum)

    def test_modified_checksum_is_rejected(self):
        manager = self.create_manager()

        data, checksum = manager.dump()

        modified_checksum = ("0" if checksum[0] != "0" else "1") + checksum[1:]

        with self.assertRaises(ValueError):
            PasswordManager(self.MASTER, data, modified_checksum)

    def test_invalid_checksum_is_rejected(self):
        manager = self.create_manager()

        data, checksum = manager.dump()

        with self.assertRaises(ValueError):
            PasswordManager(
                self.MASTER,
                data,
                checksum[:-2],
            )

    def test_domain_names_do_not_appear_in_dump(self):
        manager = PasswordManager(self.MASTER)
        manager.set("supersecretbank.com", "password123")

        data, _ = manager.dump()

        self.assertNotIn("supersecretbank.com", data)
        self.assertNotIn(
            "supersecretbank.com".encode("ascii").hex(),
            data,
        )

    def test_ciphertext_size_independent_of_password_length(self):
        manager = PasswordManager(self.MASTER)
        manager.set("short.com", "a")
        manager.set("long.com", "a" * manager.MAX_PASSWORD_LEN)

        short_entry = manager._kvs[manager._hash_domain("short.com")]
        long_entry = manager._kvs[manager._hash_domain("long.com")]

        self.assertEqual(len(short_entry), len(long_entry))

    # ------------------------------------------------------------------
    # Vault corruption / malformed input
    # ------------------------------------------------------------------

    def test_invalid_hex_data_is_rejected(self):
        with self.assertRaises(ValueError):
            PasswordManager(
                self.MASTER,
                "this-is-not-hex",
                b"checksum",
            )

    def test_truncated_vault_is_rejected(self):
        manager = self.create_manager()

        data, checksum = manager.dump()

        data_bytes = bytes.fromhex(data)
        truncated_data = data_bytes[:-1].hex()

        with self.assertRaises(ValueError):
            PasswordManager(
                self.MASTER,
                truncated_data,
                checksum,
            )

    # ------------------------------------------------------------------
    # Per-entry authenticated encryption
    # ------------------------------------------------------------------

    def test_tampered_password_ciphertext_is_rejected(self):
        manager = PasswordManager(self.MASTER)
        manager.set("example.com", "secretPassword")

        domain_key = manager._hash_domain("example.com")
        ciphertext = bytearray(manager._kvs[domain_key])

        ciphertext[-1] ^= 0x01
        manager._kvs[domain_key] = bytes(ciphertext)

        with self.assertRaises(ValueError):
            manager.get("example.com")

    def test_tampered_outer_nonce_is_rejected(self):
        manager = self.create_manager()

        data, _ = manager.dump()

        data_bytes = bytearray.fromhex(data)

        # Salt = first 16 bytes
        # Outer nonce = next 12 bytes
        data_bytes[16] ^= 0x01

        with self.assertRaises(ValueError):
            PasswordManager(self.MASTER, bytes(data_bytes).hex())

    def test_password_ciphertext_cannot_be_swapped_between_domains(self):
        manager = PasswordManager(self.MASTER)
        manager.set("domainA", "passwordA")
        manager.set("domainB", "passwordB")

        domain_a_key = manager._hash_domain("domainA")
        domain_b_key = manager._hash_domain("domainB")

        ciphertext_a = manager._kvs[domain_a_key]
        ciphertext_b = manager._kvs[domain_b_key]

        manager._kvs[domain_a_key] = ciphertext_b
        manager._kvs[domain_b_key] = ciphertext_a

        with self.assertRaises(ValueError):
            manager.get("domainA")

        with self.assertRaises(ValueError):
            manager.get("domainB")

    def test_tampered_serialized_data_is_rejected_without_checksum(self):
        manager = self.create_manager()

        data, _ = manager.dump()

        data_bytes = bytearray.fromhex(data)
        data_bytes[-1] ^= 1

        with self.assertRaises(ValueError):
            PasswordManager(self.MASTER, bytes(data_bytes).hex())

    # ------------------------------------------------------------------
    # Persistence of multiple entries
    # ------------------------------------------------------------------

    def test_updates_survive_serialization(self):
        manager = self.create_manager()

        manager.set("domainA", "updatedPassword")
        manager.remove("domainB")
        manager.set("newDomain", "newPassword")

        data, checksum = manager.dump()
        reconstructed = PasswordManager(self.MASTER, data, checksum)

        self.assertEqual(
            reconstructed.get("domainA"),
            "updatedPassword",
        )
        self.assertIsNone(reconstructed.get("domainB"))
        self.assertEqual(
            reconstructed.get("newDomain"),
            "newPassword",
        )

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def test_generate_new_rejects_negative_length(self):
        manager = PasswordManager(self.MASTER)

        with self.assertRaises(ValueError):
            manager.generate_new("example.com", -1)

    def test_password_starting_with_null_round_trips(self):
        manager = PasswordManager(self.MASTER)

        password = "\0secret"
        manager.set("example.com", password)

        self.assertEqual(manager.get("example.com"), password)

    def test_updating_password_uses_new_nonce(self):
        manager = PasswordManager(self.MASTER)

        manager.set("example.com", "password1")
        first = manager._kvs[manager._hash_domain("example.com")]

        manager.set("example.com", "password2")
        second = manager._kvs[manager._hash_domain("example.com")]

        self.assertNotEqual(first[:12], second[:12])
        self.assertNotEqual(first, second)

    def test_different_entries_use_different_nonces(self):
        manager = PasswordManager(self.MASTER)

        manager.set("domainA", "passwordA")
        manager.set("domainB", "passwordB")
        manager.set("domainC", "passwordC")

        key_a = manager._hash_domain("domainA")
        key_b = manager._hash_domain("domainB")
        key_c = manager._hash_domain("domainC")

        nonce_a = manager._kvs[key_a][:12]
        nonce_b = manager._kvs[key_b][:12]
        nonce_c = manager._kvs[key_c][:12]

        self.assertEqual(len({nonce_a, nonce_b, nonce_c}), 3)


if __name__ == "__main__":
    unittest.main()
