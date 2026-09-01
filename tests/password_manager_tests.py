import unittest

from password_manager import PasswordManager

class PasswordManagerTests(unittest.TestCase):
    MASTER_PASSWORD = "master1234"
    ALTERNATE_MASTER_PASSWORD = "4321retsam"

    PASSWORDS = {
        "domainA": "passwordA",
        "domainB": "passwordB",
        "domainC": "passwordC",
        (
            "veryVeryVeryLongDomainNameOfOneHundredTwentyEightPlusCharactersRe"
            "VeryVeryVeryLongDomainNameOfOneHundredTwentyEightPlusCharacters"
        ): "veryVeryLongDomainNamePassword",
        "domainE": "passwordE",
    }

    def create_manager_with_passwords(self, master_password=MASTER_PASSWORD):
        manager = PasswordManager(master_password)

        for domain, password in self.PASSWORDS.items():
            manager.set(domain, password)

        return manager

    def test_set_and_get_password(self):
        manager = PasswordManager(self.MASTER_PASSWORD)

        for domain, password in self.PASSWORDS.items():
            manager.set(domain, password)

        for domain, password in self.PASSWORDS.items():
            self.assertEqual(manager.get(domain), password)

    def test_set_updates_existing_password(self):
        manager = self.create_manager_with_passwords()
        replacement_password = "replacePassword"

        for domain in self.PASSWORDS:
            manager.set(domain, replacement_password)

        for domain in self.PASSWORDS:
            self.assertEqual(manager.get(domain), replacement_password)

    def test_get_missing_domain_returns_none(self):
        manager = PasswordManager(self.MASTER_PASSWORD)

        self.assertIsNone(manager.get("missingDomain"))

    def test_remove_existing_password(self):
        manager = self.create_manager_with_passwords()

        for domain in self.PASSWORDS:
            self.assertTrue(manager.remove(domain))
            self.assertIsNone(manager.get(domain))

    def test_remove_missing_password_returns_false(self):
        manager = PasswordManager(self.MASTER_PASSWORD)

        self.assertFalse(manager.remove("missingDomain"))

    def test_dump_produces_different_data_each_time(self):
        manager = self.create_manager_with_passwords()

        data1, checksum1 = manager.dump()
        data2, checksum2 = manager.dump()

        self.assertNotEqual(data1, data2)
        self.assertNotEqual(checksum1, checksum2)

    def test_separate_managers_produce_different_dumps(self):
        manager1 = self.create_manager_with_passwords()
        manager2 = self.create_manager_with_passwords()

        data1, checksum1 = manager1.dump()
        data2, checksum2 = manager2.dump()

        self.assertNotEqual(data1, data2)
        self.assertNotEqual(checksum1, checksum2)

        for domain, password in self.PASSWORDS.items():
            self.assertEqual(manager1.get(domain), password)
            self.assertEqual(manager2.get(domain), password)

    def test_different_master_passwords_produce_different_dumps(self):
        manager1 = self.create_manager_with_passwords(
            self.MASTER_PASSWORD
        )
        manager2 = self.create_manager_with_passwords(
            self.ALTERNATE_MASTER_PASSWORD
        )

        _, checksum1 = manager1.dump()
        _, checksum2 = manager2.dump()

        self.assertNotEqual(checksum1, checksum2)

    def test_reconstruct_manager_from_dump(self):
        manager = self.create_manager_with_passwords()
        data, checksum = manager.dump()

        restored_manager = PasswordManager(
            self.MASTER_PASSWORD,
            data,
            checksum,
        )

        for domain, password in self.PASSWORDS.items():
            self.assertEqual(restored_manager.get(domain), password)

    def test_reconstruct_with_wrong_master_password_fails(self):
        manager = self.create_manager_with_passwords()
        data, checksum = manager.dump()

        with self.assertRaises(ValueError):
            PasswordManager(
                self.ALTERNATE_MASTER_PASSWORD,
                data,
                checksum,
            )

    def test_generated_password_has_requested_length(self):
        manager = PasswordManager(self.MASTER_PASSWORD)

        password = manager.generate_new("testDomain", 16)

        self.assertEqual(len(password), 16)
        self.assertTrue(password.isalnum())

    def test_generated_password_is_stored(self):
        manager = PasswordManager(self.MASTER_PASSWORD)

        password = manager.generate_new("testDomain", 16)

        self.assertEqual(manager.get("testDomain"), password)

    def test_generate_password_for_existing_domain_fails(self):
        manager = PasswordManager(self.MASTER_PASSWORD)
        manager.set("testDomain", "existingPassword")

        with self.assertRaises(ValueError):
            manager.generate_new("testDomain", 16)

    def test_generate_password_over_maximum_length_fails(self):
        manager = PasswordManager(self.MASTER_PASSWORD)

        with self.assertRaises(ValueError):
            manager.generate_new(
                "testDomain",
                manager.MAX_PASSWORD_LEN + 1,
            )

    def test_set_password_over_maximum_length_fails(self):
        manager = PasswordManager(self.MASTER_PASSWORD)
        password = "a" * (manager.MAX_PASSWORD_LEN + 1)

        with self.assertRaises(ValueError):
            manager.set("testDomain", password)



    def test_modified_ciphertext_is_rejected(self):
        manager = self.create_manager_with_passwords()
        data, checksum = manager.dump()

        modified_data = data[:-2] + (
            "00" if data[-2:] != "00" else "ff"
        )

        with self.assertRaises(ValueError):
            PasswordManager(
                self.MASTER_PASSWORD,
                modified_data,
                checksum,
            )

    def test_modified_vault_data_with_original_checksum_is_rejected(self):
        manager = self.create_manager_with_passwords()
        data, checksum = manager.dump()

        modified_data = data[:-2] + (
            "00" if data[-2:] != "00" else "ff"
        )

        with self.assertRaises(ValueError):
            PasswordManager(
                self.MASTER_PASSWORD,
                modified_data,
                checksum,
            )

    def test_modified_checksum_is_rejected(self):
        manager = self.create_manager_with_passwords()
        data, checksum = manager.dump()

        modified_checksum = bytearray(checksum)
        modified_checksum[0] ^= 0xFF

        with self.assertRaises(ValueError):
            PasswordManager(
                self.MASTER_PASSWORD,
                data,
                bytes(modified_checksum),
            )

    def test_malformed_serialized_data_is_rejected(self):
        manager = PasswordManager(self.MASTER_PASSWORD)

        malformed_data = "not valid serialized vault data"

        with self.assertRaises(ValueError):
            PasswordManager(
                self.MASTER_PASSWORD,
                malformed_data,
                b"invalid checksum",
            )


if __name__ == "__main__":
    unittest.main()
