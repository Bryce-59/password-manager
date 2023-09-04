import unittest

from password_manager import PasswordManager

class PasswordManagerTests(unittest.TestCase):

  kvs = { 'domainA': 'passwordA', 
          'domainB': 'passwordB',
          'domainC': 'passwordC',
          'veryVeryVeryLongDomainNameOfOneHundredTwentyEightPlusCharactersReVeryVeryVeryLongDomainNameOfOneHundredTwentyEightPlusCharacters': 'veryVeryLongDomainNamePassword',
          'domainE' : 'passwordE'}
  master = 'master1234'
  altMaster = '4321retsam'

  def test_set_get(self):
    # test that set and get both work as intended
    password_manager = PasswordManager(self.master)
    for domain in self.kvs:
      password_manager.set(domain, self.kvs[domain])

    for domain in self.kvs:
      self.assertTrue(password_manager.get(domain) == self.kvs[domain])

    newVal = "replacePassword"
    for domain in self.kvs:
      password_manager.set(domain, newVal)
    
    for domain in self.kvs:
      self.assertTrue(password_manager.get(domain) == newVal)


  def test_checksum(self):
     # test that the checksum and the encrypted data is different for one passwordManager
      password_manager = PasswordManager(self.master)
      for domain in self.kvs:
        password_manager.set(domain, self.kvs[domain])

      data1, checksum1 = password_manager.dump()
      data2, checksum2 = password_manager.dump()
      self.assertFalse(checksum1 == checksum2)
      self.assertFalse(data1 == data2)

      # test that the checksum is different for two similar passwordManagers
      password_manager2 = PasswordManager(self.master)
      for domain in self.kvs:
        password_manager2.set(domain, self.kvs[domain])

      for domain in self.kvs: # quickly test for equality
        self.assertTrue(password_manager.get(domain) == password_manager2.get(domain))
      
      _, checksum3 = password_manager2.dump()
      self.assertFalse(checksum1 == checksum3)

      # test that the checksum is different for two different passwordManagers
      password_manager3 = PasswordManager(self.altMaster)
      for domain in self.kvs:
        password_manager3.set(domain, self.kvs[domain])

      for domain in self.kvs: # quickly test for equality
        self.assertTrue(password_manager.get(domain) == password_manager3.get(domain))
      
      _, checksum4 = password_manager3.dump()
      self.assertFalse(checksum1 == checksum4)

  def test_remove(self):
      # test that the remove function works as intended
      password_manager = PasswordManager(self.master)
      for domain in self.kvs:
        password_manager.set(domain, self.kvs[domain])
      
      for domain in self.kvs: # test successful removal
         self.assertTrue(password_manager.remove(domain))

      for domain in self.kvs: # test that entries no longer exist
         self.assertFalse(password_manager.get(domain) == self.kvs[domain])

      for domain in self.kvs: # test return value
         self.assertFalse(password_manager.remove(domain))

  def test_reconstruct(self):
      # test that the passwordManager can be reconstructed from serialized data
      password_manager = PasswordManager(self.master)
      for domain in self.kvs:
        password_manager.set(domain, self.kvs[domain])

      data, checksum = password_manager.dump()

      clone_pw_manager = None
      try:
        clone_pw_manager = PasswordManager(self.master, data, checksum)
      except:
         self.assertTrue(True == False)

      for domain in self.kvs:
        self.assertTrue(clone_pw_manager.get(domain) == self.kvs[domain])

      # test that the passwordManager cannot be built without the master password
      self.assertRaises(ValueError, PasswordManager, self.altMaster, data, checksum)

  def test_password(self):
      # test that the generate password function works as intended 
      password_manager = PasswordManager(self.master)
      for domain in self.kvs:
        password_manager.set(domain, self.kvs[domain])

      domain = 'testDomain'
      newDomain = 'testDomain2'
      length = 16
      pw = password_manager.generate_new(domain, length)
      self.assertTrue(len(pw) == length)
      self.assertTrue(pw.isalnum())

      self.assertRaises(ValueError, password_manager.generate_new, domain, length)
      self.assertRaises(ValueError, password_manager.generate_new, newDomain, password_manager.MAX_PASSWORD_LEN + 1)

      pw = password_manager.generate_new(newDomain, length)
      self.assertTrue(len(pw) == length)
      self.assertTrue(pw.isalnum())

if __name__ == "__main__":
    unittest.main()
