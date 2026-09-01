from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import aead, algorithms, Cipher, modes
from cryptography.hazmat.primitives.kdf import pbkdf2
import os
import pickle

class PasswordManager:
  """
  A class used to manage passwords securely. 
  
  ...

  Methods
  -------

  dump()
    Computes a serialized representation of the password manager together with a checksum.

  generate_new()
    Generates a password for a particular domain.
  
  get()
    Fetches the password associated with a domain from the password manager.

  remove()
    Removes the password for the requested domain from the password manager.

  set()
    Associates a password with a domain in the password manager.
  """

  MAX_PASSWORD_LEN = 64

  def __init__(self, password, data = None, checksum = None):
    """Constructor for the password manager.
    
    Args:
      password (str) : master password for the manager
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty password
                              manager)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """
    self._kvs = {}

    # load the salt or initialize if it is None
    if data is not None:
      data_bytes = bytes.fromhex(data)
      if checksum is not None:
        digest = hashes.Hash(hashes.SHA256(), default_backend())
        digest.update(data_bytes)
        if checksum != digest.finalize():
          raise ValueError("checksums do not match")

      self._salt = data_bytes[:16]
      nonce = data_bytes[16:32]
    else:
      self._salt = os.urandom(16)
      nonce = self._salt
      
    # generate the master key
    kdf = pbkdf2.PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self._salt, iterations = 2000000, backend = default_backend())
    self._master = kdf.derive(bytes(password, 'ascii'))

    if data is not None:
      # check that the password is correct and that the data is well-formed
      aes = Cipher(algorithms.AES(self._master), modes.CTR(nonce), default_backend())
      decryptor = aes.decryptor()
      decrpyted = decryptor.update(data_bytes[32:]) + decryptor.finalize()

      if decrpyted[:16] != self._getKey(self._salt)[:16]:
        raise ValueError("bad password")
      try:
        self._kvs = pickle.loads(decrpyted[16:])
      except:
        raise ValueError("malformed data")
    
    # initialize the seed for self._random()
    digeste = hashes.Hash(hashes.SHA256(), default_backend())
    digeste.update(self._master + nonce)
    self._SEED = digeste.finalize()

  def _getHash(self, key):
    hasher = hmac.HMAC(self._getKey(key), hashes.SHA256(), default_backend())
    hasher.update(key)
    return hasher.finalize()

  def _getKey(self, tag):
    hasher = hmac.HMAC(self._master + self._salt, hashes.SHA256(), default_backend())
    hasher.update(tag)
    return (hasher.finalize())[:16]

  def _random(self):
    digest = hashes.Hash(hashes.SHA256(), default_backend())
    digest.update(self._SEED)
    self._SEED = digest.finalize()
    return self._SEED

  def dump(self):
    """Computes a serialized representation of the password manager
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the password
                   manager (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    dump = pickle.dumps(self._kvs)
    dump_bytes = self._getKey(self._salt)[:16] # a magic number (the key for salt) for verifation
    dump_bytes += dump

    nonce = self._random()[:16]
    aes = Cipher(algorithms.AES(self._master), modes.CTR(nonce), default_backend())
    encryptor = aes.encryptor()
    encrypted = encryptor.update(dump_bytes) + encryptor.finalize()

    serial = self._salt + nonce + encrypted
    digest = hashes.Hash(hashes.SHA256(), default_backend())
    digest.update(serial)
    serial = serial.hex()
    return serial, digest.finalize()
  
  def generate_new(self, domain, desired_len):
    """Generates a password for a particular domain. The password
       is a random string with characters drawn from [A-Za-z0-9].
       The password is automatically added to the password manager for
       the associated domain.
       
       Args:
         domain (str) : the domain to generate a password for
         desired_len (int) : length of the password to generate (in characters)

       Returns:
         password (str) : the generated password

       Raises:
         ValueError : if a password already exists for the provided domain
         ValueError : if the requested password length exceeds the maximum
    """
    key = bytes(domain, 'ascii')
    domain_hash = self._getHash(key)

    if domain_hash in self._kvs:
      raise ValueError('Domain already in database')
    if desired_len > self.MAX_PASSWORD_LEN:
      raise ValueError('Maximum password length exceeded')

    new_password = ''
    for i in range(desired_len):
      nextIndex = int.from_bytes(self._random(), 'little') % 62
      if nextIndex < 10:
        nextLetter = str(nextIndex)
      elif nextIndex < 36:
        nextLetter = chr(ord('A') + (nextIndex - 10))
      else:
        nextLetter = chr(ord('a') + (nextIndex - 36))
      new_password += nextLetter

    self.set(domain, new_password)

    return new_password

  def get(self, domain):
    """Fetches the password associated with a domain from the password
       manager.
    
    Args:
      domain (str) : the domain to fetch
    
    Returns: 
      password (str) : the password associated with the requested domain if
                       it exists and otherwise None
    """
    
    key = bytes(domain, 'ascii')
    domain_hash = self._getHash(key)
    
    if domain_hash in self._kvs:
      pass_encrypt = self._kvs[domain_hash]

      aesgcm = aead.AESGCM(self._getKey(domain_hash))
      value = aesgcm.decrypt(self._getKey(key), pass_encrypt, None)
      value = (value.decode('ascii','little')).lstrip('\0')
      return value
    return None
  
  def remove(self, domain):
    """Removes the password for the requested domain from the password
       manager.
       
       Args:
         domain (str) : the domain to remove

       Returns:
         success (bool) : True if the domain was removed and False if the domain was
                          not found
    """
    key = bytes(domain, 'ascii')
    domain_hash = self._getHash(key)

    if domain_hash in self._kvs:
      del self._kvs[domain_hash]
      return True

    return False

  def set(self, domain, password):
    """Associates a password with a domain and adds it to the password
       manager (or updates the associated password if the domain is already
       present in the password manager).
       
       Args:
         domain (str) : the domain to set
         password (str) : the password associated with the domain

       Returns:
         None

       Raises:
         ValueError : if password length exceeds the maximum
    """
    if len(password) > self.MAX_PASSWORD_LEN:
      raise ValueError('Maximum password length exceeded')

    key = bytes(domain, 'ascii')
    domain_hash = self._getHash(key)

    aesgcm = aead.AESGCM(self._getKey(domain_hash))
    value = bytes(password.rjust(self.MAX_PASSWORD_LEN, '\0'), 'ascii')
    self._kvs[domain_hash] = aesgcm.encrypt(self._getKey(key), value, None)
