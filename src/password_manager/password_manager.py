from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand, HKDF
import os
import json
import base64
import hmac as hmac_mod


class PasswordManager:
    MAX_PASSWORD_LEN = 64

    def __init__(self, password, data=None, checksum=None):
      self._kvs = {}
      self._nonce_counter = 0
      self._rng_counter = 0

      if data is not None:
        try:
            data_bytes = bytes.fromhex(data)
        except (ValueError, TypeError):
            raise ValueError("malformed data")

        MIN_LEN = 16 + 12 + 16
        if len(data_bytes) < MIN_LEN:
            raise ValueError("malformed data")

        if checksum is not None:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data_bytes)
            if not hmac_mod.compare_digest(checksum, digest.finalize().hex()):
                raise ValueError("checksums do not match")

        self._salt = data_bytes[:16]
        nonce = data_bytes[16:28]

      else:
          self._salt = os.urandom(16)


      # Derive the master key.
      kdf = pbkdf2.PBKDF2HMAC(
          algorithm=hashes.SHA256(),
          length=32,
          salt=self._salt,
          iterations=2000000
      )

      try:
            pbkdf2_key = kdf.derive(password.encode("ascii"))
      except UnicodeEncodeError:
            raise ValueError("password must contain ASCII characters")

      self._prk = self._hmac(self._salt, pbkdf2_key)

      self._master = pbkdf2_key
      self._rng_key = self._get_rng()

      if data is not None:
          aesgcm = aead.AESGCM(self._master)

          try:
              decrypted = aesgcm.decrypt(
                  nonce,
                  data_bytes[28:],
                  None
              )
          except InvalidTag as exc:
            raise ValueError("bad password or malformed data") from exc

          if decrypted[:16] != self._get_key(self._salt)[:16]:
              raise ValueError("bad password")

          # Everything after the 16-byte magic value is JSON.
          self._deserialize_state(decrypted[16:])

    def _hmac(self, key, data):
      h = hmac.HMAC(key, hashes.SHA256())
      h.update(data)
      return h.finalize()

    def _hash_domain(self, domain):
      try:
          domain_bytes = bytes(domain, 'ascii')
      except UnicodeEncodeError as exc:
          raise ValueError("domain must contain ASCII characters") from exc

      return self._hmac(self._get_key(domain_bytes), domain_bytes)

    def _get_key(self, tag):
        return HKDFExpand(
            algorithm=hashes.SHA256(),
            length=16,
            info=b"password-manager-key:" + tag,
        ).derive(self._prk)

    def _get_rng(self):
        return HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=b"password-manager-rng",
        ).derive(self._prk)

    def _random(self):
          if self._rng_counter >= 2**64:
              raise ValueError("random generator exhausted")
    
          counter_bytes = self._rng_counter.to_bytes(8, "big")
          self._rng_counter += 1
    
          return self._hmac(self._rng_key, counter_bytes)

    def _next_nonce(self):
        """
        Returns a unique 12-byte nonce and advances the nonce counter.
        """
        if self._nonce_counter >= 2**96:
            raise ValueError("nonce counter exhausted")

        nonce = self._nonce_counter.to_bytes(12, 'big')
        self._nonce_counter += 1

        return nonce

    def _serialize_state(self):
      """
      Serialize the password manager state into JSON.
      """
      state = {
          "nonce_counter": self._nonce_counter,
          "rng_counter": self._rng_counter,
          "entries": {
              base64.b64encode(domain_hash).decode("ascii"):
                  base64.b64encode(encrypted).decode("ascii")
              for domain_hash, encrypted in self._kvs.items()
          }
      }

      return json.dumps(
          state,
          separators=(",", ":"),
          sort_keys=True
      ).encode("utf-8")


    def _deserialize_state(self, data):
        """
        Deserialize and validate the password manager state.
        """
        try:
            state = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("malformed data")

        if not isinstance(state, dict):
            raise ValueError("malformed data")

        if set(state.keys()) != {
            "nonce_counter",
            "rng_counter",
            "entries"
        }:
            raise ValueError("malformed data")

        nonce_counter = state["nonce_counter"]
        entries = state["entries"]

        if isinstance(nonce_counter, bool) or not isinstance(nonce_counter, int):
            raise ValueError("malformed data")

        if not 0 <= nonce_counter < 2**96:
            raise ValueError("malformed data")

        rng_counter = state["rng_counter"]

        if isinstance(rng_counter, bool) or not isinstance(rng_counter, int):
            raise ValueError("malformed data")

        if not 0 <= rng_counter < 2**64:
            raise ValueError("malformed data")

        if not isinstance(entries, dict):
            raise ValueError("malformed data")

        kvs = {}

        for domain_hash_b64, encrypted_b64 in entries.items():
            if not isinstance(domain_hash_b64, str):
                raise ValueError("malformed data")

            if not isinstance(encrypted_b64, str):
                raise ValueError("malformed data")

            try:
                domain_hash = base64.b64decode(
                    domain_hash_b64,
                    validate=True
                )

                encrypted = base64.b64decode(
                    encrypted_b64,
                    validate=True
                )
            except (ValueError, TypeError):
                raise ValueError("malformed data")

            if len(domain_hash) != 32:
                raise ValueError("malformed data")

            # 12-byte nonce + 16-byte GCM authentication tag
            if len(encrypted) < 28:
                raise ValueError("malformed data")

            kvs[domain_hash] = encrypted

        self._nonce_counter = nonce_counter
        self._rng_counter = rng_counter
        self._kvs = kvs

    def _encode_password(self, password):
        """
        Encode every password as exactly 65 bytes:
            1 byte length || password || zero padding
        """
        value = password.encode("ascii")

        if len(value) > self.MAX_PASSWORD_LEN:
            raise ValueError("maximum password length exceeded")

        return bytes([len(value)]) + value + b"\x00" * (
            self.MAX_PASSWORD_LEN - len(value)
        )

    def _decode_password(self, value):
        """
        Decode the fixed-length password representation.
        """
        if len(value) != self.MAX_PASSWORD_LEN + 1:
            raise ValueError("invalid password data")

        length = value[0]

        if length > self.MAX_PASSWORD_LEN:
            raise ValueError("invalid password data")

        # Make sure the padding is actually zero.
        if value[1 + length:] != b"\x00" * (self.MAX_PASSWORD_LEN - length):
            raise ValueError("invalid password data")

        try:
            return value[1:1 + length].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid password data") from exc


    def dump(self):
        """
        Computes a serialized representation of the password manager
        together with a checksum.
        """

        # Allocate the nonce before serializing so that the serialized
        # counter represents the next unused nonce.
        nonce = self._next_nonce()

        # Serialize the state as JSON.
        dump = self._serialize_state()

        # Magic value used for password verification.
        dump_bytes = self._get_key(self._salt)[:16]
        dump_bytes += dump

        # Encrypt and authenticate the serialized state.
        aesgcm = aead.AESGCM(self._master)
        encrypted = aesgcm.encrypt(
            nonce,
            dump_bytes,
            None
        )

        serial = self._salt + nonce + encrypted

        digest = hashes.Hash(hashes.SHA256())
        digest.update(serial)

        return serial.hex(), digest.finalize().hex()

    def generate_new(self, domain, desired_len):
        """
        Generates a password for a particular domain.
        """

        domain_hash = self._hash_domain(domain)

        if domain_hash in self._kvs:
            raise ValueError('Domain already in database')

        if not 0 <= desired_len <= self.MAX_PASSWORD_LEN:
            raise ValueError("invalid password length")

        chars = []

        for i in range(desired_len):
            next_index = int.from_bytes(
                self._random(),
                'little'
            ) % 62

            if next_index < 10:
                next_letter = str(next_index)
            elif next_index < 36:
                next_letter = chr(ord('A') + (next_index - 10))
            else:
                next_letter = chr(ord('a') + (next_index - 36))

            chars.append(next_letter)

        new_password = "".join(chars)

        self.set(domain, new_password)

        return new_password

    def get(self, domain):
        """
        Fetches the password associated with a domain.
        """

        domain_hash = self._hash_domain(domain)

        if domain_hash in self._kvs:
            pass_encrypt = self._kvs[domain_hash]

            # Each stored password is:
            #     nonce || ciphertext
            nonce = pass_encrypt[:12]
            ciphertext = pass_encrypt[12:]

            aesgcm = aead.AESGCM(
                self._get_key(domain_hash)
            )

            try:
                value = aesgcm.decrypt(
                    nonce,
                    ciphertext,
                    domain_hash
                )
            except InvalidTag as exc:
                raise ValueError("invalid password data") from exc


            return self._decode_password(value)

        return None

    def remove(self, domain):
        """
        Removes the password for the requested domain.
        """

        domain_hash = self._hash_domain(domain)

        if domain_hash in self._kvs:
            del self._kvs[domain_hash]
            return True

        return False

    def set(self, domain, password):
        """
        Associates a password with a domain.
        """

        domain_hash = self._hash_domain(domain)

        aesgcm = aead.AESGCM(
            self._get_key(domain_hash)
        )

        value = self._encode_password(password)

        # Generate a fresh, unique nonce.
        nonce = self._next_nonce()

        encrypted = aesgcm.encrypt(
            nonce,
            value,
            domain_hash
        )

        # Store:
        #     nonce || ciphertext
        self._kvs[domain_hash] = nonce + encrypted