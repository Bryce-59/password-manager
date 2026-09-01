import os
import json
import base64
import hmac as hmac_mod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


class PasswordManager:
    ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    MAX_PASSWORD_LEN = 64
    PBKDF2_ITERATIONS = 2_000_000

    ENTRY_KEY_LEN = 16
    MASTER_KEY_LEN = 32
    GCM_TAG_LEN = 16
    NONCE_LEN = 12
    RNG_COUNTER_LEN = 8
    SALT_LEN = 16

    # ------------------------------------------------------------------
    # Initialization / Loading
    # ------------------------------------------------------------------

    def __init__(self, password, data=None, checksum=None):
        """
        Initialize the password manager.

        If ``data`` is provided, restore the password manager from the
        serialized encrypted state. Otherwise, initialize a new empty
        password manager with a randomly generated salt.

        Args:
            password: ASCII password used to derive the master encryption key.
            data: Optional hexadecimal string containing a serialized,
                encrypted password manager state.
            checksum: Optional SHA-256 checksum of the serialized data,
                represented as a hexadecimal string.

        Raises:
            ValueError: If the password is not ASCII, the serialized data is
                malformed, the checksum does not match, or the password does
                not match the encrypted state.
        """

        self._kvs = {}
        self._nonce_counter = 0
        self._rng_counter = 0

        if data is not None:
            try:
                data_bytes = bytes.fromhex(data)
            except (ValueError, TypeError):
                raise ValueError("malformed data")

            min_len = self.SALT_LEN + self.NONCE_LEN + self.GCM_TAG_LEN
            if len(data_bytes) < min_len:
                raise ValueError("malformed data")

            if checksum is not None:
                digest = hashes.Hash(hashes.SHA256())
                digest.update(data_bytes)
                if not hmac_mod.compare_digest(checksum, digest.finalize().hex()):
                    raise ValueError("checksums do not match")

            self._salt = data_bytes[: self.SALT_LEN]
            nonce = data_bytes[self.SALT_LEN : self.SALT_LEN + self.NONCE_LEN]

        else:
            self._salt = os.urandom(self.SALT_LEN)

        # Derive the master key.
        kdf = pbkdf2.PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.MASTER_KEY_LEN,
            salt=self._salt,
            iterations=self.PBKDF2_ITERATIONS,
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
                    nonce, data_bytes[self.SALT_LEN + self.NONCE_LEN :], None
                )
            except InvalidTag as exc:
                raise ValueError("bad password or malformed data") from exc

            if decrypted[: self.SALT_LEN] != self._get_key(self._salt)[: self.SALT_LEN]:
                raise ValueError("bad password")

            self._deserialize_state(decrypted[self.SALT_LEN :])

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

        if set(state.keys()) != {"nonce_counter", "rng_counter", "entries"}:
            raise ValueError("malformed data")

        nonce_counter = state["nonce_counter"]
        entries = state["entries"]

        if isinstance(nonce_counter, bool) or not isinstance(nonce_counter, int):
            raise ValueError("malformed data")

        if not 0 <= nonce_counter < 2 ** (self.NONCE_LEN * 8):
            raise ValueError("malformed data")

        rng_counter = state["rng_counter"]

        if isinstance(rng_counter, bool) or not isinstance(rng_counter, int):
            raise ValueError("malformed data")

        if not 0 <= rng_counter < 2 ** (self.RNG_COUNTER_LEN * 8):
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
                domain_hash = base64.b64decode(domain_hash_b64, validate=True)

                encrypted = base64.b64decode(encrypted_b64, validate=True)
            except (ValueError, TypeError):
                raise ValueError("malformed data")

            if len(domain_hash) != 32:
                raise ValueError("malformed data")

            min_encrypted_len = self.NONCE_LEN + self.GCM_TAG_LEN
            if len(encrypted) < min_encrypted_len:
                raise ValueError("malformed data")

            kvs[domain_hash] = encrypted

        self._nonce_counter = nonce_counter
        self._rng_counter = rng_counter
        self._kvs = kvs

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def dump(self):
        """
        Serialize and encrypt the current password manager state.

        The serialized state is encrypted using AES-GCM and includes the
        manager's salt and a unique nonce. A SHA-256 checksum of the complete
        serialized representation is also calculated.

        Returns:
            A tuple containing:
                - A hexadecimal string containing the serialized,
                  encrypted password manager state.
                - A hexadecimal SHA-256 checksum of the serialized state.

        Raises:
            ValueError: If the nonce counter has been exhausted.
        """

        # Allocate the nonce before serializing so that the serialized
        # counter represents the next unused nonce.
        nonce = self._next_nonce()

        # Serialize the state as JSON.
        dump = self._serialize_state()

        # Magic value used for password verification.
        dump_bytes = self._get_key(self._salt)[: self.SALT_LEN]
        dump_bytes += dump

        # Encrypt and authenticate the serialized state.
        aesgcm = aead.AESGCM(self._master)
        encrypted = aesgcm.encrypt(nonce, dump_bytes, None)

        serial = self._salt + nonce + encrypted

        digest = hashes.Hash(hashes.SHA256())
        digest.update(serial)

        return serial.hex(), digest.finalize().hex()

    def _serialize_state(self):
        """
        Serialize the password manager state into JSON.
        """
        state = {
            "nonce_counter": self._nonce_counter,
            "rng_counter": self._rng_counter,
            "entries": {
                base64.b64encode(domain_hash).decode("ascii"): base64.b64encode(
                    encrypted
                ).decode("ascii")
                for domain_hash, encrypted in self._kvs.items()
            },
        }

        return json.dumps(state, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _next_nonce(self):
        """
        Returns a unique 12-byte nonce and advances the nonce counter.
        """
        if self._nonce_counter >= 2 ** (self.NONCE_LEN * 8):
            raise ValueError("nonce counter exhausted")

        nonce = self._nonce_counter.to_bytes(self.NONCE_LEN, "big")
        self._nonce_counter += 1

        return nonce

    # ------------------------------------------------------------------
    # Password Management
    # ------------------------------------------------------------------

    def get(self, domain):
        """
        Fetch the password associated with a domain.

        Args:
            domain: ASCII domain name whose password should be retrieved.

        Returns:
            The decrypted password associated with ``domain``, or ``None``
            if the domain is not stored.

        Raises:
            ValueError: If the domain contains non-ASCII characters or the
                stored password data is invalid or cannot be authenticated.
        """

        domain_hash = self._hash_domain(domain)

        if domain_hash in self._kvs:
            pass_encrypt = self._kvs[domain_hash]

            # Each stored password is:
            #     nonce || ciphertext
            nonce = pass_encrypt[: self.NONCE_LEN]
            ciphertext = pass_encrypt[self.NONCE_LEN :]

            aesgcm = aead.AESGCM(self._get_key(domain_hash))

            try:
                value = aesgcm.decrypt(nonce, ciphertext, domain_hash)
            except InvalidTag as exc:
                raise ValueError("invalid password data") from exc

            return self._decode_password(value)

        return None

    def set(self, domain, password):
        """
        Associate a password with a domain.

        The password is encoded using a fixed-length representation and
        encrypted with AES-GCM before being stored.

        Args:
            domain: ASCII domain name associated with the password.
            password: ASCII password to store.

        Raises:
            ValueError: If the domain or password contains non-ASCII
                characters, the password exceeds the maximum allowed length,
                or the nonce counter has been exhausted.
        """

        domain_hash = self._hash_domain(domain)

        aesgcm = aead.AESGCM(self._get_key(domain_hash))

        value = self._encode_password(password)

        # Generate a fresh, unique nonce.
        nonce = self._next_nonce()

        encrypted = aesgcm.encrypt(nonce, value, domain_hash)

        # Store:
        #     nonce || ciphertext
        self._kvs[domain_hash] = nonce + encrypted

    def remove(self, domain):
        """
        Remove the password associated with a domain.

        Args:
            domain: ASCII domain name whose password should be removed.

        Returns:
            ``True`` if an entry was removed, or ``False`` if the domain was
            not present in the password manager.

        Raises:
            ValueError: If the domain contains non-ASCII characters.
        """

        domain_hash = self._hash_domain(domain)

        if domain_hash in self._kvs:
            del self._kvs[domain_hash]
            return True

        return False

    # ------------------------------------------------------------------
    # Password Generation
    # ------------------------------------------------------------------

    def generate_new(self, domain, desired_len):
        """
        Generate and store a new random password for a domain.

        The generated password contains only ASCII letters and decimal
        digits. The password is automatically stored in the password
        manager before being returned.

        Args:
            domain: ASCII domain name for which the password should be
                generated.
            desired_len: Length of the generated password. Must be between
                zero and ``MAX_PASSWORD_LEN``, inclusive.

        Returns:
            The newly generated password.

        Raises:
            ValueError: If the domain contains non-ASCII characters, the
                domain already has a stored password, the requested length
                is invalid, or the random generator or nonce counter has
                been exhausted.
        """

        domain_hash = self._hash_domain(domain)

        if domain_hash in self._kvs:
            raise ValueError("Domain already in database")

        if not 0 <= desired_len <= self.MAX_PASSWORD_LEN:
            raise ValueError("invalid password length")

        chars = []

        for _ in range(desired_len):
            next_index = int.from_bytes(self._random(), "little") % len(self.ALPHABET)
            chars.append(self.ALPHABET[next_index])

        new_password = "".join(chars)

        self.set(domain, new_password)

        return new_password

    def _random(self):
        """Return the next 32-byte value from the deterministic random generator."""
        if self._rng_counter >= 2 ** (self.RNG_COUNTER_LEN * 8):
            raise ValueError("random generator exhausted")

        counter_bytes = self._rng_counter.to_bytes(self.RNG_COUNTER_LEN, "big")
        self._rng_counter += 1

        return self._hmac(self._rng_key, counter_bytes)

    def _get_rng(self):
        """Derive the key used by the deterministic random generator."""
        return HKDFExpand(
            algorithm=hashes.SHA256(),
            length=self.MASTER_KEY_LEN,
            info=b"password-manager-rng",
        ).derive(self._prk)

    # ------------------------------------------------------------------
    # Encoding / Decoding
    # ------------------------------------------------------------------

    def _encode_password(self, password):
        """
        Encode every password as exactly 65 bytes:
            1 byte length || password || zero padding
        """
        value = password.encode("ascii")

        if len(value) > self.MAX_PASSWORD_LEN:
            raise ValueError("maximum password length exceeded")

        return (
            bytes([len(value)]) + value + b"\x00" * (self.MAX_PASSWORD_LEN - len(value))
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
        if value[1 + length :] != b"\x00" * (self.MAX_PASSWORD_LEN - length):
            raise ValueError("invalid password data")

        try:
            return value[1 : 1 + length].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid password data") from exc

    # ------------------------------------------------------------------
    # Misc Helpers
    # ------------------------------------------------------------------

    def _hash_domain(self, domain):
        """Return a keyed hash of the ASCII domain name."""
        try:
            domain_bytes = bytes(domain, "ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("domain must contain ASCII characters") from exc

        return self._hmac(self._get_key(domain_bytes), domain_bytes)

    def _get_key(self, tag):
        """Derive a 16-byte key from the given tag."""
        return HKDFExpand(
            algorithm=hashes.SHA256(),
            length=self.ENTRY_KEY_LEN,
            info=b"password-manager-key:" + tag,
        ).derive(self._prk)

    def _hmac(self, key, data):
        """Return the HMAC-SHA256 digest of the data using the given key."""
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        return h.finalize()
