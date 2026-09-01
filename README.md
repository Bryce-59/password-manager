# Password Manager

A small, security-focused password manager written in Python. It uses modern cryptographic primitives to protect stored passwords, bind entries to their domains, and securely serialize the manager's state.

This is an **improved and hardened version of an earlier 2023 implementation**, with a focus on stronger authenticated encryption, safer serialization, explicit nonce management, key separation, and more defensive input validation.

## How To Use

Install the only external dependency:

```bash
pip install cryptography
```

The main implementation is contained in `password_manager.py`.

### Basic Usage

```python
from password_manager import PasswordManager

manager = PasswordManager("master-password")

# Store and retrieve a password
manager.set("example.com", "my-password")
manager.get("example.com")

# Generate and store a password
generated = manager.generate_new("another-example.com", 20)

# Remove a password
manager.remove("example.com")

# Save the encrypted state
data, checksum = manager.dump()
```

A saved manager can be restored with:

```python
manager = PasswordManager(
    "master-password",
    data=data,
    checksum=checksum,
)
```

A test suite is included in `password_manager_tests.py`.

---

# Current Implementation

The current version is built around a few simple ideas: derive cryptographic material from the master password, give each domain its own encryption key, authenticate encrypted data, and store only encrypted password entries.

## Master Key Derivation

The user's master password is converted into a 256-bit master key using **PBKDF2-HMAC-SHA256** with a randomly generated 16-byte salt and 2,000,000 iterations.

```text
Master Password
       │
       ▼
PBKDF2-HMAC-SHA256
       │
       ▼
   Master Key
```

The salt is stored alongside the encrypted manager state, so it does not need to remain secret.

## Key Separation

The master key output by PBKDF2 is used in two ways. It is used directly (together with the salt) to encrypt the top-level serialized state with AES-GCM, and it is separately fed through **HKDF** to produce an independent pseudorandom key (PRK) from which all *entry-specific* keys and the random-generator key are derived via `HKDFExpand`.

```text
                    Master Key (PBKDF2 output)
                           │
              ┌────────────┼────────────────┐
              ▼            ▼                 
     State encryption    HKDF-Extract         
     (AES-GCM, direct)      │                 
                             ▼                 
                            PRK
                       ┌─────┴─────┐
                       ▼           ▼
                Entry-specific   RNG Key
                     keys
```

This means per-domain entries and the password generator never share key material with each other or with the top-level state encryption — reducing the blast radius if any single derived key were ever compromised. The top-level state encryption key is not run through this separation, since it is only ever used once per `dump()` call and doesn't need role-specific derivation the way per-entry keys do.

## Domain-Bound Entries

Domains are first converted to a keyed hash and used as the identifier for entries in the internal database.

Each password is then encrypted using a key derived specifically for that domain.

The domain hash is also supplied to **AES-GCM as associated authenticated data (AAD)**. This means the encrypted password is cryptographically bound to its domain.

Conceptually:

```text
Domain
  │
  ├──► Domain Hash ───► Entry Identifier
  │
  └──► Key Derivation ─► Entry Encryption Key
                              │
Password ────────────────────┘
                              │
                              ▼
                           AES-GCM
```

As a result, an encrypted password entry cannot simply be moved to another domain and successfully decrypted — this is the manager's defense against **swap attacks**, where an adversary interchanges the stored entries for two different domains. Because the binding happens at the AEAD layer itself, this protection holds independently of the rollback protection described below.

## Authenticated Encryption

The current implementation uses **AES-GCM** for both the manager state and individual password entries.

AES-GCM provides:

* Confidentiality
* Integrity
* Authentication

When encrypted data is modified, authentication fails and the entry is rejected instead of silently returning corrupted data.

## Rollback Protection

`dump()` returns both the serialized, encrypted state and a SHA-256 checksum computed over that serialized blob. When the manager is later reconstructed, supplying this checksum causes the loader to verify it against the incoming data before attempting to decrypt anything.

This guards against **rollback attacks**, where an adversary who once had access to an older serialized state replaces a newer one with it. Authenticated encryption alone does not prevent this — an old ciphertext is still a validly authenticated ciphertext — so the checksum is expected to be persisted somewhere the adversary cannot also tamper with (e.g. separate trusted storage), and checked on every load.

## Password Storage

Passwords are encoded into a fixed-size 65-byte representation:

```text
1 byte length || password || zero padding
```

With a maximum password length of 64 characters, every stored password therefore has the same plaintext size before encryption, regardless of its actual length. This prevents ciphertext size from leaking password length.

On decoding, the implementation verifies the stored length, checks the padding, and ensures that the resulting value is valid ASCII.

## Nonce Management

AES-GCM requires careful nonce management. The current implementation uses an explicit monotonically increasing counter to generate 12-byte nonces.

Each encryption receives a new nonce, and the counter is stored as part of the serialized state so that nonce allocation can continue after the manager is loaded again.

The implementation also detects counter exhaustion rather than allowing the counter to wrap around.

## Password Generation

Generated passwords use the following alphabet:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
```

Random values are produced by an HMAC-SHA256-based counter construction with a separately derived key.

The generator state is serialized alongside the password database, allowing the generator to resume consistently after loading.

## Serialization

The manager state is serialized as JSON rather than as a Python object.

A saved manager has the general structure:

```text
salt || nonce || encrypted state
```

The encrypted state contains:

* The nonce counter
* The random-generator counter
* The password entries

Entries are encoded using Base64 so they can be represented safely inside JSON.

Before accepting a serialized manager, the implementation validates the structure and the expected types and lengths of its fields.

## Input Validation

Master passwords and domain names are required to be ASCII and are explicitly validated, raising a clear `ValueError` if they are not. Stored passwords are assumed to be ASCII per the project's design assumptions and are not independently re-validated for encoding beyond what round-trips through encode/decode.

Beyond encoding, malformed input can be rejected for reasons such as:

* Invalid hexadecimal or Base64 data
* Unexpected JSON structure
* Invalid counter values
* Incorrect ciphertext lengths
* Invalid password encodings or padding
* Authentication failures

The goal is not just to make invalid input fail, but to make it fail in a controlled and predictable way.

---

# What Improved?

The original version already explored several interesting security concepts, but the current implementation replaces a number of weaker or less explicit mechanisms with safer constructions.

## AES-CTR → AES-GCM

The original manager encrypted its serialized state using AES-CTR.

CTR provides encryption, but **does not provide authentication**. An attacker who modifies the ciphertext can therefore alter the resulting plaintext without the encryption mode itself detecting the modification.

The current version uses AES-GCM instead, giving the encrypted manager state both confidentiality and integrity.

**Why it matters:** encrypted data should generally be authenticated as well as encrypted.

## `pickle` → Structured JSON

The original serialized the password database with Python's `pickle` module.

The current version uses JSON with an explicitly defined schema.

This means the stored format is now:

* Easier to inspect and reason about
* Independent of Python object serialization
* Explicitly validated during loading
* Less reliant on dynamic object deserialization

The loader checks the structure before accepting the state rather than simply attempting to deserialize an arbitrary Python object.

## Deterministic Nonces → Explicit Nonce Management

The original implementation derived encryption nonces deterministically from domain- and key-related values, which meant an updated entry could end up reusing a nonce under the same key — a critical failure mode for AES-GCM.

The current implementation introduces an explicit, persisted nonce counter and allocates a fresh 12-byte nonce for every encryption, guaranteeing no nonce is ever reused under a given key under normal operation.

**Why it matters:** nonce reuse under AES-GCM doesn't just leak information — it can allow forging future ciphertexts under the same key.

## Direct Key Construction → Key Separation with HKDF

The original implementation relied primarily on HMAC constructions built directly on the master key and salt for every purpose.

The current version adds an HKDF-based derivation step on top of the same PBKDF2 master key, giving entry-specific keys and the random generator's key independent derived key material rather than reusing the same construction for unrelated purposes.

**Why it matters:** separating cryptographic roles reduces accidental key reuse and makes the design easier to audit.

## Hash-Chain Randomness → Counter-Based HMAC Generator

The original password generator repeatedly hashed a mutable seed, and that same seed value doubled as the nonce source for state encryption — meaning generator state was partially exposed by every dump.

The current implementation uses an HMAC-SHA256 construction driven by an explicit counter and a separately derived key, decoupling the generator's internal state from anything that gets exposed in the output.

## Implicit Password Length → Explicit Encoding

Previously, passwords were padded and later recovered by stripping padding bytes — which also meant a password beginning with a null byte could not round-trip correctly.

The current representation explicitly stores the password length before the password data, so the decoder validates the complete representation rather than assuming stripped padding recovers the original password.

## Minimal Validation → Defensive Validation

The current implementation performs considerably more validation when loading and decrypting data, covering cases such as invalid encodings, malformed structure, out-of-range counters, and authentication failures — see [Input Validation](#input-validation) above.

The goal is not just to make invalid input fail, but to make it fail in a controlled and predictable way.

## Overall Result

The project started as a demonstration of a semantically secure password manager, aiming to satisfy an indistinguishability-style security game against an adaptive adversary. The current version keeps that original goal while making the implementation more explicit, defensive, and cryptographically robust — and adds explicit, independent defenses against rollback and swap attacks specifically.

The biggest changes can be summarized as:

| Area              | Original            | Current                        |
| ----------------- | -------------------- | ------------------------------- |
| State encryption  | AES-CTR              | AES-GCM                         |
| Serialization     | `pickle`              | Validated JSON                  |
| Authentication    | Limited                | Authenticated encryption        |
| Nonces            | Deterministic          | Explicit counter-based          |
| Key derivation    | PBKDF2 + direct HMAC   | PBKDF2 + HKDF-separated keys    |
| Random generation | Hash chain             | HMAC + counter                  |
| Password encoding | Padding-based          | Length-prefixed                 |
| Input validation  | Limited                | Extensive                       |
| Key separation    | Less explicit          | Separate derived keys           |

---

# Project Scope

This is a **educational project**, not a production password manager.

It intentionally focuses on the cryptographic design rather than providing a complete end-user password-management application.

# Credits
- 2023 Bryce Richardson, 2026 Bryce Richardson