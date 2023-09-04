# About the Project
A demo of a semantically secure password manager in Python from 2023.

This password manager is protected against both swap attacks and rollback attacks. 
 - It is protected against swap attacks by encrypting each password with a key derived from the domain name, such that if the domain is altered by an adversary, it is no longer possible to decrypt the corresponding password. 
 - It is protected against rollback attacks by creating a checksum (a hash of the password manager's serialized contents) when the password manager is saved. The checksum is then compared against the serialized contents before reconstruction in order to verify that the contents were not altered.

# How to Use
To install dependencies, use `pip install cryptography`. After that, the library is free to use. 

A simple test suite can be found in `password_manager_tests.py`.

# Credits
- 2023 Bryce Richardson