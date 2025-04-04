'''
Functions for AES256-GCM encryption/decryption (pycriptodome and gpg) and Argon2 hashing.
This module provides functions to generate an AES key, encrypt and decrypt messages,
and hash and verify passwords using Argon2.
It uses the PyCryptodome library for AES encryption and Argon2 for password hashing.
It is important to note that the AES key should be kept secret and secure.
The Argon2 hash should also be stored securely, as it is used to verify passwords.
This module is intended for educational purposes and should not be used in 
production without proper security measures.

Author: RAFAEL PERAZZO B MOTA
Date: 2025-03-30
Version: 1.1


Example usage:
# Generate or load the AES key
aes_key = generate_key()
print(f"AES Key: {aes_key.hex()}")

# Encrypt a message
MESSAGE = "Hello, World!"
encrypted_text = aes_gcm_encrypt(aes_key, MESSAGE)
print(f"Ciphertext: {encrypted_text}")

# Decrypt the message
decrypted_text = aes_gcm_decrypt(aes_key, encrypted_text)
print(f"Plaintext: {decrypted_text}")

# Hash a password with Argon2
PASSWORD = "mysecretpassword123456789012345"
HASH_ARGON = hash_argon2id(aes_key, PASSWORD)
print(f"Argon2 Hash: {HASH_ARGON}")
# Verify the password
is_valid = verify_hash(HASH_ARGON, aes_key, PASSWORD)
print(f"Password is valid: {is_valid}")
# Verify a different password
is_valid = verify_hash(HASH_ARGON, aes_key, "wrongpassword")
print(f"Password is valid: {is_valid}")

enc = gpg_encrypt("12345", "Hello, World!")
print(enc)
dec = gpg_decrypt("12345", enc)
print(dec)

hmac_txt = hmac(aes_key, MESSAGE)
print(hmac_txt)
# Verify the HMAC
is_valid = verify_hmac(aes_key, MESSAGE, hmac_txt)
print(f"HMAC is valid: {is_valid}")

'''
# -*- coding: utf-8 -*-
from pathlib import Path
import base64
import argon2
from argon2 import PasswordHasher
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA3_256
from Crypto.Random import get_random_bytes
import gnupg

__version__ = '0.0.1'

def hexstring_to_bytes(hex_string):
    '''
    Converts a hexadecimal string to bytes.
    :param hex_string: hexadecimal string to be converted
    :return: bytes
    '''
    # Remove any leading '0x' and convert to bytes
    hex_string = hex_string.lstrip('0x')
    return bytes.fromhex(hex_string)

def bytes_to_hexstring(byte_string):
    '''
    Converts bytes to a hexadecimal string.
    :param byte_string: bytes to be converted
    :return: hexadecimal string
    '''
    # Convert bytes to hexadecimal string
    hex_string = byte_string.hex()
    # Add '0x' prefix
    hex_string = '0x' + hex_string
    return hex_string

def generate_key():
    '''
    Generates a new AES key and saves it to a file.
    :return: AES key
    '''
    keyfile = Path("key.key")
    # Check if the key file exists
    if not keyfile.is_file():
        # Generate a new AES key
        aes_key = get_random_bytes(32)
        # Save the key to a file
        with open("key.key", "wb") as key_file:
            key_file.write(aes_key)
    else:
        print("Key file already exists. Loading the existing key.")
        with open("key.key", "rb") as key_file:
            aes_key = key_file.read()
    return aes_key

def gpg_encrypt(key, plaintext):
    '''
    Encrypts the plaintext using GPG Symmetric encryption.
    :param key: GPG passphrase - string
    :param plaintext: plaintext to be encrypted - string
    :return: ciphertext - string
    '''
    gpg = gnupg.GPG()
    # Encrypt the plaintext
    encrypted_data = gpg.encrypt(plaintext,passphrase=key,symmetric='AES256',recipients=None)
    return str(encrypted_data)

def gpg_decrypt(key, ciphertext):
    '''
    Decrypts the ciphertext using GPG Symmetric decryption.
    :param key: GPG passphrase - string
    :param ciphertext: ciphertext to be decrypted - string
    :return: decrypted plaintext - string
    '''
    gpg = gnupg.GPG()
    # Decrypt the ciphertext
    decrypted_data = gpg.decrypt(ciphertext,passphrase=key)
    return str(decrypted_data)

def aes_gcm_encrypt(key, plaintext):
    '''
    Encrypts the plaintext using AES GCM encryption with a random nonce.
    :param key: AES key (must be 16, 24, or 32 bytes long) -  bytes or hexadecimal string
    :param plaintext: plaintext to be encrypted - string or bytes
    :return: ciphertext (nonce + ciphertext + tag) - base64 string
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    if isinstance(plaintext, str):
        # Convert string plaintext to bytes
        plaintext = plaintext.encode()
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode((nonce + ciphertext + tag)).decode('utf-8')

def aes_gcm_decrypt(key, ciphertext):
    '''
    Decrypts the ciphertext using AES GCM decryption.
    :param key: AES key (must be 16, 24, or 32 bytes long) - bytes or hexadecimal string
    :param ciphertext: ciphertext to be decrypted (nonce + ciphertext + tag) - bytes or base64 string
    :return: decrypted plaintext - string
    '''
    if isinstance(key, str):
        # Convert base64 string key to bytes
        key = hexstring_to_bytes(key)
    if isinstance(ciphertext, str):
        # Convert base64 string ciphertext to bytes
        ciphertext = base64.b64decode(ciphertext)
    nonce = ciphertext[:16]
    tag = ciphertext[-16:]
    ciphertext = ciphertext[16:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

def hmac(key, message):
    '''
    Applies HMAC to the message using SHA3-256.
    :param key: key for the HMAC - bytes or hexadecimal string
    :param message: message to be hashed - string
    :return: HMAC signature - string
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    # Create the HMAC
    h = HMAC.new(key, digestmod=SHA3_256)
    h.update(message.encode())
    # Convert to hexadecimal
    signature = h.hexdigest()
    return signature

def verify_hmac(key, message, signature):
    '''
    Verifies if the HMAC signature matches the message.
    :param key: key for the HMAC - bytes or hexadecimal string
    :param message: message to be verified - string
    :param signature: HMAC signature to be verified - string
    :return: True if the signature is valid, False otherwise
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    # Create the HMAC
    h = HMAC.new(key, digestmod=SHA3_256)
    h.update(message.encode())
    # Convert to hexadecimal
    signature_calculated = h.hexdigest()
    # Compare the calculated signature with the provided signature
    if signature_calculated == signature:
        return True
    else:
        return False

def hash_argon2id(key, password):
    '''
    Applies Argon2 hashing to the password using a HMAC.
    :param key: key for the HMAC - bytes or hexadecimal string
    :param password: password to be hashed - string
    :return: Argon2 hash - string
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    # Create the HMAC
    h = HMAC.new(key,digestmod=SHA3_256)
    h.update(password.encode())
    # Convert to hexadecimal
    signature = h.hexdigest()
    
    # Apply Argon2 hashing
    ph = PasswordHasher()
    hash_argon = ph.hash(signature)
    return hash_argon

def verify_hash(hash_argon, key, password):
    '''
    Verifies if the Argon2 hash matches the password.
    :param hash_argon: stored Argon2 hash - string
    :param key: key for the HMAC - bytes or hexadecimal string
    :param password: password to be verified - string
    :return: True if the password is correct, False otherwise
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    # Create the HMAC
    h = HMAC.new(key,digestmod=SHA3_256)
    h.update(password.encode())
    # Convert to hexadecimal
    signature = h.hexdigest()
    
    # Apply Argon2 hashing
    ph = PasswordHasher()
    try:
        ph.verify(hash_argon, signature)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
