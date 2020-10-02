# This file contains AES-GCM symmetric encryption scheme primitives.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from Log import log


# Generate a random symmetric key with given size.
# Params:
# - sym_key_size = length in bytes of the symmetric key
# - debug = if 1, prints will be shown during execution; default 0, no prints are shown
def sym_key_gen(sym_key_size=None, debug=0):

    from Const import SYM_KEY_MIN_SIZE, SYM_KEY_DEFAULT_SIZE
    from FunctionUtils import clamp, generate_random_string

    if sym_key_size is None:
        sym_key_size = SYM_KEY_DEFAULT_SIZE

    import sys

    # Set the minimum possible symmetric key size to the one defined in SYM_KEY_MIN_SIZE
    size = clamp(sym_key_size, SYM_KEY_MIN_SIZE, sys.maxsize)

    if size is None:
        log('[ERROR] Clamping value exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in clamp')
        raise Exception

    import math

    # Check size is a power of 2
    if not math.log2(size).is_integer():
        log('[ERROR] Generate symmetric key size exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in generate_sym_key size')
        raise Exception

    return generate_random_string(length=size, debug=debug)


# Encrypt the plaintext using the AES-GCM with the given key and a randomly generated IV.
# Params:
# - key = encryption key
# - plaintext = data to encrypt
# - associated_data = data associated to the encryption that will be authenticated but not encrypted (it must also be
#   passed in on decryption)
# - debug = if 1, prints will be shown during execution; default 0, no prints are shown
def sym_encrypt(key=None, plaintext=None, associated_data=None, debug=0):

    # Check if the plaintext is set
    if plaintext is None:
        log('[ERROR] Encryption plaintext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encryption plaintext')
        raise Exception

    # Check if the key is set
    if key is None:
        log('[ERROR] Encryption key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encryption key')
        raise Exception

    from Const import IV_DEFAULT_SIZE
    import os

    # Generate a random initialization vector
    iv = os.urandom(IV_DEFAULT_SIZE)

    # Construct an AES-GCM Cipher object with the given key and IV
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()

    # Check if associated_data is set
    if associated_data is not None:
        encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext (GCM does not require padding)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag


# Decrypt the ciphertext using AES-GCM with the given key and IV.
# Params:
# - key = decryption key
# - associated_data = data associated to the encryption
# - iv = initialization vector
# - ciphertext = data to decrypt
# - tag = used for authenticating the message during the decryption
# - debug = if 1, prints will be shown during execution; default 0, no prints are shown
def sym_decrypt(key=None, associated_data=None, iv=None, ciphertext=None, tag=None, debug=0):

    # Check if the ciphertext is set
    if ciphertext is None:
        log('[ERROR] Decryption ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decryption ciphertext')
        raise Exception

    # Check if the key is set
    if key is None:
        log('[ERROR] Decryption key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decryption key')
        raise Exception

    # Check if the IV is set
    if iv is None:
        log('[ERROR] Decryption IV exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decryption IV')
        raise Exception

    # Construct a Cipher object, with the key, IV and additionally the GCM tag used for authenticating the message
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()

    if associated_data is not None:
        # associated_data is put back in or the tag will fail to verify when we finalize the decryptor
        decryptor.authenticate_additional_data(associated_data)

    # Decryption gets you the authenticated plaintext (if the tag does not match an InvalidTag exception will be raised)
    return decryptor.update(ciphertext) + decryptor.finalize()
