"""
This file contains AES-GCM symmetric encryption scheme primitives.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import const
import function_utils as fu
import logging
import math
import sys


def key_gen(sym_key_size=const.SYM_KEY_DEFAULT_SIZE, debug=0):
    """
    Generate a random symmetric key with given size.
    :param sym_key_size: length in bytes of the symmetric key
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the randomly generated symmetric key
    """

    # Clamp the size between SYM_KEY_MIN_SIZE and the system maximum possible value
    size = fu.clamp(sym_key_size, const.SYM_KEY_MIN_SIZE, sys.maxsize)

    # Check if an error occurred during clamping
    if size is None:
        logging.error('sym_key_gen clamp size exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_key_gen clamp size')
        raise Exception

    # Check if size is a power of 2
    if not math.log2(size).is_integer():
        logging.error('sym_key_gen size exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_key_gen size')
        raise Exception

    # Generate and return a random symmetric key with the given size
    return fu.generate_random_string(size, debug)


def iv_gen(iv_length=const.IV_DEFAULT_SIZE, debug=0):
    """
    Generate an initialisation vector (IV) with the given length.
    :param iv_length: length in bytes of the IV
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the randomly generated IV
    """

    # Clamp the size between IV_DEFAULT_SIZE and the system maximum possible value
    length = fu.clamp(iv_length, const.IV_DEFAULT_SIZE, sys.maxsize)

    # Check if an error occurred during clamping
    if length is None:
        logging.error('generate_iv clamp length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in generate_iv clamp length')
        raise Exception

    # Check if length is a power of 2
    if not math.log2(length).is_integer():
        logging.error('generate_iv length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in generate_iv length')
        raise Exception

    # Generate and return a random IV with the given length
    return fu.generate_random_string(iv_length, debug)


def encrypt(key=None, iv=None, plaintext=None, debug=0):
    """
    Encrypt the given plaintext using the AES-GCM with the given key and IV.
    :param key: encryption key
    :param iv: initialisation vector
    :param plaintext: data to encrypt
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the ciphertext
    """

    # Check if plaintext is set
    if plaintext is None:
        logging.error('sym_encrypt plaintext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_encrypt plaintext')
        raise Exception

    # Check if key is set
    if key is None:
        logging.error('sym_encrypt key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_encrypt key')
        raise Exception

    # Check if iv is set
    if iv is None:
        logging.error('sym_encrypt IV exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_encrypt IV')
        raise Exception

    # Construct an AES-GCM Cipher object with the given key and IV
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()

    # Encrypt the plaintext and return the related ciphertext (GCM does not require padding)
    return encryptor.update(plaintext)


def decrypt(key=None, iv=None, ciphertext=None, debug=0):
    """
    Decrypt the ciphertext using AES-GCM with the given key and IV.
    :param key: decryption key
    :param iv: initialisation vector
    :param ciphertext: data to decrypt
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the plaintext
    """

    # Check if key is set
    if key is None:
        logging.error('sym_decrypt key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_decrypt key')
        raise Exception

    # Check if iv is set
    if iv is None:
        logging.error('sym_decrypt IV exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_decrypt IV')
        raise Exception

    # Check if ciphertext is set
    if ciphertext is None:
        logging.error('sym_decrypt ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_decrypt ciphertext')
        raise Exception

    # Construct a Cipher object, with the key, IV and additionally the GCM tag used for authenticating the message
    decrypter = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).decryptor()

    # Decrypt the ciphertext and return the related ciphertext
    return decrypter.update(ciphertext)
