"""
This file contains AES-GCM symmetric encryption scheme primitives.
"""

from Crypto.Cipher import AES

import const
import function_utils as fu
import logging
import math
import sys


def key_gen(sym_key_size=const.SYM_KEY_DEFAULT_SIZE, debug=0):
    """
    Generate a random symmetric key with given size.
    :param sym_key_size: length in bytes of the symmetric key
    :param debug: if 1, # prints will be shown during execution; default 0, no # prints are shown
    :return: the randomly generated symmetric key
    """

    # Clamp the size between SYM_KEY_MIN_SIZE and the system maximum possible value
    size = fu.clamp(sym_key_size, const.SYM_KEY_MIN_SIZE, sys.maxsize)

    # Check if an error occurred during clamping
    if size is None:
        logging.error('sym_key_gen clamp size exception')
        # if debug:  # ONLY USE FOR DEBUG
            # print('EXCEPTION in sym_key_gen clamp size')
        raise Exception

    # Check if size is a power of 2
    if not math.log2(size).is_integer():
        logging.error('sym_key_gen size exception')
        # if debug:  # ONLY USE FOR DEBUG
            # print('EXCEPTION in sym_key_gen size')
        raise Exception

    # Generate and return a random symmetric key with the given size
    return fu.generate_random_bytes(size, debug)


def iv_gen(iv_length=const.IV_DEFAULT_SIZE, debug=0):
    """
    Generate an initialisation vector (IV) with the given length.
    :param iv_length: length in bytes of the IV
    :param debug: if 1, # prints will be shown during execution; default 0, no # prints are shown
    :return: the randomly generated IV
    """

    # Clamp the size between IV_DEFAULT_SIZE and the system maximum possible value
    length = fu.clamp(iv_length, const.IV_DEFAULT_SIZE, const.IV_MAX_SIZE)

    # Check if an error occurred during clamping
    if length is None:
        logging.error('generate_iv clamp length exception')
        # if debug:  # ONLY USE FOR DEBUG
            # print('EXCEPTION in generate_iv clamp length')
        raise Exception

    # Check if length is a power of 2
    if not math.log2(length).is_integer():
        logging.error('generate_iv length exception')
        # if debug:  # ONLY USE FOR DEBUG
            # print('EXCEPTION in generate_iv length')
        raise Exception

    # Generate and return a random IV with the given length
    return fu.generate_random_bytes(iv_length, debug)


def get_cipher(mode=AES.MODE_CTR, init_val=0, tag=None, key=None, iv=None, debug=0):
    """
    Create a cipher with the given mode, key and iv.
    :param mode: cipher mode
    :param init_val: initial value (ONLY FOR CTR MODE)
    :param tag: authentication tag (ONLY FOR GCM MODE)
    :param key: encryption key
    :param iv: initialisation vector
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the cipher
    """

    # Check if key is set
    if key is None:
        logging.error('cipher key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in cipher key')
        raise Exception

    # Check if iv is set
    if iv is None:
        logging.error('cipher iv exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in cipher iv')
        raise Exception

    # Construct a AES Cipher object with the given mode, key and IV
    if mode is AES.MODE_CTR:
        cipher = AES.new(key, mode, initial_value=init_val, nonce=iv)
    else:
        cipher = AES.new(key, mode, nonce=iv)

    return cipher


def encrypt(cipher=None, plaintext=None, debug=0):
    """
    Encrypt the given plaintext using the given cipher.
    :param cipher: cipher to use for encryption
    :param plaintext: data to encrypt
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the ciphertext
    """

    # Check if cipher is set
    if cipher is None:
        logging.error('encrypt cipher exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt cipher')
        raise Exception

    # Check if plaintext is set
    if plaintext is None:
        logging.error('encrypt plaintext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt plaintext')
        raise Exception

    # Encrypt the plaintext and return the related ciphertext
    return cipher.encrypt(plaintext)


def decrypt(cipher=None, ciphertext=None, debug=0):
    """
    Decrypt the ciphertext using the given cipher.
    :param cipher: cipher to use for encryption
    :param ciphertext: data to decrypt
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the plaintext
    """

    # Check if cipher is set
    if cipher is None:
        logging.error('decrypt cipher exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt cipher')
        raise Exception

    # Check if ciphertext is set
    if ciphertext is None:
        logging.error('decrypt ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt ciphertext')
        raise Exception

    # Decrypt the ciphertext and return the related ciphertext
    return cipher.decrypt(ciphertext)
