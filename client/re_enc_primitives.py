"""
This file contains all the primitives for the Puncturing Encryption of the re-encryption process.
"""

from Crypto.Cipher import AES

import const
import logging
import random                       # [WARNING] NOT CRYPTOGRAPHICALLY SECURE
import sym_enc_primitives as sym


def re_encrypt(data=None, re_enc_length=const.RE_ENC_LENGTH, seed=None, key=None, iv=None, init_val=None, debug=0):
    """
    Re-encrypt data using the given parameters.
    :param data: data to re-encrypt
    :param re_enc_length: number of bytes to re-encrypt
    :param seed: seed to randomly select bytes to re-encrypt
    :param key: symmetric key to encrypt randomly selected bytes
    :param iv: initialisation vector for the symmetric encryption
    :param init_val: initial value (ONLY FOR CTR MODE)
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: re-encrypted data
    """

    # Check if data is set
    if data is None:
        logging.error('re_encrypt data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt data')
        raise Exception

    # Check if key is set
    if key is None:
        logging.error('re_encrypt key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt key')
        raise Exception

    # Check if iv is set
    if iv is None:
        logging.error('re_encrypt iv exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt iv')
        raise Exception

    # Check if the number of bytes to re-encrypt is lesser than the data length
    if re_enc_length < len(data):  # Apply punctured encryption

        return apply_punctured_enc(data, re_enc_length, seed, key, iv, init_val, debug)

    else:  # Re-encryption of the whole data

        sym_cipher = sym.get_cipher(AES.MODE_CTR, init_val, None, key, iv)
        return sym.encrypt(sym_cipher, data, debug)


def re_decrypt(data=None, re_enc_length=const.RE_ENC_LENGTH, seed=None, key=None, iv=None, init_val=None, debug=0):
    """
    Re-decrypt data using the given parameters.
    :param data: data to re-decrypt
    :param re_enc_length: number of re-encrypted bytes
    :param seed: seed that randomly selected re-encrypted bytes
    :param key: symmetric key to decrypt randomly selected bytes
    :param iv: initialisation vector for the symmetric decryption
    :param init_val: initial value (ONLY FOR CTR MODE)
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: re-decrypted data
    """

    # Check if data is set
    if data is None:
        logging.error('re_decrypt data exception')
        # if debug:  # ONLY USE FOR DEBUG
            # print('EXCEPTION in re_decrypt data')
        raise Exception

    # Check if key is set
    if key is None:
        logging.error('re_decrypt key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_decrypt key')
        raise Exception

    # Check if iv is set
    if iv is None:
        logging.error('re_decrypt iv exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_decrypt iv')
        raise Exception

    # Check if the number of bytes to re-encrypt is lesser than the data length
    if re_enc_length < len(data):  # Apply punctured encryption

        return remove_punctured_enc(data, re_enc_length, seed, key, iv, init_val, debug)

    else:  # Re-encryption of the whole data

        sym_cipher = sym.get_cipher(AES.MODE_CTR, init_val, None, key, iv)
        return sym.decrypt(sym_cipher, data, debug)


def apply_punctured_enc(data, re_enc_length, seed, key, iv, init_val, debug=0):
    """
    Apply punctured encryption to the given data: 're_enc_length' bytes are randomly selected using the seed and
    symmetrically encrypted using the given key and iv.
    :param data: data to re-encrypt
    :param re_enc_length: number of bytes to re-encrypt
    :param seed: seed to randomly select bytes to re-encrypt
    :param key: symmetric key to encrypt randomly selected bytes
    :param iv: initialisation vector for the symmetric encryption
    :param init_val: initial value (ONLY FOR CTR MODE)
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: re-encrypted data
    """

    # Get random bytes to re-encrypt and their positions in the data
    bytes_to_re_enc, re_enc_indexes = get_bytes_to_re_enc(data, re_enc_length, seed, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('BYTES TO RE-ENCRYPT = (%d) %s' % (len(bytes_to_re_enc), bytes_to_re_enc))
        print('INDEX TO RE-ENCRYPT = (%d) %s' % (len(re_enc_indexes), re_enc_indexes))

    # Re-encrypt random data bytes
    sym_cipher = sym.get_cipher(AES.MODE_CTR, init_val, None, key, iv)
    re_enc_bytes = sym.encrypt(sym_cipher, bytes_to_re_enc, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('RE-ENCRYPTED BYTES = (%s) (%d) %s' % (type(re_enc_bytes), len(re_enc_bytes), re_enc_bytes))

    # Replace bytes with re-encrypted ones in data
    return replace_bytes(data, re_enc_bytes, re_enc_indexes, debug)


def remove_punctured_enc(data, re_enc_length, seed, key, iv, init_val, debug=0):
    """
    Remove punctured encryption to the given data: 're_enc_length' bytes are randomly selected using the seed and
    symmetrically decrypted using the given key and iv.
    :param data: data to re-decrypt
    :param re_enc_length: number of re-encrypted bytes
    :param seed: seed that randomly selected re-encrypted bytes
    :param key: symmetric key to decrypt randomly selected bytes
    :param iv: initialisation vector for the symmetric decryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: re-decrypted data
    """

    # Get random re-encrypted bytes to decrypt
    bytes_to_re_dec, re_dec_indexes = get_bytes_to_re_enc(data, re_enc_length, seed, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('BYTES TO RE-DECRYPT = (%d) %s' % (len(bytes_to_re_dec), bytes_to_re_dec))
        print('INDEX TO RE-DECRYPT = (%d) %s' % (len(re_dec_indexes), re_dec_indexes))

    # Decrypt re-encrypted data bytes
    sym_cipher = sym.get_cipher(AES.MODE_CTR, init_val, None, key, iv)
    re_dec_bytes = sym.decrypt(sym_cipher, bytes_to_re_dec, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('RE-DECRYPTED BYTES = (%s) (%d) %s' % (type(re_dec_bytes), len(re_dec_bytes), re_dec_bytes))

    # Replace bytes with re-decrypted ones in data
    return replace_bytes(data, re_dec_bytes, re_dec_indexes, debug)


def get_bytes_to_re_enc(data=None, re_enc_length=None, seed=None, debug=0):
    """
    Randomly select the given number of bytes to re-encrypt from data using the given seed.
    :param data: data where bytes are randomly selected from
    :param re_enc_length: number of bytes to select
    :param seed: seed for random selection
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: a string containing the bytes to re-encrypt and an array with their positions in data
    """

    if debug:  # ONLY USE FOR DEBUG
        print('DATA = (%s) (%d) %s' % (type(data), len(data), data))
        print('RE-ENC LENGTH = %d' % re_enc_length)
        print('SEED = (%d) %s' % (len(seed), seed))

    # Generate a pseudorandom set of indexes to re-encrypt
    re_enc_indexes = ind(seed, re_enc_length, range(len(data)))

    # if debug:  # ONLY USE FOR DEBUG
        # print('INDEXES =', re_enc_indexes)

    # Sort indexes to re-encrypt
    re_enc_indexes.sort()

    # if debug:  # ONLY USE FOR DEBUG
        # print('SORTED INDEXES =', re_enc_indexes)

    # Define variables
    bytes_to_re_enc = b''

    # Get bytes to re-encrypt
    for index in re_enc_indexes:

        # Append the hexadecimal representation of the byte to a string
        bytes_to_re_enc += data[index:index+1]

    return bytes_to_re_enc, re_enc_indexes


def ind(seed=None, size=None, dataset=None, debug=0):
    """
    Generate a pseudorandom set of l values.
    :param seed: seed for the pseudorandom generator
    :param size: size of the set to generate
    :param dataset: elements to sample
    :param debug: if 1, # prints will be shown during execution; default 0, no # prints are shown
    :return: a list of 'size' pseudorandom values
    """

    # Plant the given seed for random generator
    random.seed(a=seed)

    if debug:  # ONLY USE FOR DEBUG
        print('DATASET =', dataset)
        print('SEED =', seed)
        print('SIZE =', size)

    # Return a random sample of 'size' elements from the given set
    return random.sample(dataset, size)


def replace_bytes(data=None, new_bytes=None, new_bytes_indexes=None, debug=0):
    """
    Replace new bytes in data.
    :param data: data whose bytes must be replaced
    :param new_bytes: new bytes
    :param new_bytes_indexes: positions of bytes to replace in data
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: replaced data
    """

    # Check if data is set
    if data is None:
        logging.error('replace_re_enc_bytes data exception')
        # if debug:  # ONLY USE FOR DEBUG
            # print('EXCEPTION in replace_re_enc_bytes data')
        raise Exception

    # Check if new_bytes is set
    if new_bytes is None:
        logging.error('replace_re_enc_bytes new_bytes exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bytes new_bytes')
        raise Exception

    # Check if new_bytes_indexes is set
    if new_bytes_indexes is None:
        logging.error('replace_re_enc_bytes new_bytes_indexes exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bytes new_bytes_indexes')
        raise Exception

    data = bytearray(data)

    # Overwrite bytes in the specified file
    for i in range(len(new_bytes_indexes)):

        # Replace byte with re-encrypted one
        data[new_bytes_indexes[i]:new_bytes_indexes[i]+1] = new_bytes[i:i+1]

    return bytes(data)
