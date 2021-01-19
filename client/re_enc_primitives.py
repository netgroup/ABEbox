"""
This file contains Hybrid Proxy Re-Encryption scheme primitives. These functions are the implementation of the ones
defined in the work of S. Myers and A. Shull, "Efficient Hybrid Proxy Re-Encryption for Practical Revocation and Key
Rotation" (https://eprint.iacr.org/2017/833.pdf).
"""
# TODO AGGIORNARE DOCUMENTAZIONE, CONTROLLI VARIABILI, COMMENTI; RIMUOVE FUNZIONI NON UTILIZZATE -> RICONTROLLARE TUTTO!

from ABE.ac17 import AC17CPABE
from binascii import hexlify, unhexlify
from charm.core.engine.util import bytesToObject, objectToBytes
from charm.toolbox.policytree import PolicyParser
from const import SEED_LENGTH, SYM_KEY_DEFAULT_SIZE
from sym_enc_primitives import sym_decrypt, sym_encrypt

import logging
import random   # [WARNING] NOT CRYPTOGRAPHICALLY SECURE


def re_encrypt(data=None, args=None, debug=0):
    """ TODO AGGIORNARE DOCUMENTAZIONE E CONTROLLI VARIABILI
    Re-encrypt the ciphertext using the punctured encryption with new keys.
    :param ciphertext_infile: input file for re-encryption
    :param re_enc_length: number of bytes to re-encrypt
    :param new_pk_file: file where the new public key is stored
    :param policy: string containing the policy to apply to seed and key during encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the new ciphertext with all the parameters required for decryption
    """

    # Check if data is set
    if data is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    # Check if args is set and it contains some values
    if args is None or len(args) == 0:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    # Required re-encryption parameters
    re_enc_params = ['pk', 'sk', 'enc_seed', 'enc_key', 're_enc_length', 'iv', 'policy', 'pairing_group']

    for param in re_enc_params:
        if param not in args.keys():
            logging.error('re_encrypt ciphertext_infile exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in re_encrypt ciphertext_infile')
            raise Exception

    print('ARGS =', args)

    # Extracting re-encryption params
    pk = args[re_enc_params[0]]
    sk = args[re_enc_params[1]]
    pairing_group = args[re_enc_params[7]]
    enc_seed = bytesToObject(unhexlify(args[re_enc_params[2]]), pairing_group) if args[re_enc_params[2]] is not None \
        else None
    enc_key = bytesToObject(unhexlify(args[re_enc_params[3]]), pairing_group)
    re_enc_length = args[re_enc_params[4]]
    iv = unhexlify(args[re_enc_params[5]])
    policy = PolicyParser().parse(args[re_enc_params[6]])

    if debug:  # ONLY USE FOR DEBUG
        print('RE-APPLING RE-ENC:\nDATA = (%d) %s\nPK FILE = %s\nSK FILE = %s\nENC SEED = (%d) %s\nENC KEY = (%d) %s\n'
              'RE-ENC LENGTH = %d\nIV = (%d) %s'
              % (len(data), data, pk, sk, len(enc_seed), enc_seed, len(enc_key), enc_key, re_enc_length, len(iv), iv))

    # Check if parameters are set
    if pk is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    if sk is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    if enc_seed is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    if enc_key is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    if re_enc_length is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    if iv is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    # Decrypt seed, key and re_enc_length with ABE using given public and secret keys
    seed = None
    if enc_seed is not None:
        enc_seed['policy'] = policy
        seed = abe_decrypt(enc_seed, pk, sk, pairing_group, debug)
    enc_key['policy'] = policy
    key = abe_decrypt(enc_key, pk, sk, pairing_group, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('SEED =', seed)
        print('KEY =', key)
        print('RE-ENC LENGTH =', re_enc_length)

    # Convert seed, key and re_enc_length from pairing group elements to useful values
    seed = objectToBytes(seed, pairing_group)[: SEED_LENGTH] if seed is not None else None
    key = objectToBytes(key, pairing_group)[: SYM_KEY_DEFAULT_SIZE]
    re_enc_length = int(re_enc_length)

    # Re-encrypt the given number of bytes and get re-encryption parameters
    return re_enc_bytes(data, seed, key, iv, re_enc_length, debug)


def re_decrypt(data=None, args=None, debug=0):
    """
    Remove the last re-encryption applied to the given ciphertext file.
    :param ciphertext_infile: ciphertext file to decrypt
    :param pk_file: ABE public key
    :param sk_file: ABE secret key
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if data is set
    if data is None:
        logging.error('re_decrypt data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_decrypt data')
        raise Exception

    # Check if args is set and it contains some values
    if args is None or len(args) == 0:
        logging.error('re_decrypt pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_decrypt pk_file')
        raise Exception

    # Required re-encryption parameters
    re_enc_params = ['pk', 'sk', 'enc_seed', 'enc_key', 're_enc_length', 'iv', 'policy', 'pairing_group']

    for param in re_enc_params:
        if param not in args.keys():
            logging.error('re_encrypt ciphertext_infile exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in re_encrypt ciphertext_infile')
            raise Exception

    print('ARGS =', args)

    # Extracting re-encryption params
    pk = args[re_enc_params[0]]
    sk = args[re_enc_params[1]]
    pairing_group = args[re_enc_params[7]]
    enc_seed = bytesToObject(unhexlify(args[re_enc_params[2]]), pairing_group) if args[re_enc_params[2]] is not None \
        else None
    enc_key = bytesToObject(unhexlify(args[re_enc_params[3]]), pairing_group)
    re_enc_length = args[re_enc_params[4]]
    iv = unhexlify(args[re_enc_params[5]])
    policy = PolicyParser().parse(args[re_enc_params[6]])

    if debug:  # ONLY USE FOR DEBUG
        print('RE-APPLING RE-ENC:\nDATA = (%d) %s\nPK FILE = %s\nSK FILE = %s\nENC SEED = (%d) %s\nENC KEY = (%d) %s\n'
              'RE-ENC LENGTH = %d\nIV = (%d) %s'
              % (len(data), data, pk, sk, len(enc_seed), enc_seed, len(enc_key), enc_key, re_enc_length, len(iv), iv))

    # Check if parameters are set
    if pk is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    if sk is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    if enc_seed is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    if enc_key is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    if re_enc_length is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    if iv is None:
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    # Decrypt seed, key and re_enc_length with ABE using given public and secret keys
    seed = None
    if enc_seed is not None:
        enc_seed['policy'] = policy
        seed = abe_decrypt(enc_seed, pk, sk, pairing_group, debug)
    enc_key['policy'] = policy
    key = abe_decrypt(enc_key, pk, sk, pairing_group, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('SEED =', seed)
        print('KEY =', key)
        print('RE-ENC LENGTH =', re_enc_length)

    # Convert seed, key and re_enc_length from pairing group elements to useful values
    seed = objectToBytes(seed, pairing_group)[: SEED_LENGTH] if seed is not None else None
    key = objectToBytes(key, pairing_group)[: SYM_KEY_DEFAULT_SIZE]

    # Remove re-encryption from the ciphertext
    return remove_re_enc(data, seed, key, re_enc_length, iv, debug)


def re_enc_bytes(data=None, seed=None, key=None, iv=None, re_enc_length=None, debug=0):
    """ TODO AGGIORNARE DOCUMENTAZIONE E CONTROLLI VARIABILI
    Re-encrypt the given number of bytes in the transformed ciphertext in the input file
    :param ciphertext_infile: file where transformed ciphertext is stored
    :param ciphertext_offset: transformed ciphertext offset
    :param ciphertext_length: transformed ciphertext length
    :param re_enc_length: number of bytes to puncture
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the seed to generate random bytes indexes to re-encrypt, the symmetric key and IV used to re-encrypt
    """

    # Check if number of bytes to re-encrypt is greater than transformed ciphertext length
    if seed is not None:  # Apply punctured encryption

        # Get random bytes to re-encrypt and their positions in the input file
        bytes_to_re_enc, re_enc_indexes = get_bytes_to_re_enc(data, re_enc_length, seed, debug)

        if debug:  # ONLY USE FOR DEBUG
            print('SEED = (%d) %s' % (len(seed), seed))
            print('BYTES TO RE-ENCRYPT = (%d) %s' % (len(bytes_to_re_enc), bytes_to_re_enc))
            print('INDEX TO RE-ENCRYPT = (%d) %s' % (len(re_enc_indexes), re_enc_indexes))

        # Re-encrypt random ciphertext bytes
        re_encr_bytes = sym_encrypt(key, iv, bytes_to_re_enc, debug)

        if debug:  # ONLY USE FOR DEBUG
            print('RE-ENCRYPTED BYTES = (%d) %s' % (len(re_encr_bytes), re_encr_bytes))

        # Replace bytes with re-encrypted ones in the given file
        return replace_re_enc_bytes(data, re_encr_bytes, re_enc_indexes, debug)

    else:  # Re-encryption of the whole transformed ciphertext

        # Re-encrypt transformed ciphertext
        return sym_encrypt(key, iv, data, debug)


def get_bytes_to_re_enc(data=None, re_enc_length=None, seed=None, debug=0):
    """ TODO AGGIORNARE DOCUMENTAZIONE E CONTROLLI
    Puncture the ciphertext selecting a given number of bytes to re-encrypt.
    :param ciphertext_infile: the transformed ciphertext to puncture
    :param ciphertext_offset: transformed ciphertext offset in the input file
    :param ciphertext_length: transformed ciphertext length
    :param re_enc_length: number of bytes to select
    :param seed: seed for random
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: a string containing the bytes to re-encrypt and their positions in the input file
    """

    # Check if data is set
    if data is None:
        logging.error('get_bytes_to_re_enc data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_bytes_to_re_enc data')
        raise Exception

    # Check if re_enc_length is set
    if re_enc_length is None:
        logging.error('get_bytes_to_re_enc re_enc_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_bytes_to_re_enc re_enc_length')
        raise Exception

    if debug:  # ONLY USE FOR DEBUG
        print('RE-ENCRYPTION SEED = (%d) %s' % (len(seed), seed))
        print('RE-ENC LEN = (%s) %s' % (type(re_enc_length), re_enc_length))
        print('DATASET = (%s) %s' % (type(range(len(data))), range(len(data))))

    # Generate a pseudorandom set of indexes to re-encrypt
    re_enc_indexes = ind(seed, re_enc_length, range(len(data)))

    if debug:  # ONLY USE FOR DEBUG
        print('INDEXES =', re_enc_indexes)

    # Sort indexes to re-encrypt
    re_enc_indexes.sort()

    if debug:  # ONLY USE FOR DEBUG
        print('SORTED INDEXES =', re_enc_indexes)

    # Define variables
    bytes_to_re_enc = b''

    # Get bytes to re-encrypt
    for index in re_enc_indexes:

        if debug:  # ONLY USE FOR DEBUG
            print('BYTE TO RE-ENCRYPT #', index, '=', data[index:index + 1])

        # Append the hexadecimal representation of the byte to a string
        bytes_to_re_enc += data[index:index + 1]

    if debug:  # ONLY USE FOR DEBUG
        print('BYTES TO RE-ENC = (%d) %s' % (len(bytes_to_re_enc), bytes_to_re_enc))

    return bytes_to_re_enc, re_enc_indexes


def ind(seed=None, size=None, dataset=None, debug=0):
    """
    Generate a pseudorandom set of l values.
    :param seed: seed for the pseudorandom generator
    :param size: size of the set to generate
    :param dataset: elements to sample
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: a list of 'size' pseudorandom values
    """

    # Check if seed is set
    if seed is None:
        logging.error('ind seed exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in ind seed')
        raise Exception

    # Check if size is set
    if size is None:
        logging.error('ind size exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in ind size')
        raise Exception

    # Check if dataset is set
    if dataset is None:
        logging.error('ind set exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in ind set')
        raise Exception

    # Plant the given seed for random generator
    random.seed(seed)

    # Return a random sample of 'size' elements from the given set
    return random.sample(dataset, size)


def replace_re_enc_bytes(data=None, re_encr_bytes=None, re_enc_indexes=None, debug=0):
    """ TODO AGGIORNARE DOCUMENTAZIONE E CONTROLLI VARIABILI
    Replace re-encrypted bytes in the ciphertext in the input file.
    :param ciphertext_infile: the file whose bytes must be replaced
    :param re_encr_bytes: re-encrypted bytes
    :param re_enc_indexes: positions of bytes to replace in the ciphertext
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if data is set
    if data is None:
        logging.error('replace_re_enc_bytes data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bytes data')
        raise Exception

    # Check if re_encr_bytes is set
    if re_encr_bytes is None:
        logging.error('replace_re_enc_bytes re_encr_bytes exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bytes re_encr_bytes')
        raise Exception

    # Check if re_enc_indexes is set
    if re_enc_indexes is None:
        logging.error('replace_re_enc_bytes re_enc_indexes exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bytes re_enc_indexes')
        raise Exception

    data = bytearray(data)

    # Overwrite bytes in the specified file
    for i in range(len(re_enc_indexes)):

        if debug:  # ONLY USE FOR DEBUG
            print('#%d: REPLACING BYTE IN POSITION %d WITH BYTE %s' % (i, re_enc_indexes[i], re_encr_bytes[i:i+1]))

        # Overwrite byte with re-encrypted one
        data[re_enc_indexes[i]:re_enc_indexes[i]+1] = re_encr_bytes[i:i+1]

    print('REPLACED BYTES DATA = (%s) (%d) %s' % (type(data), len(data), data))

    return bytes(data)


def abe_decrypt(enc_data=None, pk=None, sk=None, pairing_group=None, debug=0):
    """
    Decrypt encrypted seed, symmetric key and re-encryption length with ABE using the given public and secret key.
    :param enc_seed_key_len: encrypted seed, symmetric key and re-encryption length to decrypt
    :param pk_file: ABE public key
    :param sk_file: ABE secret key
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: decrypted seed, symmetric key and number of re-encryption length
    """

    # Check if enc_data is set
    if enc_data is None:
        logging.error('decrypt_seed_key ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_seed_key ciphertext')
        raise Exception

    # Check if pk is set and it exists
    if pk is None:
        logging.error('[ERROR] decrypt_seed_key pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_seed_key pk_file')
        raise Exception

    # Check if sk is set and it exists
    if sk is None:
        logging.error('decrypt_seed_key sk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_seed_key sk_file')
        raise Exception

    # Decrypt data with ABE
    cpabe = AC17CPABE(pairing_group, 2)
    data = cpabe.decrypt(pk, enc_data, sk)

    print('DEC DATA =', data)

    return data


def remove_re_enc(re_enc_data=None, seed=None, k=None, re_enc_length=None, iv=None, debug=0):
    """
    Remove re-encryption from the given file.
    :param ciphertext_infile: file where re-encryption has to be removed
    :param seed: the seed to generate positions of re-encrypted bytes
    :param k: symmetric key used to re-encrypt
    :param re_enc_length: re-encrypted bytes number
    :param iv: IV used to re-encrypt
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if ciphertext is set
    if re_enc_data is None:
        logging.error('remove_re_enc ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_enc ciphertext')
        raise Exception

    # Check if k is set
    if k is None:
        logging.error('remove_re_enc k exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_enc k')
        raise Exception

    # Check if full transformed ciphertext has to be decrypted
    if seed is None:  # Full re-decryption

        # Read transformed ciphertext from file
        if debug:  # ONLY USE FOR DEBUG
            print('RE_ENC_DATA = (%d) %s' % (len(re_enc_data), re_enc_data))

        # Decrypt re-encrypted transformed ciphertext
        re_dec_data = sym_decrypt(k, iv, re_enc_data, debug)

        if debug:  # ONLY USE FOR DEBUG
            print('RE-DECRYPTED DATA = (%d) %s' % (len(re_dec_data), re_dec_data))

        # Check if lengths are incompatible
        if len(re_dec_data) != len(re_enc_data):
            logging.error('re-decrypted and re-encrypted transformed ciphertext lengths incompatibility')
            if debug:  # ONLY USE FOR DEBUG
                print('[ERROR] Re-decryption and original lengths incompatibility')
            raise Exception

    else:  # Apply punctured encryption

        # Get random re-encrypted bytes to decrypt
        bytes_to_re_enc, re_enc_indexes = get_bytes_to_re_enc(re_enc_data, re_enc_length, seed, debug)

        if debug:  # ONLY USE FOR DEBUG
            print('SEED = (%d) %s' % (len(seed), seed))

        # Decrypt re-encrypted transformed ciphertext bytes
        dec_ciphertext = sym_decrypt(k, iv, bytes_to_re_enc, debug)

        if debug:  # ONLY USE FOR DEBUG
            print('DECRYPTED CIPHERTEXT = (%d) %s -> %s' % (len(dec_ciphertext), dec_ciphertext,
                                                            hexlify(dec_ciphertext).decode()))

        # Replace re-encrypted bytes in the file with decrypted ones
        re_dec_data = replace_re_enc_bytes(re_enc_data, dec_ciphertext, re_enc_indexes, debug)

    return re_dec_data
