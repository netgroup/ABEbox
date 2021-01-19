"""
This file contains Hybrid Proxy Re-Encryption scheme primitives. These functions are the implementation of the ones
defined in the work of S. Myers and A. Shull, "Efficient Hybrid Proxy Re-Encryption for Practical Revocation and Key
Rotation" (https://eprint.iacr.org/2017/833.pdf).
"""
# TODO AGGIORNARE DOCUMENTAZIONE, CONTROLLI VARIABILI, COMMENTI; RIMUOVE FUNZIONI NON UTILIZZATE -> RICONTROLLARE TUTTO!

from ABE.ac17 import AC17CPABE
from charm.toolbox.pairinggroup import GT, PairingGroup
from charm.core.engine.util import bytesToObject, objectToBytes

import logging


def re_encrypt(ciphertext_infile=None, chunk_size=None, re_enc_length=None, pairing_group=None, pk=None, policy=None, debug=0):
    """ TODO AGGIORNARE DOCUMENTAZIONE E CONTROLLI VARIABILI
    Re-encrypt the ciphertext using the punctured encryption with new keys.
    :param ciphertext_infile: input file for re-encryption
    :param re_enc_length: number of bytes to re-encrypt
    :param new_pk_file: file where the new public key is stored
    :param policy: string containing the policy to apply to seed and key during encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the new ciphertext with all the parameters required for decryption
    """

    from re_enc_engine.const import RE_ENC_LENGTH
    import logging
    import os.path

    # Check if ciphertext_infile is set and it exists
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        logging.error('re_encrypt ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt ciphertext_infile')
        raise Exception

    # Check if pk is set
    if pk is None:
        logging.error('re_encrypt new_pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt new_pk_file')
        raise Exception

    # Check if policy is set
    if policy is None:
        logging.error('re_encrypt policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_encrypt policy')
        raise Exception

    # If re-encryption length is not set, assign a default value
    if re_enc_length is None:
        re_enc_length = RE_ENC_LENGTH

    # Re-encrypt the given number of bytes and get re-encryption parameters
    seed, k, iv, re_enc_length = re_enc_ciphertext_bytes(ciphertext_infile, chunk_size, re_enc_length, pairing_group, debug)

    enc_seed = abe_encrypt(seed, pairing_group, pk, policy, debug)
    enc_key = abe_encrypt(k, pairing_group, pk, policy, debug)
    # enc_re_enc_length = abe_encrypt(re_enc_length, pairing_group, pk, policy, debug)

    if debug:  # ONLY USE FOR DEBUG
        if seed is not None:
            print('SEED = (%d) %s' % (len(objectToBytes(seed, pairing_group)), objectToBytes(seed, pairing_group)))
            print('ENC SEED = (%s) %s' % (type(enc_seed), enc_seed))
        else:
            print('SEED =', seed)
            print('ENC SEED =', seed)
        print('KEY = (%d) %s' % (len(objectToBytes(k, pairing_group)), objectToBytes(k, pairing_group)))
        print('ENC KEY = (%s) %s' % (type(enc_key), enc_key))
        print('IV = (%d) %s' % (len(iv), iv))
        # print('RE-ENCRYPTION LENGTH = (%d) %s' % (len(objectToBytes(re_enc_length, pairing_group)), objectToBytes(re_enc_length, pairing_group)))
        # print('ENC RE-ENCRYPTION LENGTH = (%s) %s' % (type(enc_re_enc_length), enc_re_enc_length))

    # Encrypt seed, key and number of re-encrypted bytes using ABE with given public key and policy
    enc_seed = objectToBytes(enc_seed, pairing_group) if seed is not None else None
    enc_k = objectToBytes(enc_key, pairing_group)
    # enc_re_enc_length = objectToBytes(enc_re_enc_length, pairing_group)

    return enc_seed, enc_k, re_enc_length, iv


def re_enc_ciphertext_bytes(ciphertext_infile=None, chunk_size=None, re_enc_length=None, pairing_group=None, debug=0):
    """ TODO AGGIORNARE DOCUMENTAZIONE E CONTROLLI VARIABILI
    Re-encrypt the given number of bytes in the ciphertext file.
    :param ciphertext_infile: input file for re-encryption
    :param re_enc_length: number of bytes to re-encrypt
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the seed to generate random bytes indexes to re-encrypt, the symmetric key and IV used to re-encrypt,
    the number of re-encrypted bytes
    """

    from re_enc_engine.const import RE_ENC_LENGTH
    import logging
    import os.path

    # Check if ciphertext_infile is set and it exists
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        logging.error('re_enc_ciphertext_bytes ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_enc_ciphertext_bytes ciphertext_infile')
        raise Exception

    # If re-encryption length is not set, assign a default value
    if re_enc_length is None:
        re_enc_length = RE_ENC_LENGTH

    # Apply punctured encryption and return re-encryption parameters
    return apply_punctured_enc(ciphertext_infile, chunk_size, re_enc_length, pairing_group, debug)


def apply_punctured_enc(ciphertext_infile=None, chunk_size=None, re_enc_length=None, pairing_group=None, debug=0):
    """ TODO AGGIORNARE DOCUMENTAZIONE E CONTROLLI VARIABILI
    Apply punctured encryption to the transformed ciphertext in the given input file.
    :param ciphertext_infile: file where transformed ciphertext is stored
    :param ciphertext_offset: transformed ciphertext offset
    :param ciphertext_length: transformed ciphertext length
    :param re_enc_length: number of bytes to puncture
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the seed to generate random bytes indexes to re-encrypt, the symmetric key and IV used to re-encrypt,
    the number of re-encrypted bytes
    """

    import logging
    import os.path

    # Check if the ciphertext_infile is set and it exists
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        logging.error('apply_punctured_enc ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_punctured_enc ciphertext_infile')
        raise Exception

    # Check if chunk_size is set
    if chunk_size is None:
        logging.error('apply_punctured_enc ciphertext_offset exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_punctured_enc ciphertext_offset')
        raise Exception

    from re_enc_engine.const import RE_ENC_MIN_LENGTH, RE_ENC_LENGTH
    from re_enc_engine.function_utils import clamp

    # Set default value for re-encryption length if it is not set
    if re_enc_length is None:
        re_enc_length = RE_ENC_LENGTH

    # Clamp the number of bytes to re-encrypt between RE_ENC_MIN_LENGTH and ciphertext_length
    re_enc_length = clamp(re_enc_length, RE_ENC_MIN_LENGTH, chunk_size // 8, debug)

    # Check if an error occurred during clamping
    if re_enc_length is None:
        logging.error('clamp value exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in clamp value')
        raise Exception

    if debug:  # ONLY USE FOR DEBUG
        print('RE_ENC_LENGTH = %d' % re_enc_length)

    # Re-encrypt the given number of bytes in the ciphertext and get re-encryption parameters
    seed, k, iv = re_enc_bytes(ciphertext_infile, chunk_size, re_enc_length, pairing_group, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('SEED =', seed)
        print('KEY =', k)
        print('IV =', iv)

    return seed, k, iv, re_enc_length


def re_enc_bytes(ciphertext_infile=None, chunk_size=None, re_enc_length=None, pairing_group=None, debug=0):
    """ TODO AGGIORNARE DOCUMENTAZIONE E CONTROLLI VARIABILI
    Re-encrypt the given number of bytes in the transformed ciphertext in the input file
    :param ciphertext_infile: file where transformed ciphertext is stored
    :param ciphertext_offset: transformed ciphertext offset
    :param ciphertext_length: transformed ciphertext length
    :param re_enc_length: number of bytes to puncture
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the seed to generate random bytes indexes to re-encrypt, the symmetric key and IV used to re-encrypt
    """

    import logging
    import os.path

    # Check if ciphertext_infile is set and it exists
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        logging.error('re_enc_bytes ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_enc_bytes ciphertext_infile')
        raise Exception

    # Check if ciphertext_offset is set
    if chunk_size is None:
        logging.error('re_enc_bytes ciphertext_offset exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_enc_bytes ciphertext_offset')
        raise Exception

    from const import IV_DEFAULT_SIZE, SEED_LENGTH
    from sym_enc_primitives import generate_iv

    # Create the re-encryption symmetric key
    k, k_pg_elem = sym_key_gen(pairing_group, SEED_LENGTH, debug)

    # Create the IV for symmetric re-encryption
    iv = generate_iv(IV_DEFAULT_SIZE, debug)

    # Define variables
    seed_pg_elem = None

    from binascii import hexlify

    if debug:  # ONLY USE FOR DEBUG
        print('RE-ENCRYPTION SYM KEY = (%d) %s -> %s' % (len(k), k, hexlify(k).decode()))
        print('RE-ENCRYPTION IV = (%d) %s -> %s' % (len(iv), iv, hexlify(iv).decode()))

    # Check if number of bytes to re-encrypt is greater than transformed ciphertext length
    if re_enc_length < chunk_size:  # Apply punctured encryption

        # Generate a pseudorandom seed
        seed, seed_pg_elem = random_string_gen(pairing_group, SEED_LENGTH, debug)

        with open(ciphertext_infile, 'rb+') as f:

            for file_chunk in iter(lambda: f.read(chunk_size), ''):

                if debug:  # ONLY USE FOR DEBUG
                    print('FILE CHUNK TO RE-ENC = (%s) (%d) %s' % (type(file_chunk), len(file_chunk), file_chunk))

                if not len(file_chunk):
                    break

                # Get random bytes to re-encrypt and their positions in the input file
                bytes_to_re_enc, re_enc_indexes = get_bytes_to_re_enc(file_chunk, re_enc_length, seed, debug)

                if debug:  # ONLY USE FOR DEBUG
                    print('SEED = (%d) %s' % (len(seed), seed))
                    print('BYTES TO RE-ENCRYPT = (%d) %s' % (len(bytes_to_re_enc), bytes_to_re_enc))
                    print('INDEX TO RE-ENCRYPT = (%d) %s' % (len(re_enc_indexes), re_enc_indexes))

                from re_enc_engine.sym_enc_primitives import sym_encrypt

                # Re-encrypt random ciphertext bytes
                re_encr_bytes = sym_encrypt(key=k, iv=iv, plaintext=bytes_to_re_enc, debug=debug)

                if debug:  # ONLY USE FOR DEBUG
                    print('RE-ENCRYPTED BYTES = (%s) (%d) %s' % (type(re_encr_bytes), len(re_encr_bytes), re_encr_bytes))

                # Replace bytes with re-encrypted ones in the given file
                re_enc_file_chunk = replace_re_enc_bytes(file_chunk, re_encr_bytes, re_enc_indexes, debug)

                if debug:  # ONLY USE FOR DEBUG
                    print('PUNCTURED FILE CHUNK = (%s) (%d) %s' % (type(re_enc_file_chunk), len(re_enc_file_chunk), re_enc_file_chunk))

                f.seek(-len(re_enc_file_chunk), os.SEEK_CUR)
                f.write(re_enc_file_chunk)

    else:  # Re-encryption of the whole transformed ciphertext

        with(open(ciphertext_infile, 'wb+')) as f:

            for file_chunk in iter(lambda: f.read(chunk_size), ''):

                if debug:  # ONLY USE FOR DEBUG
                    print('FILE CHUNK TO RE-ENC = (%s) (%d) %s' % (type(file_chunk), len(file_chunk), file_chunk))

                if not len(file_chunk):
                    break

                from re_enc_engine.sym_enc_primitives import sym_encrypt

                # Re-encrypt transformed ciphertext
                re_enc_file_chunk = sym_encrypt(key=k, iv=iv, plaintext=file_chunk, debug=debug)

                if debug:  # ONLY USE FOR DEBUG
                    print('RE-ENC FILE CHUNK = (%d) %s' % (len(re_enc_file_chunk), re_enc_file_chunk))

                # Check if there have been errors during re-encryption
                if len(re_enc_file_chunk) != chunk_size:
                    logging.error('re-encrypted and original transformed ciphertext lengths incompatibility')
                    if debug:  # ONLY USE FOR DEBUG
                        print('[ERROR] re-encryption and original lengths incompatibility')
                    raise Exception

                # Overwrite previous transformed ciphertext
                f.seek(-len(re_enc_file_chunk), 1)
                f.write(re_enc_file_chunk)

    return seed_pg_elem, k_pg_elem, iv


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

    import logging

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
        print('DATA = (%s) (%d) %s' % (type(data), len(data), data))

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
            print('BYTE TO RE-ENCRYPT #', index, '=', data[index:index+1])

        # Append the hexadecimal representation of the byte to a string
        bytes_to_re_enc += data[index:index+1]

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

    import logging

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

    import random   # [WARNING] NOT CRYPTOGRAPHICALLY SECURE

    # Plant the given seed for random generator
    random.seed(a=seed)

    print('SEED =', seed)
    print('DATASET =', dataset)
    print('SIZE =', size)

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

    import logging

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


def abe_encrypt(data=None, pairing_group=None, pk=None, policy=None, debug=0):
    """
    Encrypt data using ABE scheme with the given public key and policy
    :param data: the content to encrypt
    :param pk_file: file containing the public key
    :param policy: policy to apply during encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: encrypted data
    """

    import logging

    # Check if data is set
    if data is None:
        logging.error('encrypt_seed_key_len data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_seed_key_len data')
        raise Exception

    # Check if pk is set
    if pk is None:
        logging.error('encrypt_seed_key_len pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_seed_key_len pk_file')
        raise Exception

    # Check if policy is set
    if policy is None:
        logging.error('encrypt_seed_key_len policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_seed_key_len policy')
        raise Exception

    print('DATA = (%s) %s' % (type(data), data))
    print('PK = (%s) %s' % (type(pk), pk))
    print('POLICY = (%s) %s' % (type(policy), policy))

    # Encrypt data with ABE
    cpabe = AC17CPABE(pairing_group, 2)
    enc_data = cpabe.encrypt(pk, data, policy)
    print('ENC DATA WITH POLICY = (%d) %s' % (len(enc_data), enc_data))
    enc_data.pop('policy')

    if debug:  # ONLY USE FOR DEBUG
        print('ENCRYPTED DATA = (%d) %s' % (len(enc_data), enc_data))

    return enc_data


def re_decrypt(data=None, pk_file=None, sk_file=None, enc_params=None, iv=None, debug=0):
    """
    Remove the last re-encryption applied to the given ciphertext file.
    :param ciphertext_infile: ciphertext file to decrypt
    :param pk_file: ABE public key
    :param sk_file: ABE secret key
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging
    import os.path

    # Check if data is set
    if data is None:
        logging.error('re_decrypt data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_decrypt data')
        raise Exception

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.isfile(pk_file):
        logging.error('re_decrypt pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_decrypt pk_file')
        raise Exception

    # Check if sk_file is set and it exists
    if sk_file is None or not os.path.isfile(sk_file):
        logging.error('re_decrypt sk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_decrypt sk_file')
        raise Exception

    # Remove re-encryption
    return decrypt_re_encryption(re_enc_data=data, pk_file=pk_file, sk_file=sk_file, enc_params=enc_params, iv=iv, debug=debug)


def decrypt_re_encryption(re_enc_data=None, pk_file=None, sk_file=None, enc_params=None, iv=None, debug=0):
    """
    Remove the re-encryption from the ciphertext file.
    :param re_enc_file: encrypted file to decrypt the re-encryption
    :param pk_file: ABE public key to decrypt re-encryption parameters
    :param sk_file: ABE secret key to decrypt re-encryption parameters
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging
    import os.path

    # Check if re_enc_data is set
    if re_enc_data is None or not os.path.isfile(re_enc_data):
        logging.error('decrypt_re_encryption re_enc_data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_re_encryption re_enc_data')
        raise Exception

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.isfile(pk_file):
        logging.error('decrypt_re_encryption pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_re_encryption pk_file')
        raise Exception

    # Check if sk_file is set and it exists
    if sk_file is None or not os.path.isfile(sk_file):
        logging.error('decrypt_re_encryption sk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_re_encryption sk_file')
        raise Exception

    # Decrypt seed, key and re_enc_length with ABE using given public and secret keys
    seed, key, re_enc_length = decrypt_seed_key_len(enc_seed_key_len=enc_params, pk_file=pk_file, sk_file=sk_file,
                                                    debug=debug)

    # Remove re-encryption from the ciphertext
    return remove_re_enc(re_enc_data=re_enc_data, seed=seed, k=key, iv=iv, re_enc_length=re_enc_length, debug=debug)


def decrypt_seed_key_len(enc_seed_key_len=None, pk_file=None, sk_file=None, debug=0):
    """
    Decrypt encrypted seed, symmetric key and re-encryption length with ABE using the given public and secret key.
    :param enc_seed_key: encrypted seed, symmetric key and re-encryption length to decrypt
    :param pk_file: ABE public key
    :param sk_file: ABE secret key
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: decrypted seed, symmetric key and number of re-encryption length
    """

    import logging
    import os.path

    # Check if enc_seed_key is set
    if enc_seed_key_len is None:
        logging.error('decrypt_seed_key ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_seed_key ciphertext')
        raise Exception

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.isfile(pk_file):
        logging.error('[ERROR] decrypt_seed_key pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_seed_key pk_file')
        raise Exception

    # Check if sk_file is set and it exists
    if sk_file is None or not os.path.isfile(sk_file):
        logging.error('decrypt_seed_key sk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_seed_key sk_file')
        raise Exception

    # Decrypt data with ABE
    pairing_group = PairingGroup('MNT224')
    with open(pk_file, 'rb') as f:
        pk = bytesToObject(f.read(), pairing_group)
    with open(sk_file, 'rb') as f:
        sk = bytesToObject(f.read(), pairing_group)
    cpabe = AC17CPABE(pairing_group, 2)
    enc_data = cpabe.decrypt(pk, enc_seed_key_len, sk)

    from re_enc_engine.const import H, SYM_KEY_DEFAULT_SIZE, SEED_LENGTH
    import struct

    # Retrieve params from decryption output file
    seed, key, re_enc_length = struct.unpack('%ds%dsH' % (SEED_LENGTH, SYM_KEY_DEFAULT_SIZE), enc_data)

    if debug:  # ONLY USE FOR DEBUG
        print('DECRYPTED SEED = (%d) %s' % (len(seed), seed))
        print('DECRYPTED KEY = (%d) %s' % (len(key), key))
        print('DECRYPTED RE_ENC_LENGTH = %d' % re_enc_length)

    return seed, key, re_enc_length


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

    import logging

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

        from re_enc_engine.sym_enc_primitives import sym_decrypt

        # Decrypt re-encrypted transformed ciphertext
        re_dec_data = sym_decrypt(key=k, iv=iv, ciphertext=re_enc_data, debug=debug)

        if debug:  # ONLY USE FOR DEBUG
            logging.error()
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
            print('RE-ENCRYPTED BYTES TO DECRYPT = (%d) %s' % (len(bytes_to_re_enc), bytes_to_re_enc))
            print('RE-ENCRYPTED INDEXES TO DECRYPT = (%d) %s' % (len(re_enc_indexes), re_enc_indexes))

        from re_enc_engine.sym_enc_primitives import sym_decrypt

        # Decrypt re-encrypted transformed ciphertext bytes
        dec_ciphertext = sym_decrypt(key=k, iv=iv, ciphertext=bytes_to_re_enc, debug=debug)

        if debug:  # ONLY USE FOR DEBUG
            from binascii import hexlify
            print('DECRYPTED CIPHERTEXT = (%d) %s -> %s' % (len(dec_ciphertext), dec_ciphertext,
                                                            hexlify(dec_ciphertext).decode()))

        # Replace re-encrypted bytes in the file with decrypted ones
        re_dec_data = replace_re_enc_bytes(re_enc_data, dec_ciphertext, re_enc_indexes, debug)

    return re_dec_data


def sym_key_gen(pairing_group=None, sym_key_size=None, debug=0):
    """
        Generate a random symmetric key with given size.
        :param sym_key_size: length in bytes of the symmetric key
        :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
        :return: the randomly generated symmetric key
        """

    from const import SYM_KEY_MIN_SIZE, SYM_KEY_DEFAULT_SIZE
    from function_utils import clamp

    # If sym_key_size is not defined, set a default value
    if sym_key_size is None:
        sym_key_size = SYM_KEY_DEFAULT_SIZE

    import sys

    # Clamp the size between SYM_KEY_MIN_SIZE and the system maximum possible value
    size = clamp(sym_key_size, SYM_KEY_MIN_SIZE, sys.maxsize)

    # Check if an error occurred during clamping
    if size is None:
        logging.error('sym_key_gen clamp size exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_key_gen clamp size')
        raise Exception

    import math

    # Check if size is a power of 2
    if not math.log2(size).is_integer():
        logging.error('sym_key_gen size exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_key_gen size')
        raise Exception

    rand_pg_elem = random_pairing_group_elem_gen(pairing_group, debug)
    key = objectToBytes(rand_pg_elem, pairing_group)[: sym_key_size]

    # Generate and return a random symmetric key with the given size
    return key, rand_pg_elem


def random_string_gen(pairing_group=None, length=None, debug=0):
    """
            Generate a random symmetric key with given size.
            :param sym_key_size: length in bytes of the symmetric key
            :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
            :return: the randomly generated symmetric key
            """

    from const import SEED_LENGTH

    # If sym_key_size is not defined, set a default value
    if length is None:
        length = SEED_LENGTH

    rand_pg_elem = random_pairing_group_elem_gen(pairing_group, debug)
    rand_str = objectToBytes(rand_pg_elem, pairing_group)[: length]

    # Generate and return a random symmetric key with the given size
    return rand_str, rand_pg_elem


def random_pairing_group_elem_gen(pairing_group=None, debug=0):
    """
    Generate a random byte string with the given length.
    :param length: length in bytes of the string to generate
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the random bytes string
    """

    # Return a random string with the given length
    return pairing_group.random(GT)
