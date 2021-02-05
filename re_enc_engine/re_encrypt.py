"""
This file contains Hybrid Proxy Re-Encryption scheme primitives. These functions are the implementation of the ones
defined in the work of S. Myers and A. Shull, "Efficient Hybrid Proxy Re-Encryption for Practical Revocation and Key
Rotation" (https://eprint.iacr.org/2017/833.pdf). To perform this procedure, firstly, a punctured encryption is applied
to the ciphertext with a symmetric key. Then the symmetric key and the seed for the punctured encryption are encrypted
with an asymmetric encryption scheme (particularly, CP-ABE).
"""

from binascii import hexlify
from charm.core.engine.util import bytesToObject, objectToBytes
from Crypto.Cipher import AES

import abe_primitives as abe
import const as const
import function_utils as fu
import hashlib
import json
import logging
import os.path
import pairing_group_primitives as pg
import re_enc_primitives as re_enc
import sym_enc_primitives as sym
import sys


def update_re_enc_infos(metafile, re_enc_length, pk, policy, debug=0):
    """
    Update re-encryption infos contained in the metadata file adding parameters related to the latest re-encryption
    operation.
    :param metafile: metadata file where re-encryption parameters will be saved
    :param re_enc_length: number of bytes to re-encrypt
    :param pk: public key to encrypt re-encryption parameters
    :param policy: policy to apply to the encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: re-encryption parameters
    """

    # Read metadata and update with new re-encryption infos
    with open(metafile, 'r+') as f:
        metadata = json.load(f)

        # Retrieve re-encryption parameters
        chunk_size = metadata[const.CHUNK_SIZE]

        # Generate re-encryption parameters
        seed = None
        seed_pg_elem = None
        if re_enc_length < chunk_size:
            seed, seed_pg_elem = pg.random_string_gen(pairing_group, const.SEED_LENGTH)
        key, key_pg_elem = pg.sym_key_gen(pairing_group, const.SYM_KEY_DEFAULT_SIZE, debug)
        iv = sym.iv_gen(const.IV_DEFAULT_SIZE, debug)

        # Clamp the number of bytes to re-encrypt between RE_ENC_MIN_LENGTH and the chunk size
        re_enc_length = fu.clamp(re_enc_length, const.RE_ENC_MIN_LENGTH, chunk_size, debug)

        if debug:  # ONLY USE FOR DEBUG
            print('\nCHUNK SIZE = %d' % chunk_size)
            if seed:
                print('SEED = (%d) %s' % (len(seed), seed))
                print('SEED PG ELEM = (%s) %s' % (type(seed_pg_elem), seed_pg_elem))
            else:
                print('SEED =', seed)
                print('SEED PG ELEM =', seed_pg_elem)
            print('KEY = (%d) %s' % (len(key), key))
            print('KEY PG ELEM = (%s) %s' % (type(key_pg_elem), key_pg_elem))
            print('IV = (%d) %s' % (len(iv), iv))
            print('RE-ENC LEN =', re_enc_length)

        # Prepare re-encryption parameters to write on the metadata file
        enc_seed = objectToBytes(abe.encrypt(seed_pg_elem, pairing_group, bytesToObject(pk, pairing_group), policy,
                                             debug), pairing_group) if seed is not None else seed
        enc_key = objectToBytes(abe.encrypt(key_pg_elem, pairing_group, bytesToObject(pk, pairing_group), policy,
                                            debug), pairing_group)

        if debug:  # ONLY USE FOR DEBUG
            if enc_seed:
                print('ENC SEED = (%d) %s' % (len(enc_seed), enc_seed))
            else:
                print('ENC SEED =', enc_seed)
            print('ENC KEY = (%d) %s' % (len(enc_key), enc_key))

        # Add re-encryption informations to metadata file
        metadata['re_encs'].append({
            'pk': hashlib.sha256(pk).hexdigest(),  # SHA256 of public key as hex
            'policy': policy,
            'enc_seed': hexlify(enc_seed).decode() if enc_seed is not None else enc_seed,
            'enc_key': hexlify(enc_key).decode(),
            'iv': hexlify(iv).decode(),
            're_enc_length': re_enc_length
        })

        if debug:  # ONLY USE FOR DEBUG
            print('METADATA =', metadata)

        # Overwrite metadata file
        f.seek(0)
        json.dump(metadata, f)

    return seed, key, iv, chunk_size, re_enc_length


def re_enc_file(file, chunk_size, re_enc_length, seed, key, iv, debug=0):
    """
    Split the file in chunks and apply re-encryption to each of them using the given parameters.
    :param file: file to re-encrypt
    :param chunk_size: chunk size in bytes
    :param re_enc_length: number of bytes to re-encrypt
    :param seed: seed to randomly select bytes to re-encrypt
    :param key: symmetric key to encrypt randomly selected bytes
    :param iv: initialisation vector for the symmetric encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Read file in chunks and re-encrypt each of them with the given parameters
    with open(file, 'rb+') as f:

        # Compute cipher initial value (ONLY FOR CTR MODE)
        enc_block_size = sym.get_cipher(AES.MODE_CTR, None, None, key, iv).block_size
        init_val = 0

        for file_chunk in iter(lambda: f.read(chunk_size), ''):

            if debug:  # ONLY USE FOR DEBUG
                print('FILE CHUNK TO RE-ENC = (%s) (%d) %s' % (type(file_chunk), len(file_chunk), file_chunk))

            # EOF
            if not len(file_chunk):
                break

            # Re-encrypt file chunk
            re_enc_file_chunk = re_enc.re_encrypt(file_chunk, re_enc_length, seed, key, iv, init_val, debug)

            if debug:  # ONLY USE FOR DEBUG
                print('RE-ENCRYPTED FILE CHUNK = (%s) (%d) %s' % (type(re_enc_file_chunk), len(re_enc_file_chunk),
                                                                  re_enc_file_chunk))

            # Check re-encryption correctness
            if len(re_enc_file_chunk) != len(file_chunk):
                logging.error('Re-encrypted file chunk length does not match file chunk length')
                print('[ERROR] Re-encrypted file chunk length does not match file chunk length')
                raise Exception

            # Replace file chunk with re-encrypted one
            f.seek(-len(re_enc_file_chunk), os.SEEK_CUR)
            f.write(re_enc_file_chunk)

            # Update cipher initial value
            init_val = f.tell() // enc_block_size


def apply_re_encryption(enc_file=None, metadata_enc_file=None, re_enc_length=None, pk=None, policy=None, pairing_group=None, debug=0):
    """
    Apply re-encryption to the encrypted ciphertext.
    :param enc_file: encrypted file to re-encrypt
    :param metadata_enc_file: metadata file related to encrypted file
    :param re_enc_length: number of bytes to re-encrypt
    :param pk: ABE public key
    :param policy: ABE policy
    :param pairing_group: pairing group for parameters generation
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if enc_file is set and it exists
    if enc_file is None or not os.path.isfile(enc_file):
        logging.error('apply_re_encryption enc_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption enc_file')
        raise Exception

    # Check if metadata_enc_file is set and it exists
    if metadata_enc_file is None or not os.path.isfile(metadata_enc_file):
        logging.error('apply_re_encryption metadata_enc_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption metadata_enc_file')
        raise Exception

    # Check if re_enc_length is set
    if re_enc_length is None:
        logging.error('apply_re_encryption re_enc_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption re_enc_length')
        raise Exception

    # Check if pk_file is set
    if pk is None:
        logging.error('apply_re_encryption pk exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption pk')
        raise Exception

    # Check if policy is set
    if policy is None:
        logging.error('apply_re_encryption policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption policy')
        raise Exception

    # Update metadata file with latest re-encryption parameters
    seed, key, iv, chunk_size, re_enc_length = update_re_enc_infos(metadata_enc_file, re_enc_length, pk, policy, debug)

    # Re-encrypt the given ciphertext file
    re_enc_file(enc_file, chunk_size, re_enc_length, seed, key, iv, debug)


if __name__ == '__main__':

    if len(sys.argv) != 6:
        print("Syntax: " + sys.argv[0] + " [FILE TO RE-ENCRYPT] [METADATA FILE TO SAVE RE-ENCRYPTION INFOS] "
                                         "[RE-ENC LEN IN BYTES] [PUB KEY FILE] [POLICY]")

    script, file, metadata_file, re_enc_len, pub_key_file, pol = sys.argv

    with open(pub_key_file, 'r') as f:
        data = json.load(f)

    pub_key = bytes.fromhex(data[next(iter(data.keys()))]['pk'])
    pol = '(DEPT1 and TEAM1)'
    pairing_group = pg.pairing_group_create('MNT224')

    apply_re_encryption(file, metadata_file, int(re_enc_len), pub_key, pol, pairing_group, 1)
