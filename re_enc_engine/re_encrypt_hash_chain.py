"""
This file contains Hybrid Proxy Re-Encryption scheme primitives. These functions are the implementation of the ones
defined in the work of S. Myers and A. Shull, "Efficient Hybrid Proxy Re-Encryption for Practical Revocation and Key
Rotation" (https://eprint.iacr.org/2017/833.pdf). To perform this procedure, firstly, a punctured encryption is applied
to the ciphertext with a symmetric key. Then the symmetric key and the seed for the punctured encryption are encrypted
with an asymmetric encryption scheme (particularly, CP-ABE).
"""

from binascii import hexlify, unhexlify
from charm.core.engine.util import bytesToObject, objectToBytes
from charm.toolbox.pairinggroup import GT
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


def update_re_enc_info(metafile, re_enc_params, debug=0):
    """
    Update re-encryption info contained in the metadata file adding parameters related to the latest re-encryption
    operation.
    :param metafile: metadata file where re-encryption parameters will be saved
    :param re_enc_params: re-encryption parameters
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: re-encryption parameters
    """

    # Read metadata and update with new re-encryption info
    with open(metafile, 'r+') as f:
        metadata = json.load(f)

        # Retrieve re-encryption parameters
        chunk_size = metadata[const.CHUNK_SIZE]
        pairing_group = re_enc_params['pairing_group']
        pk = re_enc_params['pk']
        policy = re_enc_params['policy']
        re_enc_length = re_enc_params['re_enc_length']
        seed = re_enc_params['seed']
        key = re_enc_params['key']
        root_iv = re_enc_params['iv']
        re_encs_num = re_enc_params['re_encs_num']

        # Clamp the number of bytes to re-encrypt between RE_ENC_MIN_LENGTH and the chunk size
        re_enc_length = fu.clamp(re_enc_length, const.RE_ENC_MIN_LENGTH, chunk_size, debug)

        iv = fu.hash_chain(root_iv, re_encs_num)

        if debug:  # ONLY USE FOR DEBUG
            print('CHUNK SIZE = %d' % chunk_size)
            print('SEED = (%s) %s' % (type(seed), seed))
            print('KEY = (%s) %s' % (type(key), key))
            print('ROOT_IV = (%d) %s' % (len(root_iv), root_iv))
            print('IV = (%d) %s' % (len(iv), iv))
            print('RE-ENC LEN =', re_enc_length)
            print('RE-ENC NUM =', re_encs_num)

        # Prepare re-encryption parameters to write on the metadata file
        enc_seed = objectToBytes(abe.encrypt(seed, pairing_group, bytesToObject(pk, pairing_group), policy, debug),
                                 pairing_group)
        enc_key = objectToBytes(abe.encrypt(key, pairing_group, bytesToObject(pk, pairing_group), policy, debug),
                                pairing_group)

        if debug:  # ONLY USE FOR DEBUG
            print('ENC SEED = (%d) %s' % (len(enc_seed), enc_seed))
            print('ENC KEY = (%d) %s' % (len(enc_key), enc_key))

        # Create re-encryption information
        re_enc_info = {
            'pk': hashlib.sha256(pk).hexdigest(),  # SHA256 of public key as hex
            'policy': policy,
            'enc_seed': hexlify(enc_seed).decode(),
            'enc_key': hexlify(enc_key).decode(),
            'iv': hexlify(root_iv).decode(),
            're_enc_length': re_enc_length,
            're_encs_num': re_encs_num + 1
        }

        # Add re-encryption informations to metadata file
        if len(metadata['re_encs']) > 0:
            metadata['re_encs'][0] = re_enc_info
        else:
            metadata['re_encs'].append(re_enc_info)

        if debug:  # ONLY USE FOR DEBUG
            print('METADATA =', metadata)

        # Overwrite metadata file
        f.seek(0)
        json.dump(metadata, f)
        f.truncate()

    return objectToBytes(seed, pairing_group)[: const.SEED_LENGTH], \
           objectToBytes(key, pairing_group)[: const.SYM_KEY_DEFAULT_SIZE], iv, chunk_size, re_enc_length


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


def apply_re_encryption(enc_file=None, metadata_enc_file=None, re_enc_params=None, debug=0):
    """
    Apply re-encryption to the encrypted ciphertext.
    :param enc_file: encrypted file to re-encrypt
    :param metadata_enc_file: metadata file related to encrypted file
    :param re_enc_params: re-encryption parameters
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

    # Check if re_enc_params is set
    if re_enc_params is None:
        logging.error('apply_re_encryption re_enc_params exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption re_enc_params')
        raise Exception

    # Update metadata file with latest re-encryption parameters
    seed, key, iv, chunk_size, re_enc_length = update_re_enc_info(metadata_enc_file, re_enc_params, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('SEED = (%d) %s' % (len(seed), seed))
        print('KEY = (%d) %s' % (len(key), key))
        print('IV = (%d) %s' % (len(iv), iv))

    # Re-encrypt the given ciphertext file
    re_enc_file(enc_file, chunk_size, re_enc_length, seed, key, iv, debug)


if __name__ == '__main__':

    if len(sys.argv) != 6:
        print('Syntax:', sys.argv[0], '[FILE TO RE-ENCRYPT] [METADATA FILE TO SAVE RE-ENCRYPTION INFOS] '
                                      '[RE-ENC LEN IN BYTES] [PUB KEY FILE] [POLICY]')

    script, file, metadata_file, re_enc_len, pub_key_file, pol = sys.argv
    debugging = 1

    with open(pub_key_file, 'r') as f:
        data = json.load(f)
        pub_key = bytes.fromhex(data[next(iter(data.keys()))]['pk'])

    with open(metadata_file, 'r') as f:
        data = json.load(f)
        re_encs_field = data['re_encs']
        re_enc_num = 0
        r_iv = sym.iv_gen(const.IV_DEFAULT_SIZE, debugging)
        if len(re_encs_field) > 0:
            re_enc_op = re_encs_field[0]
            r_iv = unhexlify(re_enc_op['iv'])
            re_enc_num = re_enc_op['re_encs_num']

    pol = '(DEPT1 and TEAM1)'
    pair_group = pg.pairing_group_create('MNT224')
    last_seed = pg.random_pairing_group_elem_gen(pair_group, GT)
    last_key = pg.random_pairing_group_elem_gen(pair_group, GT)
    max_re_enc_num = 100

    initial_re_encs = 1
    for i in range(initial_re_encs):
        print('\nHASH CHAIN HOPS =', i, '\t REV HASH CHAIN HOPS =', max_re_enc_num - i)
        re_enc_args = {
            'pairing_group': pair_group,
            'pk': pub_key,
            'policy': pol,
            're_enc_length': int(re_enc_len),
            'seed': pg.hash_chain(pair_group, last_seed, max_re_enc_num - i),
            'key': pg.hash_chain(pair_group, last_key, max_re_enc_num - i),
            'iv': r_iv,
            're_encs_num': i
        }

        apply_re_encryption(file, metadata_file, re_enc_args, debugging)
