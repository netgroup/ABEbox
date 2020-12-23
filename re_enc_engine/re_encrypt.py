"""
This file contains all functions used during re-encryption process. To perform this procedure, firstly, a punctured
encryption is applied to the ciphertext with a symmetric key. Then the symmetric key is encrypted with an asymmetric
encryption scheme (particularly, ABE).
"""

from binascii import hexlify
from charm.core.engine.util import bytesToObject, objectToBytes
from charm.toolbox.pairinggroup import PairingGroup
from re_enc_engine.re_enc_primitives2 import re_encrypt

import hashlib
import json
import logging
import os.path
import re_enc_engine.const as const
import sys


def apply_re_encryption(enc_file=None, metadata_enc_file=None, re_enc_length=None, pk=None, policy=None, debug=0):
    """
    Apply re-encryption to the encrypted ciphertext.
    :param enc_file: encrypted file to re-encrypt
    :param metadata_enc_file: metadata file related to encrypted file
    :param re_enc_length: number of bytes to re-encrypt
    :param pk_file: ABE public key
    :param policy: ABE policy
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

    # Read metadata
    with open(metadata_enc_file, 'r+') as f:

        metadata = json.load(f)

        # Retrieve re-encryption parameters
        chunk_size = metadata[const.CHUNK_SIZE]

        # Re-encrypt the given ciphertext file
        enc_params, iv = re_encrypt(enc_file, chunk_size, re_enc_length, bytesToObject(pk, PairingGroup('MNT224')), policy, debug)

        # Add re-encryption informations to metadata file
        metadata['re_encs'].append({
            'pk': hashlib.sha256(pk).hexdigest(),  # SHA256 of public key as hex
            'enc_params': hexlify(objectToBytes(enc_params, PairingGroup('MNT224'))),
            'iv': hexlify(iv)
        })

        print('METADATA =', metadata)

        f.seek(0)
        json.dump(metadata, f)


if __name__ == '__main__':

    script, file, metadata_file, re_enc_len, pub_key_file, pol = sys.argv

    with open(pub_key_file, 'r') as f:
        data = json.load(f)

    pub_key = bytes.fromhex(data[next(iter(data.keys()))]['pk'])
    pol = '(DEPT1 and TEAM1)'
    print('POLICY =', pol)

    apply_re_encryption(file, metadata_file, int(re_enc_len), pub_key, pol, 1)

