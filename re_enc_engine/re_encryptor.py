"""
This file contains all functions used during re-encryption process. To perform this procedure, firstly, a punctured
encryption is applied to the ciphertext with a symmetric key. Then the symmetric key is encrypted with an asymmetric
encryption scheme (particularly, ABE).
"""


def apply_re_encryption(enc_file=None, re_enc_length=None, pk_file=None, policy=None, debug=0):
    """
    Apply re-encryption to the encrypted ciphertext.
    :param enc_file: encrypted file to re-encrypt
    :param re_enc_length: number of bytes to re-encrypt
    :param pk_file: ABE public key
    :param policy: ABE policy
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging
    import os.path

    # Check if enc_file is set and it exists
    if enc_file is None or not os.path.exists(enc_file):
        logging.error('apply_re_encryption enc_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption enc_file')
        raise Exception

    # Check if re_enc_length is set
    if re_enc_length is None:
        logging.error('apply_re_encryption re_enc_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption re_enc_length')
        raise Exception

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.exists(pk_file):
        logging.error('apply_re_encryption pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption pk_file')
        raise Exception

    # Check if policy is set
    if policy is None:
        logging.error('apply_re_encryption policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption policy')
        raise Exception

    from old.re_enc_primitives import re_encrypt

    # Re-encrypt the given ciphertext file
    re_encrypt(enc_file, re_enc_length, pk_file, policy, debug)
