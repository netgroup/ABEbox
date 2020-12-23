"""
This file contains all the functions used to create ABE keys.
"""

from re_enc_engine.abe_primitives import setup, keygen
from old.crypto.Const import KEY_PATH, ABE_PK_FILE, ABE_MSK_FILE, ABE_SK_FILE
import logging


def key_setup(pk_file=KEY_PATH + ABE_PK_FILE, msk_file=KEY_PATH + ABE_MSK_FILE, debug=0):
    """
    Generate ABE public and master secret keys.
    :param pk_file: file where public key will be saved
    :param msk_file: file where master secret key will be saved
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Create ABE public and master secret keys and save them in the given output files
    setup(pk_outfile=pk_file, msk_outfile=msk_file, debug=debug)

    # if debug:  # ONLY USE FOR DEBUG
    #     from binascii import hexlify
    #     pk = open(pk_file, 'rb').read()
    #     print('PUB KEY = (%d) %s -> %s' % (len(pk), pk, hexlify(pk)))
    #     msk = open(msk_file, 'rb').read()
    #     print('MASTER SECRET KEY = (%d) %s -> %s' % (len(msk), msk, hexlify(msk)))


def secret_key_gen(sk_file=KEY_PATH + ABE_SK_FILE, pk_file=KEY_PATH + ABE_PK_FILE, msk_file=KEY_PATH + ABE_MSK_FILE,
                   attr_list=None, debug=0):
    """
    Generate a secret key based on the given public and master secret keys and the related attributes list.
    :param sk_file: file where secret key will be saved
    :param pk_file: file where public key is stored
    :param msk_file: file where master secret key is stored
    :param attr_list: list of attributes related to the secret key that will be generated
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Create the secret key based on the given public and master secret keys and the related attributes list and save it
    # in the given output file
    keygen(sk_outfile=sk_file, pk_file=pk_file, msk_file=msk_file, attr_list=attr_list, debug=debug)

    # if debug:  # ONLY USE FOR DEBUG
    #     from binascii import hexlify
    #     sk = open(sk_file, 'rb').read()
    #     print('SECRET KEY = (%d) %s -> %s' % (len(sk), sk, hexlify(sk)))
