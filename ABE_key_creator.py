from crypto.ABEPrimitives import setup, keygen
from crypto.Const import KEY_PATH
import logging


def key_setup(pk_file=KEY_PATH + 'pub_key', msk_file=KEY_PATH + 'master_key', debug=0):

    setup(pk_outfile=pk_file, msk_outfile=msk_file, debug=debug)

    if debug:  # ONLY USE FOR DEBUG

        from binascii import hexlify

        pk = open(pk_file, 'rb').read()

        print('PUB KEY = (%d) %s -> %s' % (len(pk), pk, hexlify(pk)))

        msk = open(msk_file, 'rb').read()

        print('MASTER SECRET KEY = (%d) %s -> %s' % (len(msk), msk, hexlify(msk)))


def secret_key_gen(sk_file=KEY_PATH + 'secret_key', pk_file=KEY_PATH + 'public_key',
                   msk_file=KEY_PATH + 'master_key', attr_list=None, debug=0):

    keygen(sk_outfile=sk_file, pk_file=pk_file, msk_file=msk_file, attr_list=attr_list, debug=debug)

    if debug:  # ONLY USE FOR DEBUG

        from binascii import hexlify

        sk = open(sk_file, 'rb').read()
        print('SECRET KEY = (%d) %s -> %s' % (len(sk), sk, hexlify(sk)))