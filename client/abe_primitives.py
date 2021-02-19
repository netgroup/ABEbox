"""
This file contains CP-ABE scheme primitives. These functions simply wrap the command line ones provided by the libraries
cpabe and libbswabe of John Bethencourt, Amit Sahai and Brent Waters. Full details about their libraries can be found at
the following link http://acsc.cs.utexas.edu/cpabe/.
"""

from charm.core.engine.util import objectToBytes, bytesToObject
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup

import const
import logging
import os.path

from time import time


def setup(pk_outfile=const.ABE_PK_FILE, msk_outfile=const.ABE_MSK_FILE, pairing_group_curve=const.PAIRING_GROUP_CURVE,
          debug=0):
    """
    Generate CP-ABE public and master secret key and store them in the given files.
    :param pk_outfile: file where public key will be saved
    :param msk_outfile: file where master secret key will be saved
    :param pairing_group_curve: string representing curve to use for the pairing group
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Instantiate a bilinear pairing map with the given curve
    pairing_group = PairingGroup(pairing_group_curve)

    # CP-ABE
    cpabe = CPabe_BSW07(pairing_group)

    # Create public and master secret keys
    (pk, msk) = cpabe.setup()

    if debug:  # ONLY USE FOR DEBUG
        print('CP-ABE PUBLIC KEY =', pk)
        print('CP-ABE MASTER SECRET KEY =', msk)

    # Save keys on given output files
    with open(pk_outfile, 'w') as fout:
        fout.write(objectToBytes(pk, pairing_group).hex())

    with open(msk_outfile, 'w') as fout:
        fout.write(objectToBytes(msk, pairing_group).hex())


def keygen(sk_outfile=None, pk_file=const.ABE_PK_FILE, msk_file=const.ABE_MSK_FILE,
           pairing_group_curve=const.PAIRING_GROUP_CURVE, attr_list=None, debug=0):
    """ TODO update documentation
    Generate a secret key with the listed attributes using public key and master secret key. Output will be written to
    the file "priv_key" unless sk_outfile is set. Attributes can be non−numerical and numerical:
    - non−numerical attributes are simply any string of letters, digits, and underscores beginning with a letter;
    - numerical attributes are specified as ‘attr = N’, where N is a non−negative integer less than 2^64 and ‘attr’ is
      another string. The whitespace around the ‘=’ is optional. One may specify an explicit length of k bits for the
      integer by giving ‘attr = N#k’. Note that any comparisons in a policy given to cpabe−enc must then specify the
      same number of bits, e.g., ‘attr > 5#12’.
    The keywords ‘and’, ‘or’, and ‘of’ are reserved for the policy language of cpabe−enc and may not be used for either
    type of attribute.
    :param sk_outfile: file where private key will be saved
    :param pk_file: file where public key is stored
    :param msk_file: file where master secret key is stored
    :param pairing_group_curve: string representing curve to use for the pairing group
    :param attr_list: list of attributes related to the secret key that will be generated
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.isfile(pk_file):
        logging.error('keygen pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in keygen pk_file')
        raise Exception

    # Check if msk_file is set and it exists
    if msk_file is None or not os.path.isfile(msk_file):
        logging.error('keygen msk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in keygen msk_file')
        raise Exception

    # Check if attr_list is set
    if attr_list is None:
        logging.error('keygen attr_list exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in keygen attr_list')
        raise Exception

    # Instantiate a bilinear pairing map with the given curve
    pairing_group = PairingGroup(pairing_group_curve)

    # CP-ABE under DLIN (2-linear)
    cpabe = CPabe_BSW07(pairing_group)

    # Read public and master secret keys from specified files
    with open(pk_file, 'r') as fin:
        pk = bytesToObject(bytes.fromhex(fin.read()), pairing_group)

    with open(msk_file, 'r') as fin:
        msk = bytesToObject(bytes.fromhex(fin.read()), pairing_group)

    if debug:  # ONLY USE FOR DEBUG
        print('PK =', pk)
        print('MSK =', msk)
        print('Attr list =', attr_list)

    # Generate the secret key related to the given public and master secret keys and attributes list
    sk = cpabe.keygen(pk, msk, attr_list)

    if debug:  # ONLY USE FOR DEBUG
        print('SK =', sk)
        print('SK BYTES =', objectToBytes(sk, pairing_group))

    # Save secret key on specified output file
    with open(sk_outfile, 'w') as fout:
        fout.write(objectToBytes(sk, pairing_group).hex())


def encrypt(data=None, pairing_group=None, pk=None, policy=None, debug=0):
    """
    Encrypt data using ABE scheme with the given public key and policy
    :param data: the content to encrypt
    :param pairing_group: pairing group to use
    :param pk: public key to use for encryption
    :param policy: policy to apply during encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: encrypted data
    """
    starting_time = time() * 1000.0

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

    if debug:  # ONLY USE FOR DEBUG
        print('DATA = (%s) %s' % (type(data), data))
        print('PK = (%s) %s' % (type(pk), pk))
        print('POLICY = (%s) %s' % (type(policy), policy))

    elapsed_time = (time() * 1000.0) - starting_time
    print('[{}] before CPabe_BSW07'.format(elapsed_time))
    # Encrypt data with CP-ABE
    cpabe = CPabe_BSW07(pairing_group)

    elapsed_time = (time() * 1000.0) - starting_time
    print('[{}] after Pabe_BSW07'.format(elapsed_time))

    enc_data = cpabe.encrypt(pk, data, policy)

    elapsed_time = (time() * 1000.0) - starting_time
    print('[{}] after cpabe.encrypt'.format(elapsed_time))

    if debug:  # ONLY USE FOR DEBUG
        print('ENC DATA WITH POLICY = %s' % enc_data)

    # Remove policy from encrypted data
    enc_data.pop('policy')

    if debug:  # ONLY USE FOR DEBUG
        print('ENCRYPTED DATA = %s' % enc_data)

    #elapsed_time = (time() * 1000.0) - starting_time
    #print('[{}] end of abe.encrypt'.format(elapsed_time))

    return enc_data


def decrypt(enc_data=None, pk=None, sk=None, pairing_group=None, debug=0):
    """
    Decrypt encrypted data with CP-ABE using the given public and secret key.
    :param enc_data: encrypted data to decrypt
    :param pk: CP-ABE public key
    :param sk: CP-ABE secret key
    :param pairing_group: pairing group to use
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: decrypted data
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

    # Decrypt data with CP-ABE and return the result
    cpabe = CPabe_BSW07(pairing_group)

    # print('############################### ABE.DECRYPT')
    # import traceback
    # traceback.print_stack()
    return cpabe.decrypt(pk, sk, enc_data)
