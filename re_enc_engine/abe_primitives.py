"""
This file contains CP-ABE scheme primitives. These functions simply wrap the command line ones provided by the libraries
cpabe and libbswabe of John Bethencourt, Amit Sahai and Brent Waters. Full details about their libraries can be found at
the following link http://acsc.cs.utexas.edu/cpabe/.
"""

from ABE.ac17 import AC17CPABE
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as rpg
from charm.toolbox.pairinggroup import PairingGroup, GT

from re_enc_engine.const import POLICY
from re_enc_engine.const import ABE_PK_FILE, ABE_MSK_FILE, ABE_SK_FILE, PAIRING_GROUP_CURVE

import logging
import os.path
import subprocess


def setup(pk_outfile=ABE_PK_FILE, msk_outfile=ABE_MSK_FILE, pairing_group_curve=PAIRING_GROUP_CURVE, debug=0):
    """
    Generate CP-ABE public and master secret key and store them in the given files.
    :param pk_outfile: file where public key will be saved
    :param msk_outfile: file where master secret key will be saved
    :param pairing_group_curve: string representing curve to use for the pairing group
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # # Create bash command to execute
    # bash_command = 'cpabe-setup'
    #
    # if pk_outfile is not None:
    #     bash_command += ' -p ' + pk_outfile
    #
    # if msk_outfile is not None:
    #     bash_command += ' -m ' + msk_outfile
    #
    # logging.info('setup command = ' + bash_command)
    #
    # if debug:   # ONLY USE FOR DEBUG
    #     print('setup command = ' + bash_command)
    #
    # # Execute command
    # process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    # output, error = process.communicate()
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('setup output = ' + str(output))
    #     print('setup error = ' + str(error))

    # Instantiate a bilinear pairing map with the given curve
    pairing_group = PairingGroup(pairing_group_curve)

    # CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

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


def keygen(sk_outfile=None, pk_file=ABE_PK_FILE, msk_file=ABE_MSK_FILE, pairing_group_curve=PAIRING_GROUP_CURVE,
           attr_list=None, debug=0):
    # TODO Correct documentation
    """
    Generate a key with the listed attributes using public key and master secret key. Output will be written to the file
    "priv_key" unless sk_outfile is set. Attributes can be non−numerical and numerical:
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

    # # Create bash command to execute
    # bash_command = 'cpabe-keygen'
    #
    # if sk_outfile is not None:
    #     bash_command += ' -o ' + sk_outfile
    #
    # bash_command += ' ' + pk_file + ' ' + msk_file
    #
    # for attr in attr_list:
    #     bash_command += ' ' + attr
    #
    # logging.info('keygen command = ' + bash_command)
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('keygen command = ' + bash_command)
    #
    # # Execute command
    # process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    # output, error = process.communicate()
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('keygen output = ' + str(output))
    #     print('keygen error = ' + str(error))

    # Instantiate a bilinear pairing map with the given curve
    pairing_group = PairingGroup(pairing_group_curve)

    # CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # Read public and master secret keys from specified files
    with open(pk_file, 'r') as fin:
        pk = bytesToObject(bytes.fromhex(fin.read()), pairing_group)

    with open(msk_file, 'r') as fin:
        msk = bytesToObject(bytes.fromhex(fin.read()), pairing_group)

    print('PK =', pk)
    print('MSK =', msk)
    print('Attr list =', attr_list)

    # Generate the secret key related to the given public and master secret keys and attributes list
    sk = cpabe.keygen(pk, msk, attr_list)

    print('SK =', sk)
    print('SK BYTES =', objectToBytes(sk, pairing_group))

    # Save secret key on specified output file
    with open(sk_outfile, 'w') as fout:
        fout.write(objectToBytes(sk, pairing_group).hex())


def encrypt(enc_outfile=None, pk_file=ABE_PK_FILE, plaintext_file=None, plaintext=None, policy=None,
            pairing_group_curve=PAIRING_GROUP_CURVE, debug=0):
    # TODO Correct documentation
    """
    Encrypt a file under the decryption policy using public key. The encrypted file will be written to [FILENAME].cpabe
    unless enc_outfile is set. The original file will be removed.
    :param enc_outfile: file where ciphertext will be saved
    :param pk_file: file where public key is stored
    :param plaintext_file: file to encrypt
    :param policy: policy related to the file
    :param pairing_group_curve: string representing curve to use for the pairing group
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.isfile(pk_file):
        logging.error('encrypt pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt pk_file')
        raise Exception

    # Check if plaintext_file is set and it exists
    # if plaintext_file is None or not os.path.isfile(plaintext_file):
    #     logging.error('encrypt plaintext_file exception')
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('EXCEPTION in encrypt plaintext_file')
    #     raise Exception

    # Check if policy is set
    if policy is None:
        logging.error('encrypt policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt policy')
        raise Exception

    # # Create bash command to execute
    # bash_command = 'cpabe-enc'
    #
    # if enc_outfile is not None:
    #     bash_command += ' -o ' + enc_outfile
    #
    # bash_command += ' ' + pk_file + ' ' + plaintext_file + ' ' + policy
    #
    # logging.info('encrypt command = ' + bash_command)
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('encrypt command = ' + bash_command)
    #
    # # Execute command
    # process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    # output, error = process.communicate()
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('encrypt output = ' + str(output))
    #     print('encrypt error = ' + str(error))

    # Instantiate a bilinear pairing map with the given curve
    pairing_group = PairingGroup(pairing_group_curve)
    print('PAIRING GROUP =', pairing_group)

    # CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # Read public key from specified file
    with open(pk_file, 'r') as fin:
        pk_hex = fin.read()
        pk = bytesToObject(bytes.fromhex(pk_hex), pairing_group)

    # Read plaintext from specified file
    # with open(plaintext_file, 'r') as fin:
    #     data = fin.read()
    #     print('READ SYM KEY BYTES = (%d) %s' % (len(bytes.fromhex(data)), bytes.fromhex(data)))
    #     plaintext = bytesToObject(bytes.fromhex(data), pairing_group)

    print('PLAINTEXT TO ENC =', plaintext)

    # plaintext = bytesToObject(bytes.fromhex(plaintext), pairing_group)

    # print('PLAINTEXT TO ENC =', plaintext)

    # Encrypt the plaintext with given public key and policy
    ciphertext = cpabe.encrypt(pk, plaintext, policy)

    print('CP-ABE CIPHERTEXT =', ciphertext)

    ciphertext.pop(POLICY)

    print('CP-ABE CIPHERTEXT BYTES =', objectToBytes(ciphertext, pairing_group).hex())

    # Save ciphertext on specified output file
    with open(enc_outfile, 'w') as fout:
        fout.write(objectToBytes(ciphertext, pairing_group).hex())


def decrypt(dec_outfile=None, pk_file=ABE_PK_FILE, sk_file=ABE_SK_FILE, ciphertext_file=None,
            pairing_group_curve=PAIRING_GROUP_CURVE, debug=0):
    # TODO Correct documentation
    """
    Decrypt ciphertext_file using secret and public keys. If the name of ciphertext_file is X.cpabe, the decrypted file
    will be written as X and ciphertext_file will be removed; otherwise the file will be decrypted in place. Use of
    dec_outfile overrides this behavior.
    :param dec_outfile: file where decrypted ciphertext will be saved
    :param pk_file: file where public key is stored
    :param sk_file: file where secret key is stored
    :param ciphertext_file: file to decrypt
    :param pairing_group_curve: string representing curve to use for the pairing group
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.isfile(pk_file):
        logging.error('decrypt pk_file exception')
        if debug:   # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt pk_file')
        raise Exception

    # Check if sk_file is set and it exists
    if sk_file is None or not os.path.isfile(sk_file):
        logging.error('decrypt sk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt sk_file')
        raise Exception

    # Check if ciphertext_file is set and it exists
    if ciphertext_file is None or not os.path.isfile(ciphertext_file):
        logging.error('decrypt ciphertext_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt ciphertext_file')
        raise Exception

    # # Create bash command to execute
    # bash_command = 'cpabe-dec'
    #
    # if dec_outfile is not None:
    #     bash_command += ' -o ' + dec_outfile
    #
    # bash_command += ' ' + pk_file + ' ' + sk_file + ' ' + ciphertext_file
    #
    # logging.info('decrypt command = ' + bash_command)
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('decrypt command = ' + bash_command)
    #
    # # Execute command
    # process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    # output, error = process.communicate()
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('decrypt output = ' + str(output))
    #     print('decrypt error = ' + str(error))

    # Instantiate a bilinear pairing map with the given curve
    pairing_group = PairingGroup(pairing_group_curve)

    # CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # Read public and secret key from specified files
    with open(pk_file, 'r') as fin:
        pk = bytesToObject(bytes.fromhex(fin.read()), pairing_group)

    with open(sk_file, 'r') as fin:
        sk = bytesToObject(bytes.fromhex(fin.read()), pairing_group)

    # Read ciphertext from specified file
    with open(ciphertext_file, 'r') as fin:
        ciphertext = bytesToObject(bytes.fromhex(fin.read()), pairing_group)

    # Decrypt the ciphertext
    plaintext = cpabe.decrypt(pk, ciphertext, sk)

    print('CP-ABE PLAINTEXT =', plaintext)

    # Save plaintext on the specified output file
    with open(dec_outfile, 'w') as fout:
        fout.write(plaintext)


def get_random_group_point(pairing_group_curve=PAIRING_GROUP_CURVE, debug=0):
    """
    Extract a random point from the pairing group related to the given curve.
    :param pairing_group_curve: string representing curve to use for the pairing group
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the SHA1 representation of a random group point
    """

    # Instantiate a bilinear pairing map with the given curve
    pairing_group = PairingGroup(pairing_group_curve)
    print('PAIRING GROUP =', pairing_group)

    # Get a random group point in GT
    point = pairing_group.random(GT)

    if debug:  # ONLY USE FOR DEBUG
        print('GROUP POINT =', point)

    #return objectToBytes(point, pairing_group).hex()
    return point
