"""
This file contains ABE scheme primitives. These functions simply wrap the command line ones provided by the libraries
cpabe and libbswabe of John Bethencourt, Amit Sahai and Brent Waters. Full details about their libraries can be found at
the following link http://acsc.cs.utexas.edu/cpabe/.
"""

from crypto.Const import ABE_PK_FILE, ABE_MSK_FILE, ABE_SK_FILE

import logging
import os.path
import subprocess


def setup(pk_outfile=None, msk_outfile=None, debug=0):
    """
    Generate ABE public and master secret key and store them in the given files.
    :param pk_outfile: file where public key will be saved
    :param msk_outfile: file where master secret key will be saved
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Create bash command to execute
    bash_command = 'cpabe-setup'

    if pk_outfile is not None:
        bash_command += ' -p ' + pk_outfile

    if msk_outfile is not None:
        bash_command += ' -m ' + msk_outfile

    logging.info('setup command = ' + bash_command)

    if debug:   # ONLY USE FOR DEBUG
        print('setup command = ' + bash_command)

    # Execute command
    process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    output, error = process.communicate()

    if debug:  # ONLY USE FOR DEBUG
        print('setup output = ' + str(output))
        print('setup error = ' + str(error))


def keygen(sk_outfile=None, pk_file=ABE_PK_FILE, msk_file=ABE_MSK_FILE, attr_list=None, debug=0):
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

    # Create bash command to execute
    bash_command = 'cpabe-keygen'

    if sk_outfile is not None:
        bash_command += ' -o ' + sk_outfile

    bash_command += ' ' + pk_file + ' ' + msk_file

    for attr in attr_list:
        bash_command += ' ' + attr

    logging.info('keygen command = ' + bash_command)

    if debug:  # ONLY USE FOR DEBUG
        print('keygen command = ' + bash_command)

    # Execute command
    process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    output, error = process.communicate()

    if debug:  # ONLY USE FOR DEBUG
        print('keygen output = ' + str(output))
        print('keygen error = ' + str(error))


def encrypt(enc_outfile=None, pk_file=ABE_PK_FILE, plaintext_file=None, policy=None, debug=0):
    """
    Encrypt a file under the decryption policy using public key. The encrypted file will be written to [FILENAME].cpabe
    unless enc_outfile is set. The original file will be removed.
    :param enc_outfile: file where ciphertext will be saved
    :param pk_file: file where public key is stored
    :param plaintext_file: file to encrypt
    :param policy: policy related to the file
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.isfile(pk_file):
        logging.error('encrypt pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt pk_file')
        raise Exception

    # Check if plaintext_file is set and it exists
    if plaintext_file is None or not os.path.isfile(plaintext_file):
        logging.error('encrypt plaintext_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt plaintext_file')
        raise Exception

    # Check if policy is set
    if policy is None:
        logging.error('encrypt policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt policy')
        raise Exception

    # Create bash command to execute
    bash_command = 'cpabe-enc'

    if enc_outfile is not None:
        bash_command += ' -o ' + enc_outfile

    bash_command += ' ' + pk_file + ' ' + plaintext_file + ' ' + policy

    logging.info('encrypt command = ' + bash_command)

    if debug:  # ONLY USE FOR DEBUG
        print('encrypt command = ' + bash_command)

    # Execute command
    process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    output, error = process.communicate()

    if debug:  # ONLY USE FOR DEBUG
        print('encrypt output = ' + str(output))
        print('encrypt error = ' + str(error))


def decrypt(dec_outfile=None, pk_file=ABE_PK_FILE, sk_file=ABE_SK_FILE, ciphertext_file=None, debug=0):
    """
    Decrypt ciphertext_file using secret and public keys. If the name of ciphertext_file is X.cpabe, the decrypted file
    will be written as X and ciphertext_file will be removed; otherwise the file will be decrypted in place. Use of
    dec_outfile overrides this behavior.
    :param dec_outfile: file where decrypted ciphertext will be saved
    :param pk_file: file where public key is stored
    :param sk_file: file where secret key is stored
    :param ciphertext_file: file to decrypt
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

    # Create bash command to execute
    bash_command = 'cpabe-dec'

    if dec_outfile is not None:
        bash_command += ' -o ' + dec_outfile

    bash_command += ' ' + pk_file + ' ' + sk_file + ' ' + ciphertext_file

    logging.info('decrypt command = ' + bash_command)

    if debug:  # ONLY USE FOR DEBUG
        print('decrypt command = ' + bash_command)

    # Execute command
    process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    output, error = process.communicate()

    if debug:  # ONLY USE FOR DEBUG
        print('decrypt output = ' + str(output))
        print('decrypt error = ' + str(error))
