# This file contains ABE scheme primitives. These functions simply wrap the command line ones provided by the libraries
# cpabe and libbswabe of John Bethencourt, Amit Sahai and Brent Waters. Full details about their libraries can be found
# at the following link http://acsc.cs.utexas.edu/cpabe/.

from crypto.Const import ABE_PK_FILE, ABE_MSK_FILE, ABE_SK_FILE
from Log import log

import os.path
import subprocess


# Generate system parameters, a public key and a master secret key.
# Params:
# - pk_outfile = file where public key will be saved
# - msk_outfile = file where master secret key will be saved
# - debug = if 1, prints will be shown during execution; default 0, no prints are shown
def setup(pk_outfile=None, msk_outfile=None, debug=0):

    # Create bash command to execute
    bash_command = 'cpabe-setup'
    if pk_outfile is not None:
        bash_command += ' -p ' + pk_outfile
    if msk_outfile is not None:
        bash_command += ' -m ' + msk_outfile
    log('Setup command = ' + bash_command)

    if debug:   # ONLY USE FOR DEBUG
        print('Setup command = ' + bash_command)

    # Execute command
    process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    output, error = process.communicate()
    log('Setup output = ' + str(output))
    log('Setup error = ' + str(error))

    if debug:   # ONLY USE FOR DEBUG
        print('Setup output = ' + str(output))
        print('Setup error = ' + str(error))


# Generate a key with the listed attributes using public key and master secret key. Output will be written to the file
# "priv_key" unless sk_outfile is set.
# Attributes can be non−numerical and numerical:
# - non−numerical attributes are simply any string of letters, digits, and underscores beginning with a letter;
# - numerical attributes are specified as ‘attr = N’, where N is a non−negative integer less than 2^64 and ‘attr’ is
#   another string. The whitespace around the ‘=’ is optional. One may specify an explicit length of k bits for the
#   integer by giving ‘attr = N#k’. Note that any comparisons in a policy given to cpabe−enc must then specify the same
#   number of bits, e.g., ‘attr > 5#12’.
# The keywords ‘and’, ‘or’, and ‘of’ are reserved for the policy language of cpabe−enc and may not be used for either
# type of attribute.
# Params:
# - sk_outfile = file where private key will be saved
# - pk_file = file where public key is stored
# - msk_file = file where master secret key is stored
# - attr_list = list of attributes related to the secret key that will be generated
# - debug = if 1, prints will be shown during execution; default 0, no prints are shown
def keygen(sk_outfile=None, pk_file=ABE_PK_FILE, msk_file=ABE_MSK_FILE, attr_list=None, debug=0):

    # Verify correctness of parameters
    if attr_list is None or not os.path.isfile(pk_file) or not os.path.isfile(msk_file):
        log('[ERROR] KeyGen exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in keygen')
        raise Exception

    # Create bash command to execute
    bash_command = 'cpabe-keygen'
    if sk_outfile is not None:
        bash_command += ' -o ' + sk_outfile
    bash_command += ' ' + pk_file + ' ' + msk_file
    for attr in attr_list:
        bash_command += ' ' + attr
    log('KeyGen command = ' + bash_command)

    if debug:   # ONLY USE FOR DEBUG
        print('KeyGen command = ' + bash_command)

    # Execute command
    process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    output, error = process.communicate()
    log('Setup output = ' + str(output))
    log('Setup error = ' + str(error))

    if debug:   # ONLY USE FOR DEBUG
        print('Setup output = ' + str(output))
        print('Setup error = ' + str(error))


# Encrypt a file under the decryption policy using public key. The encrypted file will be written to [FILENAME].cpabe
# unless enc_outfile is set. The original file will be removed. If policy is not specified, an exception is returned.
# Params:
# - enc_outfile = file where ciphertext will be saved
# - pk_file = file where public key is stored
# - plaintext_file = file to encrypt
# - policy = policy related to the file
# - debug = if 1, prints will be shown during execution; default 0, no prints are shown
def encrypt(enc_outfile=None, pk_file=ABE_PK_FILE, plaintext_file=None, policy=None, debug=0):

    # Verify correctness of parameters
    if plaintext_file is None or policy is None or not os.path.isfile(pk_file):
        log('[ERROR] Encrypt exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt')
        raise Exception

    # Create bash command to execute
    bash_command = 'cpabe-enc'

    if enc_outfile is not None:
        bash_command += ' -o ' + enc_outfile

    bash_command += ' ' + pk_file + ' ' + plaintext_file + ' ' + policy

    log('Encrypt command = ' + bash_command)
    if debug:   # ONLY USE FOR DEBUG
        print('Encrypt command = ' + bash_command)

    # Execute command
    process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    output, error = process.communicate()
    log('Encrypt output = ' + str(output))
    log('Encrypt error = ' + str(error))

    if debug:   # ONLY USE FOR DEBUG
        print('Encrypt output = ' + str(output))
        print('Encrypt error = ' + str(error))


# Decrypt ciphertext_file using private and public keys. If the name of ciphertext_file is X.cpabe, the decrypted file
# will be written as X and ciphertext_file will be removed; otherwise the file will be decrypted in place. Use of
# dec_outfile overrides this behavior.
# Params:
# - dec_outfile = file where decrypted ciphertext will be saved
# - pk_file = file where public key is stored
# - sk_file = file where private key is stored
# - ciphertext_file = file to decrypt
# - debug = if 1, prints will be shown during execution; default 0, no prints are shown
def decrypt(dec_outfile=None, pk_file=ABE_PK_FILE, sk_file=ABE_SK_FILE, ciphertext_file=None, debug=0):

    # Verify correctness of parameters
    if ciphertext_file is None or not os.path.isfile(pk_file) or not os.path.isfile(sk_file):
        log('[ERROR] Decrypt exception')
        if debug:   # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt')
        raise Exception

    # Create bash command to execute
    bash_command = 'cpabe-dec'
    if dec_outfile is not None:
        bash_command += ' -o ' + dec_outfile
    bash_command += ' ' + pk_file + ' ' + sk_file + ' ' + ciphertext_file
    log('Decrypt command = ' + bash_command)

    if debug:   # ONLY USE FOR DEBUG
        print('Decrypt command = ' + bash_command)

    # Execute command
    process = subprocess.Popen(bash_command, shell=True, stdout=subprocess.PIPE)
    output, error = process.communicate()
    log('Decrypt output = ' + str(output))
    log('Decrypt error = ' + str(error))

    if debug:   # ONLY USE FOR DEBUG
        print('Decrypt output = ' + str(output))
        print('Decrypt error = ' + str(error))
