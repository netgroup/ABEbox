"""
This file contains all functions used during encryption process. To perform this procedure, firstly, an hybrid
encryption is applied to the plaintext. Then the resulting ciphertext needs to be transformed through an All-Or-Nothing
transformation.
"""

from old.crypto.Const import AONT_DEFAULT_ENCODING, AONT_DEFAULT_N, AONT_DEFAULT_K0, CHUNK_SIZE


def create_encrypted_file(plaintext_infile=None, ciphertext_outfile=None, pk_file=None, policy=None, n=AONT_DEFAULT_N,
                          k0=AONT_DEFAULT_K0, encoding=AONT_DEFAULT_ENCODING, chunk_size=CHUNK_SIZE, debug=0):
    """
    Create the encrypted file starting from a plaintext input file and applying hybrid encryption and transformation.
    :param plaintext_infile: file to encrypt
    :param ciphertext_outfile: file where transformed ciphertext will be saved
    :param pk_file: ABE public key file used for hybrid encryption
    :param policy: ABE policy to apply to the ciphertext
    :param n: transformation chunk length in bits
    :param k0: transformation random length in bits
    :param encoding: transformation encoding used
    :param chunk_size: size of each plaintext chunk to encrypt and transform
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    from old.crypto.SymEncPrimitives import sym_key_gen
    from old.crypto.Const import SYM_KEY_DEFAULT_SIZE, VERSION
    from binascii import hexlify
    import logging
    import os

    # Check if plaintext_infile is set and it exists
    if plaintext_infile is None or not os.path.exists(plaintext_infile):
        logging.error('create_encrypted_file plaintext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in create_encrypted_file plaintext_infile')
        raise Exception

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.exists(pk_file):
        logging.error('create_encrypted_file pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in create_encrypted_file pk_file')
        raise Exception

    # Check if policy is set
    if policy is None:
        logging.error('create_encrypted_file policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in create_encrypted_file policy')
        raise Exception

    # Create the key for symmetric encryption of the plaintext
    sym_key = sym_key_gen(sym_key_size=SYM_KEY_DEFAULT_SIZE, debug=debug)

    if debug:  # ONLY USE FOR DEBUG
        print('[ENCRYPTOR] SYM KEY =', sym_key)

    from old.crypto.SymEncPrimitives import generate_iv
    from old.crypto.Const import IV_DEFAULT_SIZE

    # Create the initialisation vector for symmetric encryption
    iv = generate_iv(IV_DEFAULT_SIZE, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('[ENCRYPTOR]\tIV = (%d) %s -> %s' % (len(iv), iv, hexlify(iv).decode()))

    # Encrypt symmetric key with ABE using given public key and policy
    enc_key = encrypt_sym_key(sym_key, pk_file, policy, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('ENCRYPTED SYMMETRIC KEY =', enc_key)

    # If output file is not defined, set a default one
    if ciphertext_outfile is None:
        ciphertext_outfile = 'enc_' + plaintext_infile

    # Protection scheme version
    version = VERSION

    # Put together all header data to write
    header = [version, n, k0, len(enc_key), enc_key, iv, os.path.getsize(plaintext_infile)]

    # Write header on the output file
    write_header_on_file(ciphertext_outfile, header, debug)

    # Apply encryption, transform ciphertext and write result on the output file
    apply_enc_aont(plaintext_infile, ciphertext_outfile, sym_key, iv, n, encoding, k0, chunk_size, debug)


def apply_enc_aont(plaintext_infile=None, ciphertext_outfile=None, key=None, iv=None, n=AONT_DEFAULT_N,
                   encoding=AONT_DEFAULT_ENCODING, k0=AONT_DEFAULT_K0, chunk_size=CHUNK_SIZE, debug=0):
    """
    Apply hybrid encryption and All-Or-Nothing Transformation to the plaintext input file.
    :param plaintext_infile: file with the plaintext to encrypt and transform
    :param ciphertext_outfile: file where transformed ciphertext will be saved
    :param key: symmetric encryption key
    :param iv: symmetric encryption initialisation vector
    :param n: transformation chunk length in bits
    :param encoding: transformation encoding
    :param k0: transformation random length in bits
    :param chunk_size: size of each plaintext chunk to encrypt and transform
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging
    import os

    # Check if plaintext_infile is set and it exists
    if plaintext_infile is None or not os.path.exists(plaintext_infile):
        logging.error('apply_enc_aont plaintext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_enc_aont plaintext_infile')
        raise Exception

    # Check if ciphertext_outfile is set and it exists
    if ciphertext_outfile is None or not os.path.exists(ciphertext_outfile):
        logging.error('apply_enc_aont ciphertext_outfile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_enc_aont ciphertext_outfile')
        raise Exception

    # Check if key is set
    if key is None:
        logging.error('apply_enc_aont key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_enc_aont key')
        raise Exception

    # Check if iv is set
    if iv is None:
        logging.error('apply_enc_aont IV exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_enc_aont IV')
        raise Exception

    from old.crypto.SymEncPrimitives import sym_encrypt
    from binascii import hexlify

    # Read data chunk from the plaintext input file
    with(open(plaintext_infile, 'rb')) as fin:

        # Encrypt and transform chunks until all plaintext is encrypted and transformed
        for plaintext_chunk in iter(lambda: fin.read(chunk_size), ''):

            # Last read is empty, so processing will be skipped
            if not len(plaintext_chunk):
                return

            if debug:  # ONLY USE FOR DEBUG
                print('[ENCRYPTOR] PLAINTEXT CHUNK = (%d) %s -> %s' % (len(plaintext_chunk), plaintext_chunk,
                                                                       hexlify(plaintext_chunk)))

            # Encrypt the plaintext chunk using AES GCM with the given key
            ciphertext_chunk = sym_encrypt(key=key, iv=iv, plaintext=plaintext_chunk, debug=debug)

            if debug:  # ONLY USE FOR DEBUG
                print('[ENCRYPTOR] CIPHERTEXT CHUNK = (%d) %s -> %s' % (len(ciphertext_chunk), ciphertext_chunk,
                                                                        hexlify(ciphertext_chunk).decode()))

            # Apply All-Or-Nothing Transformation to the ciphertext chunk
            transf_ciphertext_chunk = apply_aont(ciphertext_chunk, n, encoding, k0, debug)

            if debug:  # ONLY USE FOR DEBUG
                print('[ENCRYPTOR] TRANSFORMED CIPHERTEXT CHUNK = (%d) %s -> %s'
                      % (len(transf_ciphertext_chunk), transf_ciphertext_chunk, hexlify(transf_ciphertext_chunk)))

            # Write transformed ciphertext chunk on output file
            write_data_on_file(ciphertext_outfile, transf_ciphertext_chunk, debug)


def apply_aont(data=None, n=AONT_DEFAULT_N, encoding=AONT_DEFAULT_ENCODING, k0=AONT_DEFAULT_K0, debug=0):
    """
    Apply All-Or-Nothing Transformation to the given data
    :param data: data to transform
    :param n: transformation chunk length in bits
    :param encoding: transformation encoding
    :param k0: transformation random length in bits
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging

    # Check if data is set
    if data is None:
        logging.error('apply_aont data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_aont data')
        raise Exception

    if debug:  # ONLY USE FOR DEBUG
        print('DATA BYTES = (%d) %s' % (len(data), data))

    # Initialise variables
    transformed_data = ''

    # Divide data in chunks to perform the transformation
    step = (n - k0) // 8
    for i in range(0, len(data), step):

        # Compute next data chunk starting byte
        next_i = i + step

        # Check if last chunk is shorter than previous ones
        if next_i > len(data):
            next_i = len(data)

        # Get a data chunk of fixed length
        to_transform = data[i: next_i]

        if debug:  # ONLY USE FOR DEBUG
            print('TO_TRANSFORM = (%d) %s' % (len(to_transform), to_transform))

        from old.crypto.OAEPbis import init, pad
        from binascii import hexlify

        # Initialise transformation parameters
        init(n=n, enc=encoding, k0=k0)

        # Apply transformation to data chunk
        transformed_data_chunk = pad(hexlify(to_transform).decode(), debug)

        if debug:  # ONLY USE FOR DEBUG
            print('TRANSFORMED DATA CHUNK = (%d) %s' % (len(transformed_data_chunk), transformed_data_chunk))

        # Append transformed data chunk to the final transformation result
        transformed_data += transformed_data_chunk

    if debug:  # ONLY USE FOR DEBUG
        print('TRANSFORMED DATA BITS = (%s) (%d) %s' % (type(transformed_data), len(transformed_data),
                                                        transformed_data))

    from binascii import unhexlify

    # Convert transformation result from hexadecimal to bytes and fill it with leading zeros
    transformed_data_bytes = unhexlify(hex(int(transformed_data, 2))[2:].zfill(len(transformed_data) // 4))

    if debug:  # ONLY USE FOR DEBUG
        print('TRANSFORMED DATA BYTES = (%d) %s' % (len(transformed_data_bytes), transformed_data_bytes))

    return transformed_data_bytes


def encrypt_sym_key(key=None, pk_file=None, policy=None, debug=0):
    """
    Encrypt the given symmetric key with an asymmetric encryption scheme (particularly, ABE).
    :param key: symmetric key to encrypt
    :param pk_file: ABE public key file
    :param policy: ABE policy to apply to the encrypted key
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: encrypted symmetric key
    """

    import logging
    import os

    # Check if key is set
    if key is None:
        logging.error('encrypt_sym_key key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_sym_key key')
        raise Exception

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.exists(pk_file):
        logging.error('encrypt_sym_key pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_sym_key pk_file')
        raise Exception

    # Check if policy is set
    if policy is None:
        logging.error('encrypt_sym_key policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_sym_key policy')
        raise Exception

    from old.crypto.Const import TEMP_PATH

    # Define temporary files for key encryption
    temp_sym_key_file = 'sym_key'
    temp_enc_sym_key_file = 'enc_' + temp_sym_key_file

    # Write key on temporary file
    # with(open(TEMP_PATH + temp_sym_key_file, 'wb')) as fout:
    # with(open(TEMP_PATH + temp_sym_key_file, 'w')) as fout:
    #    fout.write(key)

    from re_enc_engine.abe_primitives import encrypt

    # Encrypt temporary key file with ABE
    encrypt(enc_outfile=TEMP_PATH + temp_enc_sym_key_file, pk_file=pk_file,
            plaintext_file=TEMP_PATH + temp_sym_key_file, plaintext=key, policy=policy, debug=debug)

    # Read encrypted key from temporary outfile
    with(open(TEMP_PATH + temp_enc_sym_key_file, 'r')) as fin:
        enc_key = fin.read()

    # Delete temporary files
    os.remove(TEMP_PATH + temp_enc_sym_key_file)

    return enc_key


def write_header_on_file(ciphertext_outfile=None, data=None, debug=0):
    """
    Write the header parameters on the given output ciphertext file
    :param ciphertext_outfile: file where header will be written
    :param data: header params to write
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging

    # Check if ciphertext_outfile is set
    if ciphertext_outfile is None:
        logging.error('write_header_on_file ciphertext_outfile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in write_header_on_file ciphertext_outfile')
        raise Exception

    # Check if data is set
    if data is None:
        logging.error('write_header_on_file data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in write_header_on_file data')
        raise Exception

    # Get values to write on file
    version = data[0]
    n = data[1]
    k0 = data[2]
    enc_key_length = data[3]
    enc_key = data[4]
    iv = data[5]
    ciphertext_length = data[6]
    re_enc_num = 0

    if debug:  # ONLY USE FOR DEBUG
        print('VERSION = %d' % version)
        print('N = %d' % n)
        print('K0 = %d' % k0)
        print('ENC SYM KEY = (%d) %s' % (enc_key_length, enc_key))
        print('IV = (%d) %s' % (len(iv), iv))
        print('CIPHERTEXT LENGTH = %d' % ciphertext_length)
        print('RE-ENCRYPTIONS NUM = %d' % re_enc_num)

    # Create string format for struct
    struct_format = 'BHHH%ds%dsQH' % (enc_key_length, len(iv))

    if debug:  # ONLY USE FOR DEBUG
        print('STRING FORMAT FOR STRUCT = ', struct_format)

    import struct

    # Create struct with all header parameters
    data_to_write = struct.pack(struct_format, version, n, k0, enc_key_length, enc_key, iv, ciphertext_length,
                                re_enc_num)

    if debug:  # ONLY USE FOR DEBUG
        print('DATA TO WRITE ON FILE = (%d) %s' % (len(data_to_write), data_to_write))

    from old.FunctionUtils import write_bytes_on_file

    # Write data bytes on given outfile
    write_bytes_on_file(outfile=ciphertext_outfile, data=data_to_write, debug=debug)


def write_data_on_file(ciphertext_outfile=None, data=None, debug=0):
    """
    Append given data on the given file
    :param ciphertext_outfile: file where data will be written
    :param data: data to write
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging
    import os.path

    # Check if ciphertext_outfile is set and it exists
    if ciphertext_outfile is None or not os.path.exists(ciphertext_outfile):
        logging.error('write_data_on_file ciphertext_outfile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in write_data_on_file ciphertext_outfile')
        raise Exception

    # Check if data is set
    if data is None:
        logging.error('write_data_on_file data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in write_data_on_file data')
        raise Exception

    from old.FunctionUtils import write_bytes_on_file

    # Append data to the end of the given outfile
    write_bytes_on_file(ciphertext_outfile, data, 'ab', 0, debug)
