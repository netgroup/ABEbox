from crypto.Const import AONT_DEFAULT_ENCODING, AONT_DEFAULT_N, AONT_DEFAULT_K0, CHUNK_SIZE


def create_encrypted_file(plaintext_infile=None, ciphertext_outfile=None, pk_file=None, policy=None, n=AONT_DEFAULT_N,
                          k0=AONT_DEFAULT_K0, encoding=AONT_DEFAULT_ENCODING, chunk_size=CHUNK_SIZE, debug=0):

    from crypto.SymEncPrimitives import sym_key_gen
    from Log import log
    from crypto.Const import SYM_KEY_DEFAULT_SIZE
    from binascii import hexlify
    import os

    # Check if plaintext_infile is set and exists
    if plaintext_infile is None or not os.path.exists(plaintext_infile):
        log('[ERROR] create_encrypted_file plaintext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in create_encrypted_file plaintext_infile')
        raise Exception

    # Check if pk_file is set and exists
    if pk_file is None or not os.path.exists(pk_file):
        log('[ERROR] create_encrypted_file pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in create_encrypted_file pk_file')
        raise Exception

    # Check if policy is set
    if policy is None:
        log('[ERROR] create_encrypted_file policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in create_encrypted_file policy')
        raise Exception

    # Create the key for symmetric encryption of the plaintext
    sym_key = sym_key_gen(SYM_KEY_DEFAULT_SIZE, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('[ENCRYPTOR] SYM KEY = (%d) %s -> %s' % (len(sym_key), sym_key, hexlify(sym_key)))

    from crypto.SymEncPrimitives import generate_iv

    # Create the IV for  symmetric encryption
    iv = generate_iv()

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
    version = 1

    # Put together all header data to write
    header = [version, n, k0, len(enc_key), enc_key, iv, os.path.getsize(plaintext_infile)]

    # Write header on output file
    write_header_on_file(ciphertext_outfile, header, debug)

    # Apply encryption, transform ciphertext and write result to the output file
    apply_enc_aont(plaintext_infile, ciphertext_outfile, sym_key, iv, n, encoding, k0, chunk_size, debug)


def apply_enc_aont(plaintext_infile=None, ciphertext_outfile=None, key=None, iv=None, n=AONT_DEFAULT_N,
                   encoding=AONT_DEFAULT_ENCODING, k0=AONT_DEFAULT_K0, chunk_size=CHUNK_SIZE, debug=0):

    from crypto.SymEncPrimitives import sym_encrypt
    from binascii import hexlify

    # Read data block from the plaintext input file
    with(open(plaintext_infile, 'rb')) as fin:

        for plaintext_chunk in iter(lambda: fin.read(chunk_size), ''):

            # Last read is empty, so processing is skipped
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

            # Apply All-or-Nothing Transformation to the ciphertext chunk
            #transf_ciphertext_chunk, leading_zeros = apply_aont(ciphertext_chunk, n, encoding, k0, debug)
            transf_ciphertext_chunk = apply_aont(ciphertext_chunk, n, encoding, k0, debug)

            if debug:  # ONLY USE FOR DEBUG
                print('[ENCRYPTOR] TRANSFORMED CIPHERTEXT CHUNK = (%d) %s -> %s'
                      % (len(transf_ciphertext_chunk), transf_ciphertext_chunk, hexlify(transf_ciphertext_chunk)))

            # Write transformed ciphertext chunk on output file
            write_data_on_file(ciphertext_outfile, transf_ciphertext_chunk, debug)


def apply_aont(data=None, n=AONT_DEFAULT_N, encoding=AONT_DEFAULT_ENCODING, k0=AONT_DEFAULT_K0, debug=0):

    from Log import log

    # Check if data is set
    if data is None:
        log('[ERROR] apply_aont data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_aont data')
        raise Exception

    if debug:  # ONLY USE FOR DEBUG
        print('DATA BYTES = (%d) %s' % (len(data), data))

    # Initialise variables
    transformed_data = ''
    # leading_zeros = 0

    # Divide data in chunks to perform the transformation
    step = (n - k0) // 8
    for i in range(0, len(data), step):

        # Compute next data chunk starting point
        next_i = i + step

        # Check if last chunk is shorter than previous ones
        if next_i > len(data):
            next_i = len(data)

        # Get a data chunk of fixed length
        to_transform = data[i: next_i]

        if debug:  # ONLY USE FOR DEBUG
            print('TO_TRANSFORM = (%d) %s' % (len(to_transform), to_transform))

        from crypto.OAEPbis import init, pad
        from binascii import hexlify

        # Initialize transformation parameters
        init(n=n, enc=encoding, k0=k0)

        # Apply transformation to data chunk
        transformed_data_chunk = pad(hexlify(to_transform).decode(), debug)

        if debug:  # ONLY USE FOR DEBUG
            print('TRANSFORMED DATA CHUNK = (%d) %s' % (len(transformed_data_chunk), transformed_data_chunk))

        # Compute leading zeros
        # leading_zeros = len(transformed_message_block) // 4 - len(hex(int(transformed_message_block, 2))[2:])

        # Convert transformed data chunk to hex
        # transformed_data_chunk_hex = hex(int(transformed_data_chunk, 2))[2:].zfill(len(transformed_data_chunk) // 4)

        # if debug:  # ONLY USE FOR DEBUG
            # print('LEADING ZEROS = %d' % leading_zeros)
            # print('TRANSFORMED DATA CHUNK HEX = (%d) %s' % (len(transformed_data_chunk_hex),
            #                                                 transformed_data_chunk_hex))

        transformed_data += transformed_data_chunk

    if debug:  # ONLY USE FOR DEBUG
        print('TRANSFORMED DATA BITS = (%s) (%d) %s' % (type(transformed_data), len(transformed_data), transformed_data))

    from binascii import unhexlify

    transformed_data_bytes = unhexlify(hex(int(transformed_data, 2))[2:].zfill(len(transformed_data) // 4))

    if debug:  # ONLY USE FOR DEBUG
        print('TRANSFORMED DATA BYTES = (%d) %s' % (len(transformed_data_bytes), transformed_data_bytes))

    return transformed_data_bytes


def encrypt_sym_key(key=None, pk_file=None, policy=None, debug=0):

    from Log import log
    import os

    # Check if key is set
    if key is None:
        log('[ERROR] encrypt_sym_key key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_sym_key key')
        raise Exception

    # Check if pk_file is set and exists
    if pk_file is None or not os.path.exists(pk_file):
        log('[ERROR] encrypt_sym_key pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_sym_key pk_file')
        raise Exception

    # Check if policy is set
    if policy is None:
        log('[ERROR] encrypt_sym_key policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_sym_key policy')
        raise Exception

    from crypto.Const import TEMP_PATH

    # Define temporary files for key encryption
    temp_sym_key_file = 'sym_key'
    temp_enc_sym_key_file = 'enc_' + temp_sym_key_file

    # Write key on temporary file
    with(open(TEMP_PATH + temp_sym_key_file, 'wb')) as fout:
        fout.write(key)

    from crypto.ABEPrimitives import encrypt

    # Encrypt temporary key file with ABE
    encrypt(enc_outfile=TEMP_PATH + temp_enc_sym_key_file, pk_file=pk_file, plaintext_file=TEMP_PATH + temp_sym_key_file,
            policy=policy, debug=debug)

    # Read encrypted key from temporary outfile
    with(open(TEMP_PATH + temp_enc_sym_key_file, 'rb')) as fin:
        enc_key = fin.read()

    # Delete temporary files
    os.remove(TEMP_PATH + temp_enc_sym_key_file)

    return enc_key


def write_header_on_file(ciphertext_outfile, data, debug=0):

    # Create values to write on file
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

    if debug:
        print('STRING FORMAT FOR STRUCT = ', struct_format)

    import struct

    # Create struct with all data
    data_to_write = struct.pack(struct_format, version, n, k0, enc_key_length, enc_key, iv, ciphertext_length,
                                re_enc_num)

    if debug:  # ONLY USE FOR DEBUG
        print('DATA TO WRITE ON FILE = (%d) %s' % (len(data_to_write), data_to_write))

    from FunctionUtils import write_bytes_on_file

    # Write data bytes on given outfile
    write_bytes_on_file(outfile=ciphertext_outfile, data=data_to_write, debug=debug)


def write_data_on_file(ciphertext_outfile, data, debug=0):

    # # Create string format for struct
    # struct_format = 'BHHH%ds%dsQH%dsH' % (enc_key_length, len(iv), len(transf_ciphertext))
    #
    # if debug:
    #     print('STRING FORMAT FOR STRUCT = ', struct_format)
    #
    # import struct
    #
    # # Create struct with all data
    # data_to_write = struct.pack(struct_format, version, n, k0, enc_key_length, enc_key, iv, ciphertext_length,
    #                             leading_zeros, transf_ciphertext, re_enc_num)
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('DATA TO WRITE ON FILE = (%d) %s' % (len(data_to_write), data_to_write))

    from FunctionUtils import write_bytes_on_file

    # Append data to the end of the given outfile
    write_bytes_on_file(ciphertext_outfile, data, 'ab', 0, debug)
