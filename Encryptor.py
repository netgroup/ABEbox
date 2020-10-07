from Const import AONT_DEFAULT_ENCODING, AONT_DEFAULT_N, AONT_DEFAULT_K0, AONT_DEFAULT_K0_FILL


def create_encrypted_file(plaintext_infile=None, ciphertext_outfile=None, pk_file=None, policy=None, debug=0):

    from SymEncPrimitives import sym_key_gen, sym_encrypt
    from FunctionUtils import read_bytes_from_file, write_json_file
    from Log import log
    from Const import SYM_KEY_DEFAULT_SIZE
    from binascii import hexlify
    import os.path

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

    # Read data from the plaintext input file
    data_to_enc = read_bytes_from_file(infile=plaintext_infile)

    if debug:  # ONLY USE FOR DEBUG
        print('[ENCRYPTOR] PLAINTEXT = (%d) %s' % (len(data_to_enc), data_to_enc))

    # Create the key for symmetric encryption of the plaintext
    sym_key = sym_key_gen(SYM_KEY_DEFAULT_SIZE, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('[ENCRYPTOR] SYM KEY = (%d) %s' % (len(sym_key), sym_key))

    from SymEncPrimitives import generate_iv

    # Create the IV for  symmetric encryption
    iv = generate_iv()

    # Encrypt the plaintext using symmetric encryption with the given key
    ciphertext, tag = sym_encrypt(key=sym_key, iv=iv, plaintext=data_to_enc, debug=debug)

    if debug:  # ONLY USE FOR DEBUG
        print('\n[ENCRYPTOR] ENCRYPTION RESULTS:')
        print('[ENCRYPTOR]\tCIPHERTEXT = (%d) %s -> %s' % (len(ciphertext), ciphertext, hexlify(ciphertext).decode()))
        print('[ENCRYPTOR]\tIV = (%d) %s -> %s' % (len(iv), iv, hexlify(iv).decode()))
        print('[ENCRYPTOR]\tTAG = (%s) (%d) %s -> %s' % (type(tag), len(tag), tag, hexlify(tag).decode()))

    # Apply All-or-Nothing Transformation to the ciphertext
    transf_ciphertext, n, k0, leading_zeros = apply_aont(hexlify(ciphertext).decode(), debug=debug)

    if debug:  # ONLY USE FOR DEBUG
        print('\n[ENCRYPTOR] TRANSFORMED CIPHERTEXT =', transf_ciphertext)

    # Encrypt symmetric key with ABE using given public key and policy
    enc_key = encrypt_sym_key(sym_key, pk_file, policy, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('ENCRYPTED SYMMETRIC KEY =', enc_key)

    # If output file is not defined, set a default one
    if ciphertext_outfile is None:
        ciphertext_outfile = 'enc_' + plaintext_infile

    # Protection scheme version
    version = 1

    # Put together all data to write
    data_to_write = [version, n, k0, len(enc_key), enc_key, iv, tag, len(ciphertext), leading_zeros, transf_ciphertext]

    # Write data on output file
    write_data_on_file(ciphertext_outfile, data_to_write, debug)


def apply_aont(message=None, n=AONT_DEFAULT_N, encoding=AONT_DEFAULT_ENCODING, k0=AONT_DEFAULT_K0,
               k0fill=AONT_DEFAULT_K0_FILL, debug=0):

    from Log import log

    # Check if policy is set
    if message is None:
        log('[ERROR] apply_aont message exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_aont message')
        raise Exception

    if debug:  # ONLY USE FOR DEBUG
        print('CIPHERTEXT HEX = (%d) %s' % (len(message), message))

    # Initialise variables
    transformed_ciphertext = ''
    leading_zeros = 0

    # Divide message in blocks to perform the transformation
    step = int((n - k0) / 4)
    for i in range(0, len(message), step):

        # Compute next block starting point
        next_i = i + step
        if next_i > len(message):
            next_i = len(message)

        # Get a block of fixed length from message
        to_transform = message[i: next_i]

        if debug:  # ONLY USE FOR DEBUG
            print('TO_TRANSFORM = (%d) %s' % (len(to_transform), to_transform))

        from OAEPbis import init, pad

        # Initialize transformation parameters
        init(n=n, enc=encoding, k0=k0, k0fill=k0fill)

        # Apply transformation to ciphertext block
        transformed_ciphertext_block = pad(to_transform, debug)

        if debug:  # ONLY USE FOR DEBUG
            print('TRANSFORMED CIPHERTEXT BLOCK = (%d) %s' % (len(transformed_ciphertext_block),
                                                              transformed_ciphertext_block))

        # Compute leading zeros
        leading_zeros = len(transformed_ciphertext_block) // 4 - len(hex(int(transformed_ciphertext_block, 2))[2:])

        # Convert transformed ciphertext to hex
        transformed_ciphertext_block_hex = hex(int(transformed_ciphertext_block, 2))[2:]\
            .zfill(len(transformed_ciphertext_block) // 4)

        if debug:  # ONLY USE FOR DEBUG
            print('LEADING ZEROS = %d' % leading_zeros)
            print('TRANSFORMED CIPHERTEXT BLOCK HEX = (%d) %s' % (len(transformed_ciphertext_block_hex),
                                                                  transformed_ciphertext_block_hex))
        # # Get the transformed ciphertext hex length
        # ciphertext_length = len(to_transform)
        #
        # # Convert transformed ciphertext to binary
        # transformed_ciphertext_block_bits = bin(int(transformed_ciphertext_block_hex, 16))[2:]
        #
        # if debug:  # ONLY USE FOR DEBUG
        #     print('TRANSFORMED CIPHERTEXT BLOCK BITS = (%d) %s' % (len(transformed_ciphertext_block_bits),
        #                                                            transformed_ciphertext_block_bits))
        # # leading_zeros = 0
        #
        # # Check if leading zeros have been cut: if yes, prepend the to the transformed ciphertext block bits
        # if len(transformed_ciphertext_block_bits) % 8 != 0:
        #     # leading_zeros = 8 * int((len(transformed_ciphertext_block) + 7) / 8) - len(transformed_ciphertext_block)
        #     transformed_ciphertext_block_bits = transformed_ciphertext_block_bits.zfill(
        #         8 * int((len(transformed_ciphertext_block_bits) + 7) / 8))
        #
        # # print('LEADING ZEROS = ', leading_zeros)
        #
        # if debug:  # ONLY USE FOR DEBUG
        #     print('TRANSFORMED CIPHERTEXT BLOCK BITS WITH 0s = (%d) %s' % (len(transformed_ciphertext_block_bits),
        #                                                                    transformed_ciphertext_block_bits))

        transformed_ciphertext += transformed_ciphertext_block_hex

    if debug:  # ONLY USE FOR DEBUG
        print('TRANSFORMED CIPHERTEXT = (%d) %s' % (len(transformed_ciphertext), transformed_ciphertext))

    from binascii import unhexlify

    return unhexlify(transformed_ciphertext), n, k0, leading_zeros


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

    from Const import TEMP_PATH

    # Define temporary files for key encryption
    temp_sym_key_file = 'sym_key'
    temp_enc_sym_key_file = 'enc_' + temp_sym_key_file

    # Write key on temporary file
    with(open(TEMP_PATH + temp_sym_key_file, 'wb')) as fout:
        fout.write(key)

    from ABEPrimitives import encrypt

    # Encrypt temporary key file with ABE
    encrypt(enc_outfile=TEMP_PATH + temp_enc_sym_key_file, pk_file=pk_file, plaintext_file=TEMP_PATH + temp_sym_key_file,
            policy=policy, debug=debug)

    # Read encrypted key from temporary outfile
    with(open(TEMP_PATH + temp_enc_sym_key_file, 'rb')) as fin:
        enc_key = fin.read()

    # Delete temporary files
    os.remove(TEMP_PATH + temp_enc_sym_key_file)

    return enc_key


def write_data_on_file(ciphertext_outfile, data, debug=0):

    # Create values to write on file
    version = data[0]
    n = data[1]
    k0 = data[2]
    re_enc_num = 43
    enc_key_length = data[3]
    enc_key = data[4]
    iv = data[5]
    tag = data[6]
    ciphertext_length = data[7]
    leading_zeros = data[8]
    transf_ciphertext = data[9]

    if debug:  # ONLY USE FOR DEBUG
        print('VERSION = %d' % version)
        print('N = %d' % n)
        print('K0 = %d' % k0)
        print('ENC SYM KEY = (%d) %s' % (enc_key_length, enc_key))
        print('IV = (%d) %s' % (len(iv), iv))
        print('TAG = (%d) %s' % (len(tag), tag))
        print('CIPHERTEXT LENGTH = %d' % ciphertext_length)
        print('LEADING ZEROS = %d' % leading_zeros)
        print('TRANSFORMED CIPHERTEXT = (%d) %s' % (len(transf_ciphertext), transf_ciphertext))

    # Create string format for struct
    struct_format = 'BHHH%ds%ds%dsQH%dsH' % (enc_key_length, len(iv), len(tag), len(transf_ciphertext))

    if debug:
        print('STRING FORMAT FOR STRUCT = ', struct_format)

    import struct

    # Create struct with all data
    data_to_write = struct.pack(struct_format, version, n, k0, enc_key_length, enc_key, iv, tag,
                                ciphertext_length, leading_zeros, transf_ciphertext, re_enc_num)

    if debug:  # ONLY USE FOR DEBUG
        print('DATA TO WRITE ON FILE = (%d) %s' % (len(data_to_write), data_to_write))

    from FunctionUtils import write_bytes_on_file

    # Write data bytes on given outfile
    write_bytes_on_file(ciphertext_outfile, data_to_write, debug)

    # with(open(ciphertext_outfile, 'rb')) as fin:
    #
    #    from Const import B, H, Q, IV_DEFAULT_SIZE

    #     print(fin.read(1))
    #     print(fin.read(1))
    #     print(fin.read(1))
    #     print(fin.read(1))


    #     print('TELL', fin.tell())
    #     fin.seek(B + B, 1)
    #     print('TELL', fin.tell())
    #     n1, k01, enc_key_length1 = struct.unpack('HHH', fin.read(3 * H))
    #
    #     print('READ N = %d' % n1)
    #     print('READ K0 = %d' % k01)
    #     print('READ ENC SYM KEY LEN = %d' % enc_key_length1)
    #
    #     print('TELL', fin.tell())
    #     enc_key1, iv1, tag1, ciphertext_length1 = \
    #         struct.unpack('%ds%ds%dsQ' % (enc_key_length1, IV_DEFAULT_SIZE, IV_DEFAULT_SIZE),
    #                       fin.read(enc_key_length1 + IV_DEFAULT_SIZE + IV_DEFAULT_SIZE + Q + 5))
    #
    #     transf_ciphertext_length = int((int(ciphertext_length1 * 8 / (n - k0)) + 1) * n / 8)
    #
    #     if debug:
    #         print('TRANSFORMED CIPHERTEXT LENGTH = %d' % transf_ciphertext_length)
    #
    #     ciphertext_offset = fin.tell()
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('CIPHERTEXT OFFSET = %d' % ciphertext_offset)
    #
    #     transf_ciphertext1, re_enc_num1 = struct.unpack('%dsH' % transf_ciphertext_length,
    #                                                     fin.read(transf_ciphertext_length + H))
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         #print('READ VERSION = %d' % version1)
    #         print('READ N = %d' % n1)
    #         print('READ K0 = %d' % k01)
    #         print('READ RE-ENC NUM = %d' % re_enc_num1)
    #         print('READ ENC SYM KEY = (%d) %s' % (enc_key_length1, enc_key1))
    #         print('READ IV = (%d) %s' % (len(iv1), iv1))
    #         print('READ TAG = (%d) %s' % (len(tag1), tag1))
    #         print('READ CIPHERTEXT LENGTH = %d' % ciphertext_length1)
    #         print('READ TRANSFORMED CIPHERTEXT = (%d) %s' % (len(transf_ciphertext1), transf_ciphertext1))
    #
    #     fin.seek(0)
    #     fin.seek(2 * B)
    #     n, k0, enc_key_length = struct.unpack('HHH', fin.read(3 * H))
    # #
    #     print('\n\n\nOFFSET\nREAD N = %d' % n)
    #     print('READ K0 = %d' % k0)
    #     print('READ ENC SYM KEY = %d' % enc_key_length)
    # #
    #     fin.seek(enc_key_length + IV_DEFAULT_SIZE * 2 + 5, 1)
    #     ciphertext_length = struct.unpack('Q', fin.read(Q))[0]
    #     transf_ciphertext_length = int((int(ciphertext_length * 8 / (n - k0)) + 1) * n / 8)
    # #
    #     ciphertext_offset = fin.tell()
    # #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('CIPHERTEXT OFFSET = %d' % ciphertext_offset)
    # #
    #     transf_ciphertext, re_enc_num = struct.unpack('%dsH' % transf_ciphertext_length, fin.read(transf_ciphertext_length + H))
    #     print('READ TRANSFORMED CIPHERTEXT = (%d) %s' % (len(transf_ciphertext), transf_ciphertext))
    # #
    #     fin.seek(ciphertext_offset + len(transf_ciphertext))
    #     re_enc_num = struct.unpack('H', fin.read(H))[0]
    #     print('LAST READ RE-ENC NUM =', re_enc_num)
