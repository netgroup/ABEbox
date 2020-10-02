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

    # Encrypt the plaintext using symmetric encryption with the given key
    iv, ciphertext, tag = sym_encrypt(key=sym_key, plaintext=data_to_enc, debug=debug)

    if debug:  # ONLY USE FOR DEBUG
        print('\n[ENCRYPTOR] ENCRYPTION RESULTS:')
        print('[ENCRYPTOR]\tCIPHERTEXT = (%d) %s -> %s' % (len(ciphertext), ciphertext, hexlify(ciphertext).decode()))
        print('[ENCRYPTOR]\tIV = (%d) %s -> %s' % (len(iv), iv, hexlify(iv).decode()))
        print('[ENCRYPTOR]\tTAG = (%s) (%d) %s -> %s' % (type(tag), len(tag), tag, hexlify(tag).decode()))

    # Apply All-or-Nothing Transformation to the ciphertext
    ciphertext_block_lengths, transf_ciphertext = apply_aont(hexlify(ciphertext).decode(), debug=debug)

    if debug:  # ONLY USE FOR DEBUG
        print('\n[ENCRYPTOR] TRANSFORMED CIPHERTEXT =', transf_ciphertext)

    # Encrypt symmetric key with ABE using given public key and policy
    enc_key = encrypt_sym_key(sym_key, pk_file, policy, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('ENCRYPTED SYMMETRIC KEY =', enc_key)

    # If output file is not defined, set a default one
    if ciphertext_outfile is None:
        ciphertext_outfile = 'enc_' + plaintext_infile

    # Write data on output file
    write_data_on_file(ciphertext_outfile, enc_key, iv, tag, ciphertext_block_lengths, transf_ciphertext, debug)


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
    ciphertext_block_lengths = []
    transformed_ciphertext = ''

    # Divide message in blocks to perform the transformation
    step = int(n / 4)
    for i in range(0, len(message), step):
        next_i = (i + 1) * step
        if next_i > len(message):
            next_i = len(message)
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
        # Convert transformed ciphertext to hex
        transformed_ciphertext_block_hex = hex(int(transformed_ciphertext_block, 2))[2:]

        if debug:  # ONLY USE FOR DEBUG
            print('TRANSFORMED CIPHERTEXT BLOCK HEX = (%d) %s' % (len(transformed_ciphertext_block_hex),
                                                                  transformed_ciphertext_block_hex))
        # Get the transformed ciphertext hex length
        ciphertext_length = len(to_transform)

        # Convert transformed ciphertext to binary
        transformed_ciphertext_block_bits = bin(int(transformed_ciphertext_block_hex, 16))[2:]

        if debug:  # ONLY USE FOR DEBUG
            print('TRANSFORMED CIPHERTEXT BLOCK BITS = (%d) %s' % (len(transformed_ciphertext_block_bits),
                                                                   transformed_ciphertext_block_bits))
        # leading_zeros = 0

        # Check if leading zeros have been cut: if yes, prepend the to the transformed ciphertext block bits
        if len(transformed_ciphertext_block_bits) % 8 != 0:
            # leading_zeros = 8 * int((len(transformed_ciphertext_block) + 7) / 8) - len(transformed_ciphertext_block)
            transformed_ciphertext_block_bits = transformed_ciphertext_block_bits.zfill(
                8 * int((len(transformed_ciphertext_block_bits) + 7) / 8))

        # print('LEADING ZEROS = ', leading_zeros)

        if debug:  # ONLY USE FOR DEBUG
            print('TRANSFORMED CIPHERTEXT BLOCK BITS WITH 0s = (%d) %s' % (len(transformed_ciphertext_block_bits),
                                                                           transformed_ciphertext_block_bits))

        transformed_ciphertext += transformed_ciphertext_block_hex
        ciphertext_block_lengths.append(ciphertext_length)

    return ciphertext_block_lengths, bytes.fromhex(transformed_ciphertext)


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


def write_data_on_file(ciphertext_outfile, enc_key, iv, tag, ciphertext_block_lengths, transf_ciphertext,
                       debug=0):

    # Create all parameters to write in the given file
    enc_key_length = len(enc_key)
    transf_ciphertext_block_num = len(ciphertext_block_lengths)

    if debug:  # ONLY USE FOR DEBUG
        print('ENC SYM KEY = (%d) %s' % (len(enc_key), enc_key))
        print('IV = (%d) %s' % (len(iv), iv))
        print('TAG = (%d) %s' % (len(tag), tag))
        print('TRANSFORMED CIPHERTEXT BLOCK NUM =', transf_ciphertext_block_num)
        print('CIPHERTEXT BLOCK LENGTHS =', ciphertext_block_lengths)
        print('TRANSFORMED CIPHERTEXT = (%d) %s' % (len(transf_ciphertext), transf_ciphertext))

    # Create string format for struct
    struct_format = 'H%ds%ds%dsH' % (enc_key_length, len(iv), len(tag)) + transf_ciphertext_block_num * 'H' + \
                    '%ds' % len(transf_ciphertext)

    if debug:
        print('STRING FORMAT FOR STRUCT = ', struct_format)

    import struct

    # Create struct with all data
    data_to_write = struct.pack(struct_format, enc_key_length, enc_key, iv, tag, transf_ciphertext_block_num,
                                *ciphertext_block_lengths, transf_ciphertext)

    if debug:  # ONLY USE FOR DEBUG
        print('DATA TO WRITE ON FILE =', data_to_write)

    from FunctionUtils import write_bytes_on_file

    # Write data bytes on given outfile
    write_bytes_on_file(ciphertext_outfile, data_to_write, debug)

    with(open(ciphertext_outfile, 'rb')) as fin:

        from Const import H, IV_TAG, AONT_DEFAULT_N

        l = struct.unpack('H', fin.read(H))[0]
        enc_key, iv, tag, block_num = struct.unpack('%ds%ds%dsH' % (l, IV_TAG, IV_TAG),
                                                                      fin.read(l + IV_TAG + IV_TAG + H + 1))

        block_lengths, cipher = struct.unpack('%dH%ds' % (block_num, block_num * int(AONT_DEFAULT_N / 8)), fin.read(block_num * H + block_num * int(AONT_DEFAULT_N / 8)))
        print('l =', l)
        print('enc_key =', enc_key)
        print('iv =', iv)
        print('tag = (%s) %s' % (type(tag), tag))
        print('block_num =', block_num)
        print('block_lengths =', block_lengths)
        print('ciphertext_tuple =', cipher)
        print('ciphertext compare =', cipher == transf_ciphertext)