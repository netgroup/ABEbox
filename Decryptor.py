def decrypt_file(ciphertext_infile=None, pk_files=None, sk_files=None, debug=None):

    from Log import log
    import os.path

    # Check if ciphertext_infile is set and exists
    if ciphertext_infile is None or not os.path.exists(ciphertext_infile):
        log('[ERROR] decrypt_file ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_file ciphertext_infile')
        raise Exception

    # Check if pk_files is set
    if pk_files is None:
        log('[ERROR] decrypt_file pk_files exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_file pk_files')
        raise Exception

    # Check if each element of the pk_files exists
    for pk_file in pk_files:
        if not os.path.exists(pk_file):
            log('[ERROR] decrypt_file pk_files element exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in decrypt_file pk_files element')
            raise Exception

    # Check if sk_files is set
    if sk_files is None:
        log('[ERROR] decrypt_file sk_files exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_file sk_files')
        raise Exception

    # Check if each element of the sk_files exists
    for sk_file in sk_files:
        if not os.path.exists(sk_file):
            log('[ERROR] decrypt_file sk_files element exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in decrypt_file sk_files element')
            raise Exception

    # Remove re-encryptions with ABE using given public and secret keys
    remove_re_encryptions(ciphertext_infile, pk_files, sk_files, debug)

    plaintext_outfile = 'dec_' + ciphertext_infile

    # Decrypt ciphertext file to get plaintext
    decrypt_ciphertext(ciphertext_infile, plaintext_outfile, pk_files[0], sk_files[0], debug)
    #decrypt_ciphertext(ciphertext_infile, plaintext_outfile, pk_files[0], sk_files[0], debug)


def remove_re_encryptions(infile=None, pk_files=None, sk_files=None, debug=0):

    from Log import log
    import os.path

    # Check if infile is set and exists
    if infile is None or not os.path.exists(infile):
        log('[ERROR] remove_re_encryptions infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_encryptions infile')
        raise Exception

    # Check if pk_files is set
    if pk_files is None:
        log('[ERROR] remove_re_encryptions pk_files exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_encryptions pk_files')
        raise Exception

    # Check if each element of the pk_files exists
    for pk_file in pk_files:
        if not os.path.exists(pk_file):
            log('[ERROR] remove_re_encryptions pk_files element exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in remove_re_encryptions pk_files element')
            raise Exception

    # Check if sk_files is set
    if sk_files is None:
        log('[ERROR] remove_re_encryptions sk_files exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_encryptions sk_files')
        raise Exception

    # Check if each element of the sk_files exists
    for sk_file in sk_files:
        if not os.path.exists(sk_file):
            log('[ERROR] remove_re_encryptions sk_files element exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in remove_re_encryptions sk_files element')
            raise Exception

    from ReEncPrimitives import re_decrypt

    # Remove all re-encryptions from the ciphertext file (reverse order: start from last re-encryption)
    for i in range(len(pk_files)):

        # Get current re-encryption keys
        pk_file = pk_files[-1-i]
        sk_file = sk_files[-1-i]

        # Decrypt re-encryption
        re_decrypt(infile, pk_file, sk_file, debug)


def decrypt_ciphertext(infile=None, outfile=None, pk_file=None, sk_file=None, debug=0):

    from Log import log
    import os.path

    # Check if infile is set and exists
    if infile is None or not os.path.exists(infile):
        log('[ERROR] decrypt_ciphertext infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_ciphertext infile')
        raise Exception

    # Check if pk_file is set and exists
    if pk_file is None or not os.path.exists(pk_file):
        log('[ERROR] decrypt_ciphertext pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_ciphertext pk_file')
        raise Exception

    # Check if sk_file is set and exists
    if sk_file is None or not os.path.exists(sk_file):
        log('[ERROR] decrypt_ciphertext infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_ciphertext sk_file')
        raise Exception

    # If outfile is not defined, set a default value
    if outfile is None:
        outfile = 'dec_' + infile

    # Get encryption parameters
    transf_ciphertext, enc_sym_key, iv, tag, n, k0, ciphertext_length, leading_zeros = get_encryption_params(infile,
                                                                                                             debug)

    # Decrypt symmetric key using ABE with given public and secret keys
    sym_key = decrypt_sym_key(enc_sym_key, pk_file, sk_file, debug)

    if debug:
        print('DECRYPTED SYMMETRIC KEY = (%d) %s' % (len(sym_key), sym_key))
        print('IV = (%d) %s' % (len(iv), iv))
        print('TAG = (%d) %s' % (len(tag), tag))
        print('CIPHERTEXT = (%d) %s' % (len(transf_ciphertext), transf_ciphertext))

    ciphertext = remove_aont(transf_ciphertext, n, k0, ciphertext_length, leading_zeros, debug)

    from SymEncPrimitives import sym_decrypt

    # Decrypt ciphertext
    dec_plaintext = sym_decrypt(key=sym_key, iv=iv, ciphertext=ciphertext, tag=tag, debug=debug)

    if debug:
        print('DECRYPTED PLAINTEXT = (%d) %s' % (len(dec_plaintext), dec_plaintext))

    from FunctionUtils import write_bytes_on_file

    # Write decrypted plaintext on output file
    write_bytes_on_file(outfile, dec_plaintext, debug)


def get_encryption_params(infile=None, debug=0):

    from Log import log
    import os.path

    # Check if infile is set and exists
    if infile is None or not os.path.exists(infile):
        log('[ERROR] get_encryption_params infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_encryption_params infile')
        raise Exception

    # Read and parse data bytes from file
    with(open(infile, 'rb')) as fin:

        from Const import B, H, Q, IV_DEFAULT_SIZE
        import struct

        fin.seek(B + B)
        n, k0, enc_key_length = struct.unpack('HHH', fin.read(3 * H))
        enc_key, iv, tag, ciphertext_length, leading_zeros = \
            struct.unpack('%ds%ds%dsQH' % (enc_key_length, IV_DEFAULT_SIZE, IV_DEFAULT_SIZE),
                          fin.read(enc_key_length + IV_DEFAULT_SIZE + IV_DEFAULT_SIZE + Q + H + 5))
        transf_ciphertext_length = int((int(ciphertext_length * 8 / (n - k0)) + 1) * n / 8)
        transf_ciphertext = struct.unpack('%ds' % transf_ciphertext_length, fin.read(transf_ciphertext_length))[0]

        if debug:  # ONLY USE FOR DEBUG
            #print('READ VERSION = %d' % version)
            print('READ N = %d' % n)
            print('READ K0 = %d' % k0)
            #print('READ RE-ENC NUM = %d' % re_enc_num)
            print('READ ENC SYM KEY = (%d) %s' % (enc_key_length, enc_key))
            print('READ IV = (%d) %s' % (len(iv), iv))
            print('READ TAG = (%d) %s' % (len(tag), tag))
            print('READ CIPHERTEXT LENGTH = %d' % ciphertext_length)
            print('READ LEADING ZEROS = %d' % leading_zeros)
            print('READ TRANSFORMED CIPHERTEXT = (%d) %s' % (len(transf_ciphertext), transf_ciphertext))

    return transf_ciphertext, enc_key, iv, tag, n, k0, ciphertext_length, leading_zeros


def decrypt_sym_key(enc_key=None, pk_file=None, sk_file=None, debug=0):

    from Log import log
    import os.path

    # Check if enc_key is set
    if enc_key is None:
        log('[ERROR] decrypt_sym_key enc_key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_sym_key enc_key')
        raise Exception

    # Check if pk_file is set and exists
    if pk_file is None or not os.path.exists(pk_file):
        log('[ERROR] decrypt_sym_key pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_sym_key pk_file')
        raise Exception

    # Check if sk_file is set and exists
    if sk_file is None or not os.path.exists(sk_file):
        log('[ERROR] decrypt_sym_key sk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_sym_key sk_file')
        raise Exception

    # Create temporary files for symmetric key decryption
    temp_enc_sym_key_file = 'enc_sym_key'
    temp_dec_sym_key_file = 'dec_' + temp_enc_sym_key_file

    # Write encrypted symmetric key on a temporary file
    with(open(temp_enc_sym_key_file, 'wb')) as fout:
        fout.write(enc_key)

    from ABEPrimitives import decrypt

    # Decrypt encrypted symmetric key file with ABE using given public and secret keys
    decrypt(dec_outfile=temp_dec_sym_key_file, pk_file=pk_file, sk_file=sk_file, ciphertext_file=temp_enc_sym_key_file,
            debug=debug)

    # Read decrypted symmetric key from decryption output file
    with(open(temp_dec_sym_key_file, 'rb')) as fin:
        dec_sym_key = fin.read()

    return dec_sym_key


def remove_aont(data=None, n=None, k0=None, ciphertext_length=None, leading_zeros=None, debug=0):

    from binascii import hexlify

    # Initialise variables
    untransformed_ciphertext = ''

    # Divide message in blocks to perform the untransformation
    step = int(n / 8)
    for i in range(0, len(data), step):

        # Compute next block starting point
        next_i = i + step

        print('BLOCK = (%d) %s' % (len(data[i: next_i]), data[i: next_i]))

        # Get a block of fixed length from data
        to_untransform = bin(int(hexlify(data[i: next_i]).decode(), 16))[2:].zfill(n)

        if debug:  # ONLY USE FOR DEBUG
            print('TO_UNTRANSFORM = (%d) %s' % (len(to_untransform), to_untransform))

        from OAEPbis import init, unpad

        # Initialize untransformation parameters
        init(n=n, k0=k0)

        # Apply untransformation to ciphertext block
        untransformed_ciphertext_block_hex = unpad(to_untransform, debug)[2:]

        if debug:  # ONLY USE FOR DEBUG
            print('UNTRANSFORMED CIPHERTEXT BLOCK HEX = (%d) %s' % (len(untransformed_ciphertext_block_hex),
                                                                    untransformed_ciphertext_block_hex))

        # # Convert untransformed ciphertext to binary
        # untransformed_ciphertext_block_bits = bin(int(untransformed_ciphertext_block_hex, 16))[2:]
        #
        # if debug:  # ONLY USE FOR DEBUG
        #     print('TRANSFORMED CIPHERTEXT BLOCK BITS = (%d) %s' % (len(untransformed_ciphertext_block_bits),
        #                                                            untransformed_ciphertext_block_bits))
        #
        # # Check if leading zeros have been cut: if yes, prepend the to the transformed ciphertext block bits
        # if len(untransformed_ciphertext_block_bits) % 8 != 0:
        #     untransformed_ciphertext_block_bits = untransformed_ciphertext_block_bits.zfill(
        #         8 * int((len(untransformed_ciphertext_block_bits) + 7) / 8))
        #
        # if debug:  # ONLY USE FOR DEBUG
        #     print('UNTRANSFORMED CIPHERTEXT BLOCK BITS WITH 0s = (%d) %s' % (len(untransformed_ciphertext_block_bits),
        #                                                                      untransformed_ciphertext_block_bits))

        if next_i == len(data):

            c = '0' * leading_zeros + untransformed_ciphertext_block_hex
            print('UNTRANSF BLOCK HEX = (%d) %s' % (len(c), c))

            untransformed_ciphertext_block_hex = '0' * leading_zeros + untransformed_ciphertext_block_hex

        untransformed_ciphertext += untransformed_ciphertext_block_hex

    untransformed_ciphertext = untransformed_ciphertext[: ciphertext_length * 2]

    if debug:
        print('UNTRANSFORMED CIPHERTEXT = (%d) %s' % (len(untransformed_ciphertext), untransformed_ciphertext))

    from binascii import unhexlify

    return unhexlify(untransformed_ciphertext)
