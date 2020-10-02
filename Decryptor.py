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

    ciphertext_outfile = 'dec_re_' + ciphertext_infile

    # Remove re-encryptions with ABE using given public and secret keys
    #remove_re_encryptions(ciphertext_infile, ciphertext_outfile, pk_files, sk_files, debug)

    plaintext_outfile = 'dec_' + ciphertext_infile

    # Decrypt ciphertext file to get plaintext
    #decrypt_ciphertext(ciphertext_outfile, plaintext_outfile, pk_files[0], sk_files[0], debug)
    decrypt_ciphertext(ciphertext_infile, plaintext_outfile, pk_files[0], sk_files[0], debug)


def remove_re_encryptions(infile=None, outfile=None, pk_files=None, sk_files=None, debug=0):

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
        if os.path.exists(pk_file):
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
        if os.path.exists(sk_file):
            log('[ERROR] remove_re_encryptions sk_files element exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in remove_re_encryptions sk_files element')
            raise Exception

    # If outfile is not defined, set a default value
    if outfile is None:
        outfile = 'dec_re_' + infile

    from ReEncPrimitives import re_decrypt

    # Remove all re-encryptions from the ciphertext file (reverse order: start from last re-encryption)
    for i in range(len(pk_files)):

        # Get current re-encryption keys
        pk_file = pk_files[-1-i]
        sk_file = sk_files[-1-i]

        # Decrypt re-encryption
        re_decrypt(outfile, infile, pk_file, sk_file, debug)

        # Update input file
        infile = outfile


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
    ciphertext, enc_sym_key, iv, tag = get_encryption_params(infile, debug)

    # Decrypt symmetric key using ABE with given public and secret keys
    sym_key = decrypt_sym_key(enc_sym_key, pk_file, sk_file, debug)

    if debug:
        print('DECRYPTED SYMMETRIC KEY = (%d) %s' % (len(sym_key), sym_key))
        print('IV = (%d) %s' % (len(iv), iv))
        print('TAG = (%d) %s' % (len(tag), tag))
        print('CIPHERTEXT = (%d) %s' % (len(ciphertext), ciphertext))

    ciphertext = remove_aont(ciphertext, debug)

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

        from Const import H, IV_TAG, AONT_DEFAULT_N
        import struct

        enc_sym_key_length = struct.unpack('H', fin.read(H))[0]
        enc_sym_key, iv, tag, transf_ciphertext_block_num = \
            struct.unpack('%ds%ds%dsH' % (enc_sym_key_length, IV_TAG, IV_TAG),
                          fin.read(enc_sym_key_length + IV_TAG + IV_TAG + H + 1))
        transf_ciphertext_length = transf_ciphertext_block_num * int(AONT_DEFAULT_N / 8)
        ciphertext_block_lengths, transf_ciphertext = \
            struct.unpack('%dH%ds' % (transf_ciphertext_block_num, transf_ciphertext_length),
                          fin.read(transf_ciphertext_block_num * H + transf_ciphertext_length))

    if debug:  # ONLY USE FOR DEBUG
        print('ENC SYM KEY LENGTH = %d' % enc_sym_key_length)
        print('ENC SYM KEY = (%d) %s' % (len(enc_sym_key), enc_sym_key))
        print('IV = (%d) %s' % (len(iv), iv))
        print('TAG = (%s) (%d) %s' % (type(tag), len(tag), tag))
        print('TRANSFORMED CIPHERTEXT BLOCK NUM = %d' % transf_ciphertext_block_num)
        print('CIPHERTEXT BLOCK LENGTHS = %d' % ciphertext_block_lengths)
        print('TRANSFORMED CIPHERTEXT = (%d) %s' % (len(transf_ciphertext), transf_ciphertext))

    return transf_ciphertext, enc_sym_key, iv, tag


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


def remove_aont(data=None, debug=0):

    from OAEPbis import unpad
    from binascii import hexlify

    return unpad(hexlify(data).decode(), debug)