def apply_re_encryption(enc_file=None, re_enc_length=None, pk_file=None, policy=None, debug=0):

    from Log import log
    import os.path

    # Check if enc_file is set and exists
    if enc_file is None or not os.path.exists(enc_file):
        log('[ERROR] apply_re_encryption enc_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption enc_file')
        raise Exception

    # Check if re_enc_length is set
    if re_enc_length is None:
        log('[ERROR] apply_re_encryption re_enc_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption re_enc_length')
        raise Exception

    # Check if enc_file is set and exists
    if pk_file is None or not os.path.exists(pk_file):
        log('[ERROR] apply_re_encryption pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption pk_file')
        raise Exception

    # Check if policy is set
    if policy is None:
        log('[ERROR] apply_re_encryption policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_re_encryption policy')
        raise Exception

    from ReEncPrimitives import re_encrypt

    re_encrypt(get_ciphertext(enc_file, debug), re_enc_length, pk_file, policy, debug)


def get_ciphertext(infile=None, debug=0):

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
        print('TAG = (%d) %s' % (len(tag), tag))
        print('TRANSFORMED CIPHERTEXT BLOCK NUM = %d' % transf_ciphertext_block_num)
        print('CIPHERTEXT BLOCK LENGTHS = (%d) %s' % (len(ciphertext_block_lengths), ciphertext_block_lengths))
        print('TRANSFORMED CIPHERTEXT = (%d) %s' % (len(transf_ciphertext), transf_ciphertext))

    from binascii import hexlify

    return hexlify(transf_ciphertext).decode()
