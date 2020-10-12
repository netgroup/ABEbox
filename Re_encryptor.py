def re_encrypt(enc_file=None, re_enc_length=None, pk_file=None, policy=None, debug=0):

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

    from crypto.ReEncPrimitives import re_encrypt

    re_encrypt(enc_file, re_enc_length, pk_file, policy, debug)
