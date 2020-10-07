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

    from ReEncPrimitives import re_encrypt

    re_encrypt(enc_file, re_enc_length, pk_file, policy, debug)


# def get_ciphertext(infile=None, debug=0):
#
#     # Read and parse data bytes from file
#     with(open(infile, 'rb')) as fin:
#
#         from Const import B, H, Q, IV_DEFAULT_SIZE
#         import struct
#
#         version, n, k0, enc_key_length = struct.unpack('BHHH', fin.read(B + 3 * H + 1))
#         enc_key, iv, tag, ciphertext_length, leading_zeros = \
#             struct.unpack('%ds%ds%dsQH' % (enc_key_length, IV_DEFAULT_SIZE, IV_DEFAULT_SIZE),
#                           fin.read(enc_key_length + IV_DEFAULT_SIZE + IV_DEFAULT_SIZE + Q + 5))
#         transf_ciphertext_length = int((int(ciphertext_length * 8 / (n - k0)) + 1) * n / 8)
#         transf_ciphertext = struct.unpack('%ds' % transf_ciphertext_length, fin.read(transf_ciphertext_length))[0]
#
#         if debug:  # ONLY USE FOR DEBUG
#             print('READ VERSION = %d' % version)
#             print('READ N = %d' % n)
#             print('READ K0 = %d' % k0)
#             print('READ ENC SYM KEY = (%d) %s' % (enc_key_length, enc_key))
#             print('READ IV = (%d) %s' % (len(iv), iv))
#             print('READ TAG = (%d) %s' % (len(tag), tag))
#             print('READ CIPHERTEXT LENGTH = %d' % ciphertext_length)
#             print('READ TRANSFORMED CIPHERTEXT = (%d) %s' % (len(transf_ciphertext), transf_ciphertext))
#
#     from binascii import hexlify
#
#     return hexlify(transf_ciphertext).decode()
