if __name__ == '__main__':

    debug = 0

# ============================================== SYMMETRIC SCHEME TEST ============================================== #

    from SymEncPrimitives import sym_key_gen, sym_encrypt, sym_decrypt
    from FunctionUtils import read_json_file, write_json_file
    from binascii import hexlify, unhexlify

    # # TEST PARAMETERS CREATION
    # data_to_enc = open('test_file.txt', 'rb').read()
    # print('PARAMS CREATION\nPLAINTEXT = (%d) %s' % (len(data_to_enc), data_to_enc))
    #
    # sym_key = sym_key_gen(32, debug)
    # print('SYM KEY = (%d) %s' % (len(sym_key), sym_key))
    #
    # # TEST ENCRYPTION
    # iv, ciphertext, tag = sym_encrypt(key=sym_key, plaintext=data_to_enc, debug=debug)
    # print('\nENCRYPTION\nIV = (%d) %s -> %s' % (len(iv), iv, hexlify(iv).decode()))
    # print('CIPHERTEXT = (%d) %s -> %s' % (len(ciphertext), ciphertext, hexlify(ciphertext).decode()))
    # print('TAG = (%d) %s -> %s' % (len(tag), tag, hexlify(tag).decode()))
    #
    # ciphertext_hex = hexlify(ciphertext).decode()
    #
    # print('CIPHERTEXT HEX = (%d) %s' % (len(ciphertext_hex), ciphertext_hex))
    #
    # transformed_ciphertext = []
    # step = 256
    # for i in range(0, len(ciphertext_hex), step):
    #     next_i = (i + 1) * step
    #     print('next_i =', next_i)
    #     if next_i > len(ciphertext_hex):
    #         next_i = len(ciphertext_hex)
    #     to_transform = ciphertext_hex[i: next_i]
    #     print('TO_TRANSFORM = (%d) %s' % (len(to_transform), to_transform))
    #
    #     from OAEPbis import pad
    #
    #     debug = 1
    #
    #     transformed_ciphertext_block = pad(to_transform, debug)
    #     print('TRANSFORMED CIPHERTEXT = (%d) %s' % (len(transformed_ciphertext_block), transformed_ciphertext_block))
    #     transformed_ciphertext_block = hex(int(transformed_ciphertext_block, 2))[2:]
    #     print('TRANSFORMED CIPHERTEXT HEX = (%d) %s' % (len(transformed_ciphertext_block), transformed_ciphertext_block))
    #
    #     ciphertext_length = len(to_transform)
    #     print('BLOCK LENGTH IN BITS =', ciphertext_length*4)
    #
    #     transformed_ciphertext_block = bin(int(transformed_ciphertext_block, 16))[2:]
    #     print('TRANSFORMED CIPHERTEXT BITS = (%d) %s' % (len(transformed_ciphertext_block), transformed_ciphertext_block))
    #     leading_zeros = 0
    #     if len(transformed_ciphertext_block) % 8 != 0:
    #         leading_zeros = 8 * int((len(transformed_ciphertext_block) + 7) / 8) - len(transformed_ciphertext_block)
    #         transformed_ciphertext_block = transformed_ciphertext_block.zfill(8 * int((len(transformed_ciphertext_block) + 7) / 8))
    #     print('LEADING ZEROS = ', leading_zeros)
    #     print('TRANSFORMED CIPHERTEXT BITS WITH 0s = (%d) %s' % (len(transformed_ciphertext_block), transformed_ciphertext_block))
    #
    #     transformed_ciphertext.append({
    #         'ciphertext_block': transformed_ciphertext_block,
    #         'length': ciphertext_length,
    #         'leading_zeros': leading_zeros
    #     })
    #
    #     print('CIPHERTEXT ITEM =', transformed_ciphertext)
    #
    #     from OAEPbis import unpad
    #
    #     untransf_ciphertext = unpad(transformed_ciphertext[0]['ciphertext_block'])[2:]
    #
    #     print('UNTRANSFORMED CIPHERTEXT = (%d) %s' % (len(untransf_ciphertext), untransf_ciphertext))
    #
    #     untransf_ciphertext = untransf_ciphertext[: transformed_ciphertext[0]['length']]
    #
    #     print('UNTRANSFORMED CIPHERTEXT = (%d) %s' % (len(untransf_ciphertext), untransf_ciphertext))
    #
    #     untransf_ciphertext = unhexlify(untransf_ciphertext)
    #
    #     print('UNTRANSFORMED CIPHERTEXT = (%d) %s' % (len(untransf_ciphertext), untransf_ciphertext))
    #
    #     print('UNTRANSFORMED PLAINTEXT =', sym_decrypt(sym_key, None, iv, untransf_ciphertext, tag, debug))
    #
    # #exit(0)

# ================================================= ABE SCHEME TEST ================================================= #

    from ABEPrimitives import setup, keygen, encrypt, decrypt

    # TEST SETUP
    pk_file = 'pub_key'
    msk_file = 'master_key'
    setup(pk_outfile=pk_file, msk_outfile=msk_file, debug=debug)
    print('PUB KEY FILE:')
    with open(pk_file, 'rb') as fin:
        for line in fin:
            print(line)
    print('\n\nMASTER SECRET KEY FILE:')
    with open(msk_file, 'rb') as fin:
        for line in fin:
            print(line)

    # TEST KEYGEN
    sk_file = 'kevin_priv_key'
    attr_list = {'business_staff', 'strategy_team', '\'executive_level = 7#4\'', '\'office = 2362\'',
                 '\'hire_date = \'`date +%s`'}
    keygen(sk_outfile=sk_file, pk_file=pk_file, msk_file=msk_file, attr_list=attr_list, debug=debug)
    print('\n\nSECRET KEY FILE:')
    with open(sk_file, 'rb') as fin:
        for line in fin:
            print(line)

    import Encryptor as enc

    enc.create_encrypted_file('test_file.txt', 'enc_test_file', 'pub_key', '\'business_staff\'', 1)

    pk_files = [pk_file]
    sk_files = [sk_file]

    import Decryptor as dec

    dec.decrypt_file('enc_test_file', pk_files, sk_files, 1)

    exit(0)
    # # TEST ENCRYPTION
    # plaintext_file = 'test_file.txt'
    # ciphertext_file = 'test_file.enc'
    # policy = '\'(sysadmin and (hire_date < 946702800 or security_team)) or (business_staff and 2 of ' \
    #          '(executive_level >= 5#4, audit_group, strategy_team))\''
    # encrypt(enc_outfile=ciphertext_file, pk_file=pk_file, plaintext_file=plaintext_file, policy=policy, debug=debug)
    # print('\n\nCIPHERTEXT FILE:')
    # with open(ciphertext_file, 'rb') as fin:
    #     for line in fin:
    #         print(line)
    #
    # # TEST DECRYPTION
    # decrypted_file = 'test_file.txt'
    # decrypt(dec_outfile=decrypted_file, pk_file=pk_file, sk_file=sk_file, ciphertext_file=ciphertext_file, debug=debug)
    # print('\n\nDECRYPTED FILE:')
    # with open(decrypted_file, 'rb') as fin:
    #     for line in fin:
    #         print(line)

    temp_sym_key_file = 'sym_key'
    temp_enc_sym_key_file = 'enc_' + temp_sym_key_file

    with(open(temp_sym_key_file, 'wb')) as fout:
        fout.write(sym_key)

    encrypt(enc_outfile=temp_enc_sym_key_file, pk_file=pk_file, plaintext_file=temp_sym_key_file,
            policy='\'strategy_team\'', debug=debug)

    with(open(temp_enc_sym_key_file, 'rb')) as fin:
        enc_key = hexlify(fin.read()).decode()

    print('ENCRYPTED SYMMETRIC KEY = (%d) %s' % (len(enc_key), enc_key))

    # Create JSON data for file writing
    data_to_write = {'re-encryptions': [],
                     'data': {
                         'key': enc_key,
                         'iv': hexlify(iv).decode(),
                         'ciphertext': transformed_ciphertext,
                         'tag': hexlify(tag).decode()
                     }}
    write_json_file(data_to_write, 'enc_test_file.txt', debug=debug)

# ============================================ RE-ENCRYPTION SCHEME TEST============================================= #

    from ReEncPrimitives import re_encrypt, re_decrypt
    from Const import ABE_PK_FILE

    debug = 1

    re_encrypt('enc_test_file.txt', 16, ABE_PK_FILE,
               '\'(sysadmin and (hire_date < 946702800 or security_team))'
               ' or (business_staff and 2 of (executive_level >= 5#4, '
               'audit_group, strategy_team))\'', debug)

    re_encrypt('enc_test_file.txt', 16, ABE_PK_FILE,
               '\'(sysadmin and (hire_date < 946702800 or security_team))'
               ' or (business_staff and 2 of (executive_level >= 5#4, '
               'audit_group, strategy_team))\'', debug)

    re_decrypt(None, 'enc_test_file.txt', ABE_PK_FILE, 'kevin_priv_key', debug)
    re_decrypt(None, 'dec_re_enc_test_file.txt', ABE_PK_FILE, 'kevin_priv_key', debug)

    # Read and parse JSON data from file
    data_to_dec = read_json_file('dec_re_dec_re_enc_test_file.txt', debug=debug)
    enc_sym_key = unhexlify(data_to_dec['data']['key'])
    iv = unhexlify(data_to_dec['data']['iv'])
    ciphertext = unhexlify(data_to_dec['data']['ciphertext'])
    tag = unhexlify(data_to_dec['data']['tag'])
    print('\nDECRYPTION\nIV = (%d) %s' % (len(iv), iv))
    print('ENC SYM KEY = (%d) %s' % (len(sym_key), sym_key))
    print('CIPHERTEXT = (%d) %s' % (len(ciphertext), ciphertext))
    print('TAG = (%d) %s' % (len(tag), tag))

    temp_dec_sym_key_file = 'dec_' + temp_enc_sym_key_file

    with(open(temp_enc_sym_key_file, 'wb')) as fout:
        fout.write(enc_sym_key)

    decrypt(dec_outfile=temp_dec_sym_key_file, pk_file=pk_file, sk_file=sk_file, ciphertext_file=temp_enc_sym_key_file,
            debug=debug)

    with(open(temp_dec_sym_key_file, 'rb')) as fin:
        dec_sym_key = fin.read()

    # TEST DECRYPTION
    dec_plaintext = sym_decrypt(key=dec_sym_key, iv=iv, ciphertext=ciphertext, tag=tag, debug=debug)
    print('DEC_PLAINTEXT = (%d) %s' % (len(dec_plaintext), dec_plaintext))

    exit(0)

# ================================================== DATABASE TEST ================================================== #

    from DAO import connect

    # TEST CONNECTION
    try:
        print('Trying connecting ABEbox DB...\n')
        conn = connect(host='172.25.0.3:3307', user='root', passw='abebox')
    except Exception:
        print('[ERROR] Connection failed!')
        exit()
    print('Connection successful')