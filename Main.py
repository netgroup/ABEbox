if __name__ == '__main__':

    debug = 0

# =================================================== SCHEME TEST =================================================== #

    from crypto.ABEPrimitives import setup, keygen
    from crypto.Const import TEST_PATH, OUTPUT_PATH

    # TEST ABE KEYS SETUP
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

    # TEST ABE SECRET KEY GENERATION
    sk_file = 'kevin_priv_key'
    attr_list = {'business_staff', 'strategy_team', '\'executive_level = 7#4\'', '\'office = 2362\'',
                 '\'hire_date = \'`date +%s`'}
    keygen(sk_outfile=sk_file, pk_file=pk_file, msk_file=msk_file, attr_list=attr_list, debug=debug)
    print('\n\nSECRET KEY FILE:')
    with open(sk_file, 'rb') as fin:
        for line in fin:
            print(line)

    plaintext_file = TEST_PATH + 'optimal_connection.png'
    ciphertext_file = OUTPUT_PATH + 'enc_test_file'
    policy = '\'business_staff\''
    # policy = '\'(sysadmin and (hire_date < 946702800 or security_team)) or (business_staff and 2 of ' \
    #          '(executive_level >= 5#4, audit_group, strategy_team))\''

    # TEST PLAINTEXT FILE ENCRYPTION
    import Encryptor as Enc

    Enc.create_encrypted_file(plaintext_infile=plaintext_file, ciphertext_outfile=ciphertext_file, pk_file=pk_file,
                              policy=policy, debug=1)

    #exit(0)

    # TEST CIPHERTEXT FILE RE-ENCRYPTION
    import Re_encryptor as Re_enc

    Re_enc.re_encrypt(ciphertext_file, 16, pk_file, policy, 1)

    pk_files = [pk_file]
    sk_files = [sk_file]

    # TEST RE-ENCRYPTED CIPHERTEXT FILE DECRYPTION
    import Decryptor as Dec

    Dec.decrypt_file(ciphertext_file, pk_files, sk_files, 1)

# ================================================== DATABASE TEST ================================================== #

    # from DAO import connect
    #
    # # TEST CONNECTION
    # try:
    #     print('Trying connecting ABEbox DB...\n')
    #     conn = connect(host='172.25.0.3:3307', user='root', passw='abebox')
    # except Exception:
    #     print('[ERROR] Connection failed!')
    #     exit()
    # print('Connection successful')