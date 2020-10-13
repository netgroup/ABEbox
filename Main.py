if __name__ == '__main__':

    debug = 1

# =================================================== SCHEME TEST =================================================== #

    from FunctionUtils import clear_folder, init_logger
    from crypto.Const import KEY_PATH, OUTPUT_PATH, TEMP_PATH, TEST_PATH

    # Remove files created during previous executions
    clear_folder(KEY_PATH)
    clear_folder(OUTPUT_PATH)
    clear_folder(TEMP_PATH)

    import logging

    # Initialise logger
    init_logger()

    logging.warning('MAIN LOG')

    import ABE_key_creator as abe

    # Define ABE public and master secret keys output files
    pk_file = KEY_PATH + 'pk_file'
    msk_file = KEY_PATH + 'msk_file'

    # Create ABE public and master secret keys
    abe.key_setup(pk_file=pk_file, msk_file=msk_file, debug=debug)

    # Define ABE secret key output file and related attributes set
    sk_file = KEY_PATH + 'kevin_priv_key'
    attr_list = {'business_staff', 'strategy_team', '\'executive_level = 7#4\'', '\'office = 2362\'',
                 '\'hire_date = \'`date +%s`'}

    abe.secret_key_gen(sk_file=sk_file, pk_file=pk_file, msk_file=msk_file, attr_list=attr_list, debug=debug)

    plaintext_file = TEST_PATH + 'test_file.txt'
    ciphertext_file = OUTPUT_PATH + 'enc_test_file'
    policy = '\'business_staff\''
    # policy = '\'(sysadmin and (hire_date < 946702800 or security_team)) or (business_staff and 2 of ' \
    #          '(executive_level >= 5#4, audit_group, strategy_team))\''

    # TEST PLAINTEXT FILE ENCRYPTION
    import Encryptor as Enc

    Enc.create_encrypted_file(plaintext_infile=plaintext_file, ciphertext_outfile=ciphertext_file, pk_file=pk_file,
                              policy=policy, debug=debug)

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