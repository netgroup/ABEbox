if __name__ == '__main__':

    debug = 1

    # import requests, json
    #
    # data = {
    #     "company_id": "test_id",
    #     "time_interval": 0,
    #     "full": False,
    #     "re_enc_data": json.dumps([
    #         {
    #             'file_name': 'test_file.txt',
    #             'pub_keys': ['pk_file'],
    #             'policies': ['test'],
    #             're_enc_lengths': [16]
    #         }
    #     ])
    # }
    #
    # print(data)
    # headers = {'Content-type': 'multipart/form-data', 'Connection': 'keep-alive'}
    #
    # files = {'pk_file0': open('keys/pk_file', 'rb')}
    #
    # r = requests.post('http://localhost:9000/send_re_enc_info', files=files, data=data, headers=headers)
    #
    # print(r)
    #
    # exit(0)


# =================================================== SCHEME TEST =================================================== #

    from old.FunctionUtils import clear_folder, init_logger
    from crypto.Const import KEY_PATH, OUTPUT_PATH, TEMP_PATH, TEST_PATH

    # Remove files created during previous executions
    clear_folder(KEY_PATH)
    clear_folder(OUTPUT_PATH)
    clear_folder(TEMP_PATH)

    import logging

    # Initialise logger
    init_logger()

    logging.warning('MAIN LOG')

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

    Enc.create_encrypted_file(plaintext_infile=plaintext_file, ciphertext_outfile=ciphertext_file, pk_file=pk_file,
                              policy=policy, debug=debug)

    exit(0)

    # TEST CIPHERTEXT FILE RE-ENCRYPTION

    Re_enc.apply_re_encryption(ciphertext_file, 16, pk_file, policy, debug)

    pk_files = [pk_file]
    sk_files = [sk_file]

    # TEST RE-ENCRYPTED CIPHERTEXT FILE DECRYPTION
    from old import Decryptor as Dec

    Dec.decrypt_file('re_enc_engine/storage/enc_test_file', pk_files, sk_files, debug)

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