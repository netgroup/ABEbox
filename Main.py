from CipherPrimitives import setup, keygen, encrypt, decrypt

# from DAO import connect
#
# try:
#     print('Trying connecting ABEbox DB...\n')
#     conn = connect(host='172.25.0.3:3307', user='root', passw='abebox')
# except Exception:
#     print('[ERROR] Connection failed!')
#     exit()
# print('Connection successful')

if __name__ == '__main__':

    debug = 1

    # TEST ABE LIB SETUP
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

    # TEST ABE LIB KEYGEN
    sk_file = 'kevin_priv_key'
    attr_list = {'business_staff', 'strategy_team', '\'executive_level = 7#4\'', '\'office = 2362\'',
                 '\'hire_date = \'`date +%s`'}
    keygen(sk_outfile=sk_file, pk_file=pk_file, msk_file=msk_file, attr_list=attr_list, debug=debug)
    print('\n\nSECRET KEY FILE:')
    with open(sk_file, 'rb') as fin:
        for line in fin:
            print(line)

    # TEST ABE LIB ENCRYPT
    plaintext_file = 'test_file.txt'
    ciphertext_file = 'test_file.enc'
    policy = '\'(sysadmin and (hire_date < 946702800 or security_team)) or (business_staff and 2 of ' \
             '(executive_level >= 5#4, audit_group, strategy_team))\''
    encrypt(enc_outfile=ciphertext_file, pk_file=pk_file, plaintext_file=plaintext_file, policy=policy, debug=debug)
    print('\n\nCIPHERTEXT FILE:')
    with open(ciphertext_file, 'rb') as fin:
        for line in fin:
            print(line)

    # TEST ABE LIB DECRYPT
    decrypted_file = 'dec_test_file.txt'
    decrypt(dec_outfile=decrypted_file, pk_file=pk_file, sk_file=sk_file, ciphertext_file=ciphertext_file, debug=debug)
    print('\n\nDECRYPTED FILE:')
    with open(decrypted_file, 'rb') as fin:
        for line in fin:
            print(line)
