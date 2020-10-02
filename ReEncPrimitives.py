# This file contains Hybrid Proxy Re-Encryption scheme primitives. These functions are the implementation of the ones
# defined in the work of S. Myers and A. Shull, "Efficient Hybrid Proxy Re-Encryption for Practical Revocation and Key
# Rotation" (https://eprint.iacr.org/2017/833.pdf).


def re_encrypt(ciphertext=None, re_enc_length=None, new_pk_file=None, policy=None, debug=0):
    """ Re-encrypt the ciphertext using the punctured encryption with new keys.
    :param ciphertext: data to re-encrypt
    :param re_enc_length: number of bits to re-encrypt
    :param new_pk_file: file where the new public key is stored
    :param policy: string containing the policy to apply to seed and key during encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the new ciphertext with all the parameters required for decryption
    """

    from Const import RE_ENC_MIN_LENGTH, RE_ENC_LENGTH, SEED_LENGTH
    from FunctionUtils import clamp
    from Log import log
    from SymEncPrimitives import sym_key_gen, sym_encrypt
    import json
    import os.path

    # Check if the ciphertext is set
    if ciphertext is None:
        log('[ERROR] Re-encryption ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re-encryption ciphertext')
        raise Exception

    # Check if the new public key file is set and exists
    if new_pk_file is None or not os.path.isfile(new_pk_file):
        log('[ERROR] Re-encryption new public key file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re-encryption new public key file')
        raise Exception

    # Check if the policy is set
    if policy is None:
        log('[ERROR] Re-encryption policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re-encryption policy')
        raise Exception

    # If re-encryption length is not set, assign a default value
    if re_enc_length is None:
        re_enc_length = RE_ENC_LENGTH

    if debug:  # ONLY USE FOR DEBUG
        print('CIPHERTEXT (%d) = %s' % (len(ciphertext), ciphertext))

    # Get ciphertext length in bits from hex representation
    ciphertext_length = len(ciphertext)*4

    # Clamp the number of bits to re-encrypt between RE_ENC_MIN_LENGTH and ciphertext length
    re_enc_length = clamp(re_enc_length*8, RE_ENC_MIN_LENGTH*8, ciphertext_length, debug)

    if re_enc_length is None:
        log('[ERROR] Clamping value exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in clamp')
        raise Exception

    if debug:  # ONLY USE FOR DEBUG
        print('RE_ENC_LENGTH = %d' % (re_enc_length/4))

    # Get bits to re-encrypt
    seed, re_enc_indexes, bits_to_re_enc = get_bits_to_re_enc(ciphertext=ciphertext, re_enc_length=re_enc_length,
                                                              debug=debug)

    if debug:
        print('BITS TO RE-ENCRYPT = (%d) %s -> %s' % (len(bits_to_re_enc), bits_to_re_enc, hex(int(bits_to_re_enc, 2))))

    # Convert bits to hex for re-encryption
    bytes_to_re_enc = bytes.fromhex(hex(int(bits_to_re_enc, 2))[2:].zfill(int(len(bits_to_re_enc)/4)))

    from binascii import hexlify

    if debug:
        print('HEX TO RE-ENCRYPT = (%d) %s -> %s' % (len(bytes_to_re_enc), bytes_to_re_enc, hexlify(bytes_to_re_enc)))

    # Re-encryption symmetric key
    k = sym_key_gen(sym_key_size=SEED_LENGTH, debug=debug)

    if debug:
        print('RE-ENCRYPTION SYM KEY = (%d) %s -> %s' % (len(k), k, hexlify(k).decode()))

    # Re-encrypt bits
    iv, re_enc_bytes, tag = sym_encrypt(key=k, plaintext=bytes_to_re_enc, associated_data=None, debug=debug)

    if debug:
        print('IV = (%d) %s -> %s' % (len(iv), iv, hexlify(iv).decode()))
        print('RE-ENCRYPTED BYTES = (%d) %s -> %s' % (len(re_enc_bytes), re_enc_bytes, hexlify(re_enc_bytes).decode()))
        print('TAG = (%d) %s -> %s' % (len(tag), tag, hexlify(tag).decode()))

    # Convert encryption parameters to hex
    k = hexlify(k).decode()
    iv = hexlify(iv).decode()
    re_enc_hex = hexlify(re_enc_bytes).decode()
    tag = hexlify(tag).decode()

    # Convert re-encryption result from hex to bin
    re_enc_bits = bin(int(re_enc_hex, 16))[2:]

    if debug:
        print('RE-ENCRYPTED BITS = (%d) %s' % (len(re_enc_bits), re_enc_bits))

    # Replace re-encrypted bits in the ciphertext
    re_enc_ciphertext = replace_re_enc_bits(ciphertext=ciphertext, re_enc_bits=re_enc_bits,
                                            re_enc_indexes=re_enc_indexes, re_enc_length=len(bits_to_re_enc),
                                            debug=debug)

    if debug:
        print('RE-ENCRYPTED CIPHERTEXT = (%d) %s' % (len(re_enc_ciphertext), re_enc_ciphertext))

    # Encrypt seed, key and number of re-encrypted bits using ABE with given public key and policy
    enc_data = encrypt_seed_key(data=json.dumps({'s': hexlify(seed).decode(), 'k': k, 'l*': re_enc_length}),
                                pk_file=new_pk_file, policy=policy, debug=debug)

    # Update data in the ciphertext file with new ciphertext and encryption parameters
    update_ciphertext(file=ciphertext_infile, enc_seed_key=enc_data, iv=iv, tag=tag,
                      new_ciphertext=re_enc_ciphertext, debug=debug)


def get_bits_to_re_enc(ciphertext=None, re_enc_length=None, debug=0):
    """ Puncture the ciphertext selecting a given number of bits to re-encrypt
    :param ciphertext: the text to puncture
    :param re_enc_length: number of bits to select
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the seed to randomly generate bits positions, positions of bits to re-encrypt, bits to re-encrypt
    """

    from Const import SEED_LENGTH
    from FunctionUtils import generate_random_string
    from Log import log

    # Check if the ciphertext is set
    if ciphertext is None:
        log('[ERROR] get_bits_to_re_enc ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_bits_to_re_enc ciphertext')
        raise Exception

    # Check if the re_enc_length is set
    if re_enc_length is None:
        log('[ERROR] get_bits_to_re_enc re_enc_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_bits_to_re_enc re_enc_length')
        raise Exception

    # Get ciphertext length in bits from hex representation
    ciphertext_length = len(ciphertext) * 4

    # Set default values
    seed = None
    bits_to_re_enc = ''
    re_enc_indexes = [i for i in range(ciphertext_length)]

    # Generate random positions to re-encrypt only if re-encryption length is less than ciphertext's
    if re_enc_length < ciphertext_length:

        # Generate a pseudorandom seed
        seed = generate_random_string(length=SEED_LENGTH, debug=debug)

        if debug:  # ONLY USE FOR DEBUG
            print('SEED = (%d) %s' % (len(seed), seed))

        # Generate a pseudorandom set of indexes to re-encrypt
        re_enc_indexes = ind(seed, re_enc_length, range(ciphertext_length))

        if debug:  # ONLY USE FOR DEBUG
            print('INDEXES =', re_enc_indexes)

        re_enc_indexes.sort()

        if debug:  # ONLY USE FOR DEBUG
            print('SORTED INDEXES =', re_enc_indexes)

        # Converts ciphertext in bits string
        ciphertext_bits = bin(int(ciphertext, 16))[2:]

        if debug:  # ONLY USE FOR DEBUG
            print('CIPHERTEXT IN BITS (%d) = %s' % (len(ciphertext_bits), ciphertext_bits))

        # Check if trailing zeros have been cut
        diff_bits_num = ciphertext_length - len(ciphertext_bits)

        if debug:
            print('%d trailing zeros have been cut in bits_to_re_enc' % diff_bits_num)

        # Fill cut trailing zeros
        if diff_bits_num > 0:
            ciphertext_bits = '0' * diff_bits_num + ciphertext_bits

        if debug:  # ONLY USE FOR DEBUG
            print('CIPHERTEXT IN BITS (%d) = %s' % (len(ciphertext_bits), ciphertext_bits))

        # Create a string consists of the bits in the randomly generated positions
        for index in re_enc_indexes:

            if debug:  # ONLY USE FOR DEBUG
                print('BIT #%d IN CIPHERTEXT = %d' % (index, int(ciphertext_bits[index])))

            bits_to_re_enc += ciphertext_bits[index]

    else:

        log('[WARNING] Re-encrypting full ciphertext')

        if debug:
            print('[WARNING] Re-encrypting full ciphertext')

        # Converts ciphertext in bits string
        bits_to_re_enc = bin(int(ciphertext, 16))[2:]

    # Check if trailing zeros have been cut
    diff_bits_num = re_enc_length - len(bits_to_re_enc)

    if debug:
        print('%d trailing zeros have been cut in bits_to_re_enc' % diff_bits_num)

    # Fill cut trailing zeros
    if diff_bits_num > 0:
        bits_to_re_enc = '0' * diff_bits_num + bits_to_re_enc

    return seed, re_enc_indexes, bits_to_re_enc


def ind(s=None, l=None, dataset=None, debug=0):
    """ Generate a pseudorandom set of l values.
    :param s: seed for the pseudorandom generator
    :param l: size of the set to generate
    :param dataset: elements to sample
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: a list of l pseudorandom values
    """

    from Log import log

    # Check if s is set
    if s is None:
        log('[ERROR] ind s exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in ind s')
        raise Exception

    # Check if l is set
    if l is None:
        log('[ERROR] ind l* exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in ind l*')
        raise Exception

    # Check if dataset is set
    if dataset is None:
        log('[ERROR] ind set exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in ind set')
        raise Exception

    import random   # [WARNING] NOT CRYPTOGRAPHICALLY SECURE

    # Plant the given seed for random generator
    random.seed(a=s)

    # Return a secure random sample of l elements from the given set
    return random.sample(dataset, l)


def replace_re_enc_bits(ciphertext=None, re_enc_bits=None, re_enc_indexes=None, re_enc_length=None, debug=0):
    """
    Replace re-encrypted bits in the ciphertext
    :param ciphertext: the string whose bits must be replaced
    :param re_enc_bits: re-encrypted bits
    :param re_enc_indexes: positions of bits to replace in the ciphertext
    :param re_enc_length: length of the re-encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: replaced ciphertext as hex
    """

    from Log import log

    # Check if ciphertext is set
    if ciphertext is None:
        log('[ERROR] replace_re_enc_bits ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bits ciphertext')
        raise Exception

    # Check if re_enc_bits is set
    if re_enc_bits is None:
        log('[ERROR] replace_re_enc_bits re_enc_bits exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bits re_enc_bits')
        raise Exception

    # Check if re_enc_indexes is set
    if re_enc_indexes is None:
        log('[ERROR] replace_re_enc_bits re_enc_indexes exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bits re_enc_indexes')
        raise Exception

    # Check if re_enc_length is set
    if re_enc_length is None:
        log('[ERROR] replace_re_enc_bits re_enc_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bits re_enc_length')
        raise Exception

    # Check if trailing zeros have been cut in re_enc_bits
    diff_re_enc_bits_num = re_enc_length - len(re_enc_bits)

    if debug:
        print('%d trailing zeros have been cut in re_enc_bits' % diff_re_enc_bits_num)

    # Fill cut trailing zeros
    if diff_re_enc_bits_num > 0:
        re_enc_bits = '0' * diff_re_enc_bits_num + re_enc_bits

    if debug:
        print('RE-ENCRYPTED BITS = (%d) %s' % (len(re_enc_bits), re_enc_bits))

    # Convert the ciphertext in bits
    ciphertext_bits = bin(int(ciphertext, 16))[2:]

    if debug:
        print('CIPHERTEXT BITS = (%d) %s' % (len(ciphertext_bits), ciphertext_bits))

    # Check if trailing zeros have been cut in ciphertext
    diff_ciphertext_bits_num = len(ciphertext)*4 - len(ciphertext_bits)

    if debug:
        print('%d trailing zeros have been cut in ciphertext_bits' % diff_ciphertext_bits_num)

    # Fill cut trailing zeros
    if diff_ciphertext_bits_num > 0:
        ciphertext_bits = '0' * diff_ciphertext_bits_num + ciphertext_bits

    if debug:
        print('CIPHERTEXT BITS = (%d) %s' % (len(ciphertext_bits), ciphertext_bits))

    # Convert ciphertext to a list of bits
    ciphertext_bits = list(ciphertext_bits)

    if debug:
        print('re_enc_indexes = ', len(re_enc_indexes))
        print('re_enc_bits = ', len(re_enc_bits))
        print('re_enc_length = ', re_enc_length)
        print('ciphertext_bits = (%d) %s' % (len(ciphertext_bits), ciphertext_bits))

    # Replace original bits with re-encrypted ones
    for i in range(len(re_enc_indexes)):
        if ciphertext_bits[re_enc_indexes[i]] != re_enc_bits[i]:
            print('REPLACING IN POSITION %d %s -> %s' % (re_enc_indexes[i], ciphertext_bits[re_enc_indexes[i]],
                                                         re_enc_bits[i]))
            ciphertext_bits[re_enc_indexes[i]] = re_enc_bits[i]

    # Convert the replaced ciphertext to a string
    re_enc_ciphertext_bits = ''.join(ciphertext_bits)

    if debug:
        print('RE-ENCRYPTED CIPHERTEXT BITS = (%d) %s' % (len(re_enc_ciphertext_bits), re_enc_ciphertext_bits))

    return hex(int(re_enc_ciphertext_bits, 2))[2:]


def update_ciphertext(file=None, enc_seed_key=None, iv=None, tag=None, new_ciphertext=None, debug=0):
    """
    Update the given file replacing the ciphertext with the new one and adding all the parameters required to decrypt
    the re-encryption process
    :param file: file to update
    :param enc_seed_key: encrypted seed and key (first to randomly generate bit positions for puncturing, second used
                         in the symmetric re-encryption
    :param iv: iv used in the cipher
    :param tag: tag used in the cipher
    :param new_ciphertext: new ciphertext that outputs from re-encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    from Log import log
    import json, os.path

    # Check if file is set and exists
    if file is None or not os.path.isfile(file):
        log('[ERROR] update_ciphertext file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in update_ciphertext file')
        raise Exception

    # Check if enc_seed_key is set
    if enc_seed_key is None:
        log('[ERROR] update_ciphertext enc_seed_key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in update_ciphertext enc_seed_key')
        raise Exception

    # Check if iv is set
    if iv is None:
        log('[ERROR] update_ciphertext iv exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in update_ciphertext iv')
        raise Exception

    # Check if tag is set
    if tag is None:
        log('[ERROR] update_ciphertext tag exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in update_ciphertext tag')
        raise Exception

    # Check if key is set
    if new_ciphertext is None:
        log('[ERROR] update_ciphertext new_ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in update_ciphertext new_ciphertext')
        raise Exception

    # Update data in the ciphertext file
    with(open(file)) as fin:
        data = json.load(fin)

    if debug:
        print('JSON CONTENT = ', data)

    # Update ciphertext
    data['data']['ciphertext'] = new_ciphertext

    print('RE-ENCRYPTIONS BEFORE = ', data['re-encryptions'])

    # Add parameters of new re-encryption
    data['re-encryptions'].append({
        'enc_s_k': enc_seed_key,
        'iv': iv,
        'tag': tag
    })

    print('RE-ENCRYPTIONS AFTER = ', data['re-encryptions'])

    if debug:
        print('NEW JSON CONTENT = ', data)

    with(open(file, 'w')) as fout:
        json.dump(data, fout)


def encrypt_seed_key(data=None, pk_file=None, policy=None, debug=0):
    """
    Encrypt data using ABE scheme with the given public key and policy
    :param data: the content to encrypt
    :param pk_file: file containing the public key
    :param policy: policy to apply during encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: encrypted data
    """

    from Log import log
    import os.path

    # Check if data is set
    if data is None:
        log('[ERROR] encrypt_seed_key data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_seed_key data')
        raise Exception

    # Check if the public key file is set and exists
    if pk_file is None or not os.path.isfile(pk_file):
        log('[ERROR] encrypt_seed_key public key file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_seed_key public key file')
        raise Exception

    # Check if the policy is set
    if policy is None:
        log('[ERROR] encrypt_seed_key policy exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in encrypt_seed_key policy')
        raise Exception

    # Create temporary files for ABE encryption
    temp_file = 'temp.txt'
    enc_temp_file = 'enc_' + temp_file

    import json

    with(open(temp_file, 'w')) as fout:
        json.dump(data, fout)

    from ABEPrimitives import encrypt

    # Encrypt temp file with ABE
    encrypt(enc_outfile=enc_temp_file, pk_file=pk_file, plaintext_file=temp_file, policy=policy, debug=debug)

    from binascii import hexlify

    enc_data = hexlify(open(enc_temp_file, 'rb').read()).decode()

    if debug:  # ONLY USE FOR DEBUG
        print('ENCRYPTED SEED AND KEY = ', enc_data)

    # Delete temporary files
    #os.remove(temp_file)
    #os.remove(enc_temp_file)

    return enc_data


def re_decrypt(dec_outfile=None, ciphertext_infile=None, pk_file=None, sk_file=None, debug=0):
    """
    Remove the last re-encryption applied to the given ciphertext file
    :param dec_outfile: output file for decryption
    :param ciphertext_infile: ciphertext file to decrypt
    :param pk_file: ABE public key
    :param sk_file: ABE secret key
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    from Log import log
    import os.path

    # Check if ciphertext file is set and exists
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        log('[ERROR] re_decrypt ciphertext infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_decrypt ciphertext infile')
        raise Exception

    # Check if the public key file is set and exists
    if pk_file is None or not os.path.isfile(pk_file):
        log('[ERROR] re_decrypt public key file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_decrypt public key file')
        raise Exception

    # Check if the secret key file is set and exists
    if sk_file is None or not os.path.isfile(sk_file):
        log('[ERROR] re_decrypt secret key file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_decrypt secret key file')
        raise Exception

    # Check if the output file for decryption is set, otherwise set a default value
    if dec_outfile is None:
        dec_outfile = 'dec_re_' + ciphertext_infile

    import json

    # Read data from ciphertext file
    with(open(ciphertext_infile, 'r')) as fin:
        data = json.load(fin)

    if debug:  # ONLY USE FOR DEBUG
        print('DATA READ FROM CIPHERTEXT = ', data)

    # Extract last re-encryption parameters and remove them from ciphertext file
    re_enc_params = data['re-encryptions'].pop()

    # Update ciphertext after decrypting the re-encryption
    data['data']['ciphertext'] = decrypt_re_encryption(enc_file_content=data, re_enc_params=re_enc_params,
                                                       pk_file=pk_file, sk_file=sk_file, debug=debug)

    with(open(dec_outfile, 'w')) as fout:
        json.dump(data, fout)


def decrypt_re_encryption(enc_file_content=None, re_enc_params=None, pk_file=None, sk_file=None, debug=0):
    """
    Remove the re-encryption from the ciphertext
    :param enc_file_content: content of encrypted file to decrypt
    :param re_enc_params: re-encryption parameters
    :param pk_file: ABE public key to decrypt re-encryption parameters
    :param sk_file: ABE secret key to decrypt re-encryption parameters
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: ciphertext without the given re-encryption
    """

    from Log import log
    import os.path

    # Check if enc_file_content is set
    if enc_file_content is None:
        log('[ERROR] decrypt_re_encryption enc_file_content exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_re_encryption enc_file_content')
        raise Exception

    # Check if re_enc_params is set
    if re_enc_params is None:
        log('[ERROR] decrypt_re_encryption re_enc_params exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_re_encryption re_enc_params')
        raise Exception

    # Check if the public key file is set and exists
    if pk_file is None or not os.path.isfile(pk_file):
        log('[ERROR] decrypt_re_encryption public key file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_re_encryption public key file')
        raise Exception

    # Check if the secret key file is set and exists
    if sk_file is None or not os.path.isfile(sk_file):
        log('[ERROR] decrypt_re_encryption secret key file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_re_encryption secret key file')
        raise Exception

    # Get re-encryption parameters
    enc_seed_key = re_enc_params['enc_s_k']
    iv = re_enc_params['iv']
    tag = re_enc_params['tag']

    if debug:  # ONLY USE FOR DEBUG
        print('ENC_SEED_KEY = ', enc_seed_key)
        print('IV = ', iv)
        print('TAG = ', tag)

    seed, key, re_enc_length = decrypt_seed_key(enc_seed_key=enc_seed_key, pk_file=pk_file, sk_file=sk_file, debug=debug)

    if debug:  # ONLY USE FOR DEBUG
        print('DECRYPTED SEED =', seed)
        print('DECRYPTED SYM KEY =', key)

    from binascii import unhexlify

    # Convert decryption parameters from hex to bytes
    iv = unhexlify(iv)
    key = unhexlify(key)
    tag = unhexlify(tag)

    # Remove re-encryption from the ciphertext
    dec_ciphertext = remove_re_enc(ciphertext=enc_file_content['data']['ciphertext'], seed=seed, key=key,
                                   iv=iv, tag=tag, re_enc_length=re_enc_length, debug=debug)

    return dec_ciphertext


def decrypt_seed_key(enc_seed_key=None, pk_file=None, sk_file=None, debug=0):
    """
    Decrypt encrypted seed and symmetric key with ABE using the given public key and secret key
    :param enc_seed_key: encrypted seed and symmetric key to decrypt
    :param pk_file: ABE public key
    :param sk_file: ABE secret key
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: decrypted seed, symmetric key and number of re-encrypted bits
    """

    from Log import log
    import os.path

    # Check if enc_seed_key is set
    if enc_seed_key is None:
        log('[ERROR] decrypt_seed_key ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_seed_key ciphertext')
        raise Exception

    # Check if the public key file is set and exists
    if pk_file is None or not os.path.isfile(pk_file):
        log('[ERROR] decrypt_seed_key public key file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_seed_key public key file')
        raise Exception

    # Check if the secret key file is set and exists
    if sk_file is None or not os.path.isfile(sk_file):
        log('[ERROR] decrypt_seed_key secret key file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_seed_key secret key file')
        raise Exception

    # Create temporary files for decryption
    enc_temp_file = 'enc_temp.txt'
    dec_temp_file = 'dec_' + enc_temp_file

    from binascii import unhexlify

    with(open(enc_temp_file, 'wb')) as fout:
        fout.write(unhexlify(enc_seed_key))

    from ABEPrimitives import decrypt

    # Decrypt with ABE using given public key and secret key
    decrypt(dec_outfile=dec_temp_file, pk_file=pk_file, sk_file=sk_file, ciphertext_file=enc_temp_file, debug=debug)

    import json

    # Read decryption result from output file
    with(open(dec_temp_file, 'r')) as fin:
        data = fin.read().replace('\\', '')[1:-1]
        dec_result = json.loads(data)

    if debug:  # ONLY USE FOR DEBUG
        print('ABE DECRYPTION RESULT =', type(dec_result), dec_result)

    # Delete temporary files
    os.remove(dec_temp_file)

    return dec_result['s'], dec_result['k'], dec_result['l*']


def remove_re_enc(ciphertext=None, seed=None, key=None, re_enc_length=None, iv=None, tag=None, debug=0):
    """

    :param ciphertext:
    :param seed:
    :param key:
    :param re_enc_length:
    :param iv:
    :param tag:
    :param debug:
    :return:
    """

    from Log import log

    # Check if ciphertext is set
    if ciphertext is None:
        log('[ERROR] remove_re_enc ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_enc ciphertext')
        raise Exception

    # Check if key is set
    if key is None:
        log('[ERROR] remove_re_enc key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_enc key')
        raise Exception

    # Compute ciphertext length in bits
    ciphertext_length = len(ciphertext)*4

    # Set default values to params
    bits_to_dec_positions = [i for i in range(ciphertext_length)]

    # Check if full ciphertext needs to be decrypted
    if seed is None:

        bits_to_dec = bin(int(ciphertext, 16))[2:]

        if debug:  # ONLY USE FOR DEBUG
            print('FULL DECRYPTION\nBITS TO DECRYPT = (%d) %s' % (len(bits_to_dec), bits_to_dec))

    else:

        # Set default value for number of re-encrypted bits
        if re_enc_length is None:

            from Const import RE_ENC_LENGTH

            re_enc_length = RE_ENC_LENGTH*8

        if debug:  # ONLY USE FOR DEBUG
            print('RE_ENC_LENGTH =', re_enc_length)

        from binascii import unhexlify

        # Get positions of bits to decrypt
        bits_to_dec_positions = ind(s=unhexlify(seed), l=re_enc_length, dataset=range(ciphertext_length), debug=debug)

        if debug:  # ONLY USE FOR DEBUG
            print('INDEXES =', bits_to_dec_positions)

        bits_to_dec_positions.sort()

        if debug:  # ONLY USE FOR DEBUG
            print('SORTED INDEXES =', bits_to_dec_positions)

        # Converts ciphertext in bits string
        ciphertext_bits = bin(int(ciphertext, 16))[2:]

        if debug:  # ONLY USE FOR DEBUG
            print('CIPHERTEXT IN BITS (%d) = %s' % (len(ciphertext_bits), ciphertext_bits))

        # Check if trailing zeros have been cut
        diff_bits_num = ciphertext_length - len(ciphertext_bits)

        if debug:
            print('%d trailing zeros have been cut in bits_to_re_enc' % diff_bits_num)

        # Fill cut trailing zeros
        if diff_bits_num > 0:
            ciphertext_bits = '0' * diff_bits_num + ciphertext_bits

        bits_to_dec = ''

        # Create a string consists of the bits in the randomly generated positions
        for index in bits_to_dec_positions:

            if debug:  # ONLY USE FOR DEBUG
                print('BIT #%d IN CIPHERTEXT = %d' % (index, int(ciphertext_bits[index])))

            bits_to_dec += ciphertext_bits[index]

    # Check if trailing zeros have been cut
    diff_bits_num = re_enc_length - len(bits_to_dec)

    if debug:  # ONLY USE FOR DEBUG
        print('%d trailing zeros have been cut in bits_to_re_enc' % diff_bits_num)

    # Fill cut trailing zeros
    if diff_bits_num > 0:
        bits_to_dec = '0' * diff_bits_num + bits_to_dec

    if debug:  # ONLY USE FOR DEBUG
        print('BITS TO DECRYPT = (%d) %s -> %s' % (len(bits_to_dec), bits_to_dec, hex(int(bits_to_dec, 2))))

    # Convert bits to hex for decryption
    bytes_to_dec = bytes.fromhex(hex(int(bits_to_dec, 2))[2:].zfill(int(len(bits_to_dec)/4)))

    from binascii import hexlify

    if debug:  # ONLY USE FOR DEBUG
        print('HEX TO DECRYPT = (%d) %s -> %s' % (len(bytes_to_dec), bytes_to_dec, hexlify(bytes_to_dec)))

    from SymEncPrimitives import sym_decrypt

    # Decrypt re-encrypted bits
    dec_bytes = sym_decrypt(key=key, associated_data=None, iv=iv, ciphertext=bytes_to_dec, tag=tag, debug=debug)

    if debug:  # ONLY USE FOR DEBUG
        print('DECRYPTED BYTES = (%d) %s -> %s' % (len(dec_bytes), dec_bytes, hexlify(dec_bytes).decode()))

    # Convert decryption result from bytes to bin
    dec_bits = bin(int(hexlify(dec_bytes).decode(), 16))[2:]

    if debug:  # ONLY USE FOR DEBUG
        print('DECRYPTED BITS = (%d) %s' % (len(dec_bits), dec_bits))

    # Replace decrypted bits in the ciphertext
    dec_re_enc_ciphertext = replace_re_enc_bits(ciphertext=ciphertext, re_enc_bits=dec_bits,
                                                re_enc_indexes=bits_to_dec_positions, re_enc_length=len(bits_to_dec),
                                                debug=debug)

    if debug:  # ONLY USE FOR DEBUG
        print('DECRYPTED CIPHERTEXT = (%d) %s' % (len(dec_re_enc_ciphertext), dec_re_enc_ciphertext))

    return dec_re_enc_ciphertext
