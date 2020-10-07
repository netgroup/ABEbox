# This file contains Hybrid Proxy Re-Encryption scheme primitives. These functions are the implementation of the ones
# defined in the work of S. Myers and A. Shull, "Efficient Hybrid Proxy Re-Encryption for Practical Revocation and Key
# Rotation" (https://eprint.iacr.org/2017/833.pdf).


def re_encrypt(ciphertext_infile=None, re_enc_length=None, new_pk_file=None, policy=None, debug=0):
    """ Re-encrypt the ciphertext using the punctured encryption with new keys.
    :param ciphertext_infile: input file for re-encryption
    :param re_enc_length: number of bits to re-encrypt
    :param new_pk_file: file where the new public key is stored
    :param policy: string containing the policy to apply to seed and key during encryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the new ciphertext with all the parameters required for decryption
    """

    from Const import RE_ENC_LENGTH
    from Log import log
    import os.path

    # Check if the ciphertext is set
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
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

    seed, k, iv, tag, re_enc_length = re_enc_ciphertext_bytes(ciphertext_infile, re_enc_length, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('SEED = (%d) %s' % (len(seed), seed))
        print('KEY = (%d) %s' % (len(k), k))
        print('IV = (%d) %s' % (len(iv), iv))
        print('TAG = (%d) %s' % (len(tag), tag))
        print('RE-ENCRYPTION LENGTH = %d' % re_enc_length)

    from Const import SYM_KEY_DEFAULT_SIZE, SEED_LENGTH
    import struct

    # Create struct for seed, key and re-enc length to encrypt
    data = struct.pack('%ds%dsH' % (SEED_LENGTH, SYM_KEY_DEFAULT_SIZE), seed, k, re_enc_length)

    # Encrypt seed, key and number of re-encrypted bits using ABE with given public key and policy
    enc_data = encrypt_seed_key_len(data=data, pk_file=new_pk_file, policy=policy, debug=debug)

    # Add re-encryption parameters to ciphertext file
    add_re_enc_params(file=ciphertext_infile, enc_seed_key_len=enc_data, iv=iv, tag=tag, debug=debug)


def re_enc_ciphertext_bytes(ciphertext_infile=None, re_enc_length=None, debug=0):

    from Const import RE_ENC_LENGTH
    from Log import log
    import os.path

    # Check if the ciphertext is set
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        log('[ERROR] Re-encryption ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re-encryption ciphertext')
        raise Exception

    # If re-encryption length is not set, assign a default value
    if re_enc_length is None:
        re_enc_length = RE_ENC_LENGTH

    # Get ciphertext offset and length from the input file
    ciphertext_offset, ciphertext_length = get_ciphertext_info(ciphertext_infile, debug)

    # Apply punctured encryption and return re-encryption parameters
    return apply_punctured_enc(ciphertext_infile, ciphertext_offset, ciphertext_length, re_enc_length, debug)


def get_ciphertext_info(ciphertext_infile=None, debug=0):

    from Log import log
    import os.path

    # Check if the ciphertext is set
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        log('[ERROR] get_ciphertext_info ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_ciphertext_info ciphertext_infile')
        raise Exception

    # Get ciphertext offset and length from file
    with(open(ciphertext_infile, 'rb')) as fin:

        from Const import B, H, Q, IV_DEFAULT_SIZE
        import struct

        fin.seek(2 * B)
        n, k0, enc_key_length = struct.unpack('HHH', fin.read(3 * H))
        fin.seek(enc_key_length + IV_DEFAULT_SIZE * 2 + 5, 1)  # TODO PERCHé + 5 byte???
        ciphertext_length = struct.unpack('Q', fin.read(Q))[0]
        transf_ciphertext_length = int((int(ciphertext_length * 8 / (n - k0)) + 1) * n / 8)

        fin.seek(H, 1)
        ciphertext_offset = fin.tell()

        if debug:  # ONLY USE FOR DEBUG
            print('CIPHERTEXT OFFSET = %d' % ciphertext_offset)
            print('CIPHERTEXT LENGTH = %d' % transf_ciphertext_length)

    return ciphertext_offset, transf_ciphertext_length


def apply_punctured_enc(ciphertext_infile=None, ciphertext_offset=None, ciphertext_length=None, re_enc_length=None, debug=0):

    from Log import log
    import os.path

    # Check if the ciphertext is set
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        log('[ERROR] apply_punctured_enc ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_punctured_enc ciphertext_infile')
        raise Exception

    # Check if ciphertext_offset is set
    if ciphertext_offset is None:
        log('[ERROR] apply_punctured_enc ciphertext_offset exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_punctured_enc ciphertext_offset')
        raise Exception

    # Check if ciphertext_length is set
    if ciphertext_offset is None:
        log('[ERROR] apply_punctured_enc ciphertext_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_punctured_enc ciphertext_length')
        raise Exception

    from Const import RE_ENC_MIN_LENGTH, RE_ENC_LENGTH
    from FunctionUtils import clamp

    # Set default value for re-encryption length if it is not set
    if re_enc_length is None:
        re_enc_length = RE_ENC_LENGTH

    # Clamp the number of bits to re-encrypt between RE_ENC_MIN_LENGTH and ciphertext length
    re_enc_length = clamp(re_enc_length, RE_ENC_MIN_LENGTH, ciphertext_length, debug)

    if re_enc_length is None:
        log('[ERROR] Clamping value exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in clamp')
        raise Exception

    if debug:  # ONLY USE FOR DEBUG
        print('RE_ENC_LENGTH = %d' % re_enc_length)

    seed, k, iv, tag = re_enc_bytes(ciphertext_infile, ciphertext_offset, ciphertext_length, re_enc_length, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('SEED = (%d) %s' % (len(seed), seed))
        print('KEY = (%d) %s' % (len(k), k))
        print('IV = (%d) %s' % (len(iv), iv))
        print('TAG = (%d) %s' % (len(tag), tag))

    return seed, k, iv, tag, re_enc_length


def re_enc_bytes(ciphertext_infile=None, ciphertext_offset=None, ciphertext_length=None, re_enc_length=None, debug=0):

    from Log import log
    import os.path

    # Check if the ciphertext is set
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        log('[ERROR] re_enc_bytes ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_enc_bytes ciphertext_infile')
        raise Exception

    # Check if ciphertext_offset is set
    if ciphertext_offset is None:
        log('[ERROR] re_enc_bytes ciphertext_offset exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_enc_bytes ciphertext_offset')
        raise Exception

    # Check if ciphertext_length is set
    if ciphertext_offset is None:
        log('[ERROR] re_enc_bytes ciphertext_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in re_enc_bytes ciphertext_length')
        raise Exception

    from Const import IV_DEFAULT_SIZE, SEED_LENGTH
    from SymEncPrimitives import sym_key_gen, generate_iv

    # Re-encryption symmetric key
    k = sym_key_gen(sym_key_size=SEED_LENGTH, debug=debug)

    # Create the IV for  symmetric encryption
    iv = generate_iv(IV_DEFAULT_SIZE)

    # Define variables
    seed = None

    from binascii import hexlify

    if debug:  # ONLY USE FOR DEBUG
        print('RE-ENCRYPTION SYM KEY = (%d) %s -> %s' % (len(k), k, hexlify(k).decode()))
        print('RE-ENCRYPTION IV = (%d) %s -> %s' % (len(iv), iv, hexlify(iv).decode()))

    if re_enc_length < ciphertext_length:  # Apply punctured encryption

        from FunctionUtils import generate_random_string

        # Generate a pseudorandom seed
        seed = generate_random_string(length=SEED_LENGTH, debug=debug)

        # Get random bytes to re-encrypt and generator seed
        bytes_to_re_enc, re_enc_indexes = get_bytes_to_re_enc(ciphertext_infile, ciphertext_offset, ciphertext_length,
                                                              re_enc_length, seed, debug)

        if debug:  # ONLY USE FOR DEBUG
            print('SEED = (%d) %s' % (len(seed), seed))
            print('BYTES TO RE-ENCRYPT = (%d) %s' % (len(bytes_to_re_enc), bytes_to_re_enc))
            print('INDEX TO RE-ENCRYPT = (%d) %s' % (len(re_enc_indexes), re_enc_indexes))

        from SymEncPrimitives import sym_encrypt

        # Re-encrypt ciphertext
        re_enc_ciphertext, tag = sym_encrypt(key=k, iv=iv, plaintext=bytes_to_re_enc, associated_data=None, debug=debug)

        if debug:  # ONLY USE FOR DEBUG
            print('RE-ENCRYPTED CIPHERTEXT = (%d) %s -> %s' % (len(re_enc_ciphertext), re_enc_ciphertext,
                                                               hexlify(re_enc_ciphertext).decode()))

        replace_re_enc_bytes(ciphertext_infile, re_enc_ciphertext, re_enc_indexes, debug)

        print(ciphertext_infile)

        # Update number of re-encryptions
        with(open(ciphertext_infile, 'rb+')) as fin:

            from Const import H
            import struct

            # Retrieve previous re-encryptions number from file
            fin.seek(ciphertext_offset + ciphertext_length)
            print(fin.tell())
            re_enc_num = struct.unpack('H', fin.read(H))[0]

            if debug:  # ONLY USE FOR DEBUG
                print('RE-ENCRYPTION NUM = %d' % re_enc_num)

            # Update number of re-encryptions
            re_enc_num += 1

            if debug:  # ONLY USE FOR DEBUG
                print('UPDATE RE-ENCRYPTION NUM = %d' % re_enc_num)

            # Overwrite re-encryptions number
            fin.seek(- H, 1)
            fin.write(struct.pack('H', re_enc_num))

    else:  # Re-encryption of the whole ciphertext

        with(open(ciphertext_infile, 'rb+')) as fin:

            # Retrieve ciphertext to re-encrypt
            fin.seek(ciphertext_offset)

            from Const import H
            import struct

            ciphertext, re_enc_num = struct.unpack('%dsH', fin.read(ciphertext_length + H))

            if debug:  # ONLY USE FOR DEBUG
                print('CIPHERTEXT = (%d) %s -> %s' % (len(ciphertext), ciphertext, hexlify(ciphertext).decode()))
                print('RE-ENCRYPTION NUM = %d' % re_enc_num)

            from SymEncPrimitives import sym_encrypt

            # Re-encrypt ciphertext
            re_enc_ciphertext, tag = sym_encrypt(key=k, iv=iv, plaintext=ciphertext, associated_data=None, debug=debug)

            if debug:  # ONLY USE FOR DEBUG
                print('RE-ENC CIPHERTEXT LENGTH = %d vs CIPHERTEXT LENGTH = %d' % (len(re_enc_ciphertext),
                                                                                   ciphertext_length))

            # Check if lengths are incompatible
            if len(re_enc_ciphertext) != ciphertext_length:
                if debug:  # ONLY USE FOR DEBUG
                    print('[ERROR] Re-encryption and original lengths incompatibility')
                raise Exception

            # Update number of re-encryptions
            re_enc_num += 1

            if debug:  # ONLY USE FOR DEBUG
                print('RE-ENCRYPTED CIPHERTEXT = (%d) %s -> %s' % (len(re_enc_ciphertext), re_enc_ciphertext,
                                                                   hexlify(re_enc_ciphertext).decode()))
                print('UPDATE RE-ENCRYPTION NUM = %d' % re_enc_num)

            # Create struct with data to write
            data_to_write = struct.pack('%dsH' % len(re_enc_ciphertext), re_enc_ciphertext, re_enc_num)

            if debug:  # ONLY USE FOR DEBUG
                print('DATA TO WRITE ON FILE = %s' % data_to_write)

            # Overwrite previous ciphertext and re-encryptions number
            fin.seek(- len(re_enc_ciphertext) - H, 1)
            fin.write(data_to_write)

    return seed, k, iv, tag


def get_bytes_to_re_enc(ciphertext_infile=None, ciphertext_offset=None, ciphertext_length=None, re_enc_length=None, seed=None, debug=0):
    """ Puncture the ciphertext selecting a given number of bits to re-encrypt
    :param ciphertext_infile: the text to puncture
    :param ciphertext_offset: offset of starting ciphertext byte in the file
    :param ciphertext_length: length of ciphertext bytes
    :param re_enc_length: number of bits to select
    :param seed: seed for random
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the seed to randomly generate bits positions, positions of bits to re-encrypt, bits to re-encrypt
    """

    from Log import log
    import os.path

    # Check if the ciphertext input file is set and it exists
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        log('[ERROR] get_bytes_to_re_enc ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_bytes_to_re_enc ciphertext')
        raise Exception

    # Check if the ciphertext_offset is set
    if ciphertext_offset is None:
        log('[ERROR] get_bytes_to_re_enc ciphertext_offset exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_bytes_to_re_enc ciphertext_offset')
        raise Exception

    # Check if the ciphertext_length is set
    if ciphertext_length is None:
        log('[ERROR] get_bytes_to_re_enc ciphertext_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_bytes_to_re_enc ciphertext_length')
        raise Exception

    # Check if the re_enc_length is set
    if re_enc_length is None:
        log('[ERROR] get_bytes_to_re_enc re_enc_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_bytes_to_re_enc re_enc_length')
        raise Exception

    if debug:  # ONLY USE FOR DEBUG
        print('RE-ENCRYPTION SEED = (%d) %s' % (len(seed), seed))

    # Generate a pseudorandom set of indexes to re-encrypt
    re_enc_indexes = ind(seed, re_enc_length, range(ciphertext_offset, ciphertext_offset + ciphertext_length))

    if debug:  # ONLY USE FOR DEBUG
        print('INDEXES =', re_enc_indexes)

    re_enc_indexes.sort()

    if debug:  # ONLY USE FOR DEBUG
        print('SORTED INDEXES =', re_enc_indexes)

    bytes_to_re_enc = ''

    # Get bytes to re-encrypt
    with(open(ciphertext_infile, 'rb')) as fin:

        import struct
        from binascii import hexlify

        for index in re_enc_indexes:

            # Retrieve specific byte
            fin.seek(index)
            byte = struct.unpack('s', fin.read(1))[0]

            if debug:  # ONLY USE FOR DEBUG
                print('BYTE TO RE-ENCRYPT =', byte)

            # Append to the string
            bytes_to_re_enc += hexlify(byte).decode()

    from binascii import unhexlify

    if debug:  # ONLY USE FOR DEBUG
        print('BYTES HEX = %s -> %s' % (bytes_to_re_enc, unhexlify(bytes_to_re_enc)))

    return unhexlify(bytes_to_re_enc), re_enc_indexes

    # # Get ciphertext length in bits from hex representation
    # ciphertext_length = len(ciphertext) * 4
    #
    # # Set default values
    # seed = None
    # bits_to_re_enc = ''
    # re_enc_indexes = [i for i in range(ciphertext_length)]
    #
    # # Generate random positions to re-encrypt only if re-encryption length is less than ciphertext's
    # if re_enc_length < ciphertext_length:
    #
    #     # Generate a pseudorandom seed
    #     seed = generate_random_string(length=SEED_LENGTH, debug=debug)
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('SEED = (%d) %s' % (len(seed), seed))
    #
    #     # Generate a pseudorandom set of indexes to re-encrypt
    #     re_enc_indexes = ind(seed, re_enc_length, range(ciphertext_length))
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('INDEXES =', re_enc_indexes)
    #
    #     re_enc_indexes.sort()
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('SORTED INDEXES =', re_enc_indexes)
    #
    #     # Converts ciphertext in bits string
    #     ciphertext_bits = bin(int(ciphertext, 16))[2:]
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('CIPHERTEXT IN BITS (%d) = %s' % (len(ciphertext_bits), ciphertext_bits))
    #
    #     # Check if trailing zeros have been cut
    #     diff_bits_num = ciphertext_length - len(ciphertext_bits)
    #
    #     if debug:
    #         print('%d trailing zeros have been cut in bits_to_re_enc' % diff_bits_num)
    #
    #     # Fill cut trailing zeros
    #     if diff_bits_num > 0:
    #         ciphertext_bits = '0' * diff_bits_num + ciphertext_bits
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('CIPHERTEXT IN BITS (%d) = %s' % (len(ciphertext_bits), ciphertext_bits))
    #
    #     # Create a string consists of the bits in the randomly generated positions
    #     for index in re_enc_indexes:
    #
    #         if debug:  # ONLY USE FOR DEBUG
    #             print('BIT #%d IN CIPHERTEXT = %d' % (index, int(ciphertext_bits[index])))
    #
    #         bits_to_re_enc += ciphertext_bits[index]
    #
    # else:
    #
    #     log('[WARNING] Re-encrypting full ciphertext')
    #
    #     if debug:
    #         print('[WARNING] Re-encrypting full ciphertext')
    #
    #     # Converts ciphertext in bits string
    #     bits_to_re_enc = bin(int(ciphertext, 16))[2:]
    #
    # # Check if trailing zeros have been cut
    # diff_bits_num = re_enc_length - len(bits_to_re_enc)
    #
    # if debug:
    #     print('%d trailing zeros have been cut in bits_to_re_enc' % diff_bits_num)
    #
    # # Fill cut trailing zeros
    # if diff_bits_num > 0:
    #     bits_to_re_enc = '0' * diff_bits_num + bits_to_re_enc
    #
    # return seed, re_enc_indexes, bits_to_re_enc


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


def replace_re_enc_bytes(ciphertext_infile=None, re_encr_bytes=None, re_enc_indexes=None, debug=0):
    """
    Replace re-encrypted bits in the ciphertext
    :param ciphertext_infile: the file whose bytes must be replaced
    :param re_encr_bytes: re-encrypted bytes
    :param re_enc_indexes: positions of bits to replace in the ciphertext
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: replaced ciphertext as hex
    """

    from Log import log
    import os.path

    # Check if ciphertext input file is set and it exists
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        log('[ERROR] replace_re_enc_bytes ciphertext exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bytes ciphertext')
        raise Exception

    # Check if re_enc_bytes is set
    if re_encr_bytes is None:
        log('[ERROR] replace_re_enc_bytes re_encr_bytes exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bytes re_encr_bytes')
        raise Exception

    # Check if re_enc_indexes is set
    if re_enc_indexes is None:
        log('[ERROR] replace_re_enc_bits re_enc_indexes exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in replace_re_enc_bits re_enc_indexes')
        raise Exception

    # Overwrite bytes in the specified file
    with(open(ciphertext_infile, 'rb+')) as fout:

        import struct

        for i in range(len(re_enc_indexes)):

            if debug:  # ONLY USE FOR DEBUG
                print('#%d: REPLACING BYTE IN POSITION %d WITH BYTE %s' % (i, re_enc_indexes[i], re_encr_bytes[i:i+1]))

            # Retrieve byte position in the file
            fout.seek(re_enc_indexes[i])

            # Overwrite byte with re-encrypted one
            fout.write(struct.pack('1s', re_encr_bytes[i:i+1]))

    # # Check if trailing zeros have been cut in re_enc_bits
    # diff_re_enc_bits_num = re_enc_length - len(re_enc_bits)
    #
    # if debug:
    #     print('%d trailing zeros have been cut in re_enc_bits' % diff_re_enc_bits_num)
    #
    # # Fill cut trailing zeros
    # if diff_re_enc_bits_num > 0:
    #     re_enc_bits = '0' * diff_re_enc_bits_num + re_enc_bits
    #
    # if debug:
    #     print('RE-ENCRYPTED BITS = (%d) %s' % (len(re_enc_bits), re_enc_bits))
    #
    # # Convert the ciphertext in bits
    # ciphertext_bits = bin(int(ciphertext, 16))[2:]
    #
    # if debug:
    #     print('CIPHERTEXT BITS = (%d) %s' % (len(ciphertext_bits), ciphertext_bits))
    #
    # # Check if trailing zeros have been cut in ciphertext
    # diff_ciphertext_bits_num = len(ciphertext)*4 - len(ciphertext_bits)
    #
    # if debug:
    #     print('%d trailing zeros have been cut in ciphertext_bits' % diff_ciphertext_bits_num)
    #
    # # Fill cut trailing zeros
    # if diff_ciphertext_bits_num > 0:
    #     ciphertext_bits = '0' * diff_ciphertext_bits_num + ciphertext_bits
    #
    # if debug:
    #     print('CIPHERTEXT BITS = (%d) %s' % (len(ciphertext_bits), ciphertext_bits))
    #
    # # Convert ciphertext to a list of bits
    # ciphertext_bits = list(ciphertext_bits)
    #
    # if debug:
    #     print('re_enc_indexes = ', len(re_enc_indexes))
    #     print('re_enc_bits = ', len(re_enc_bits))
    #     print('re_enc_length = ', re_enc_length)
    #     print('ciphertext_bits = (%d) %s' % (len(ciphertext_bits), ciphertext_bits))
    #
    # # Replace original bits with re-encrypted ones
    # for i in range(len(re_enc_indexes)):
    #     if ciphertext_bits[re_enc_indexes[i]] != re_enc_bits[i]:
    #         print('REPLACING IN POSITION %d %s -> %s' % (re_enc_indexes[i], ciphertext_bits[re_enc_indexes[i]],
    #                                                      re_enc_bits[i]))
    #         ciphertext_bits[re_enc_indexes[i]] = re_enc_bits[i]
    #
    # # Convert the replaced ciphertext to a string
    # re_enc_ciphertext_bits = ''.join(ciphertext_bits)
    #
    # if debug:
    #     print('RE-ENCRYPTED CIPHERTEXT BITS = (%d) %s' % (len(re_enc_ciphertext_bits), re_enc_ciphertext_bits))
    #
    # return hex(int(re_enc_ciphertext_bits, 2))[2:]


def add_re_enc_params(file=None, enc_seed_key_len=None, iv=None, tag=None, debug=0):
    """
    Update the given file adding all the parameters required to decrypt the re-encryption process
    :param file: file to update
    :param enc_seed_key_len: encrypted seed, key and re-encryption length (first element to randomly generate a set of
                             're-encryption length' (third element) bytes positions for punctured encryption, second
                             element used in the symmetric re-encryption
    :param iv: iv used in the cipher
    :param tag: tag used in the cipher
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    from Log import log
    import os.path

    # Check if file is set and exists
    if file is None or not os.path.isfile(file):
        log('[ERROR] add_re_enc_params file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in add_re_enc_params file')
        raise Exception

    # Check if enc_seed_key_len is set
    if enc_seed_key_len is None:
        log('[ERROR] add_re_enc_params enc_seed_key_len exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in add_re_enc_params enc_seed_key_len')
        raise Exception

    # Check if iv is set
    if iv is None:
        log('[ERROR] add_re_enc_params iv exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in add_re_enc_params iv')
        raise Exception

    # Check if tag is set
    if tag is None:
        log('[ERROR] add_re_enc_params tag exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in add_re_enc_params tag')
        raise Exception

    from Const import IV_DEFAULT_SIZE
    import struct

    # Create struct of data to append to the ciphertext file
    struct_format = '%ds%ds%dsH' % (len(enc_seed_key_len), IV_DEFAULT_SIZE, IV_DEFAULT_SIZE)
    data_to_append = struct.pack(struct_format, enc_seed_key_len, iv, tag, len(enc_seed_key_len))

    # Append data bytes to the file
    with(open(file, 'ab')) as fout:

        fout.write(data_to_append)

        # # Check if EOF has been reached
        # if re_enc == '':
        #
        #     fin.seek(-transf_ciphertext_length, 1)
        #
        #     struct_format = '%dsBH%ds%ds%ds' % (len(new_ciphertext), len(enc_seed_key), len(iv), len(tag))
        #
        #     if debug:
        #         print('STRING FORMAT FOR FIRST RE-ENC STRUCT = ', struct_format)
        #
        #     import struct
        #
        #     # Create struct with all re-encryption data
        #     data_to_write = struct.pack(struct_format, new_ciphertext, 1, len(enc_seed_key), enc_seed_key, iv, tag)
        #
        # else:
        #
        #     prev_re_enc_num = struct.unpack('B', re_enc)[0]
        #
        #     for i in range(prev_re_enc_num):
        #
        #         enc_seed_key_len = struct.unpack('H', fin.read(H))[0]
        #         enc_s_k, iv, tag = struct.unpack('%ds%ds%ds' % (enc_seed_key_len, IV_DEFAULT_SIZE, IV_DEFAULT_SIZE),
        #                                          fin.read(enc_seed_key_len + IV_DEFAULT_SIZE + IV_DEFAULT_SIZE))
        #
        #
        #     # Create string format for struct
        #     struct_format = '%ds%ds%dsQ%ds' % (enc_key_length, len(iv), len(tag), len(transf_ciphertext))
        #
        #     if debug:
        #         print('STRING FORMAT FOR STRUCT = ', struct_format)
        #
        #     import struct
        #
        #     # Create struct with all data
        #     data_to_write = struct.pack(struct_format, version, n, k0, enc_key_length, enc_key, iv, tag, ciphertext_length,
        #                                 transf_ciphertext)
        #
        #     if debug:  # ONLY USE FOR DEBUG
        #         print('DATA TO WRITE ON FILE =', data_to_write)
        #
        # from FunctionUtils import write_bytes_on_file
        #
        # # Write data bytes on given outfile
        # write_bytes_on_file(file, data_to_write, debug)


def encrypt_seed_key_len(data=None, pk_file=None, policy=None, debug=0):
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

    from FunctionUtils import write_bytes_on_file, read_bytes_from_file

    # Write data on temporary file
    write_bytes_on_file(temp_file, data, debug)

    from ABEPrimitives import encrypt

    # Encrypt temp file with ABE
    encrypt(enc_outfile=enc_temp_file, pk_file=pk_file, plaintext_file=temp_file, policy=policy, debug=debug)

    enc_data = read_bytes_from_file(enc_temp_file, debug)

    if debug:  # ONLY USE FOR DEBUG
        from binascii import hexlify
        print('ENCRYPTED SEED AND KEY = (%d) %s -> %s' % (len(enc_data), enc_data, hexlify(enc_data)))

    # Delete temporary files
    #os.remove(temp_file)
    #os.remove(enc_temp_file)

    return enc_data


def re_decrypt(ciphertext_infile=None, pk_file=None, sk_file=None, debug=0):
    """
    Remove the last re-encryption applied to the given ciphertext file
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

    decrypt_re_encryption(re_enc_file=ciphertext_infile, pk_file=pk_file, sk_file=sk_file, debug=debug)

    # import json
    #
    # # Read data from ciphertext file
    # with(open(ciphertext_infile, 'r')) as fin:
    #     data = json.load(fin)
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('DATA READ FROM CIPHERTEXT = ', data)
    #
    # # Extract last re-encryption parameters and remove them from ciphertext file
    # re_enc_params = data['re-encryptions'].pop()
    #
    # # Update ciphertext after decrypting the re-encryption
    # data['data']['ciphertext'] = decrypt_re_encryption(enc_file_content=data, re_enc_params=re_enc_params,
    #                                                    pk_file=pk_file, sk_file=sk_file, debug=debug)
    #
    # with(open(dec_outfile, 'w')) as fout:
    #     json.dump(data, fout)


def decrypt_re_encryption(re_enc_file=None, pk_file=None, sk_file=None, debug=0):
    """
    Remove the re-encryption from the ciphertext
    :param re_enc_file: encrypted file to decrypt the re-encryption
    :param pk_file: ABE public key to decrypt re-encryption parameters
    :param sk_file: ABE secret key to decrypt re-encryption parameters
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: ciphertext without the given re-encryption
    """

    from Log import log
    import os.path

    # Check if re_enc_file is set and it exists
    if re_enc_file is None or not os.path.isfile(re_enc_file):
        log('[ERROR] decrypt_re_encryption re_enc_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_re_encryption re_enc_file')
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
    enc_seed_key, iv, tag = get_re_enc_params(re_enc_file, debug)

    # Decrypt seed, key and re_enc_length with ABE using given public and private keys
    seed, key, re_enc_length = decrypt_seed_key(enc_seed_key=enc_seed_key, pk_file=pk_file, sk_file=sk_file,
                                                debug=debug)

    # Remove re-encryption from the ciphertext
    remove_re_enc(ciphertext_infile=re_enc_file, seed=seed, k=key, iv=iv, tag=tag, re_enc_length=re_enc_length,
                  debug=debug)


def get_re_enc_params(file=None, debug=0):

    from Log import log
    import os.path

    # Check if file is set and it exists
    if file is None or not os.path.isfile(file):
        log('[ERROR] get_re_enc_params file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_re_enc_params file')
        raise Exception

    from Const import H, IV_DEFAULT_SIZE
    import struct

    # Retrieve re-encryption params from the file
    with(open(file, 'rb+')) as fin:

        # Read length of encrypted (seed, key, re-encryption length)
        fin.seek(- H, 2)
        enc_seed_key_len_length = struct.unpack('H', fin.read(H))[0]

        if debug:  # ONLY USE FOR DEBUG
            print('ENC SEED-KEY-LEN LENGTH = %d' % enc_seed_key_len_length)

        # Read re-enc params from file
        fin.seek(- enc_seed_key_len_length - H - 2 * IV_DEFAULT_SIZE - 1, 2) # TODO PERCHé -1???
        struct_format = '%ds%ds%ds' % (enc_seed_key_len_length, IV_DEFAULT_SIZE, IV_DEFAULT_SIZE)
        enc_seed_key_len, iv, tag = struct.unpack(struct_format, fin.read(enc_seed_key_len_length + 2 * IV_DEFAULT_SIZE))

        if debug:  # ONLY USE FOR DEBUG
            print('ENC SEED-KEY-LEN = (%d) %s' % (len(enc_seed_key_len), enc_seed_key_len))
            print('IV = (%d) %s' % (len(iv), iv))
            print('TAG = (%d) %s' % (len(tag), tag))

        # Remove re-encryption params from the file
        fin.seek(- enc_seed_key_len_length - H - 2 * IV_DEFAULT_SIZE, 2)
        fin.truncate()

    return enc_seed_key_len, iv, tag


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
    enc_temp_file = 'enc_temp'
    dec_temp_file = 'dec_' + enc_temp_file

    with(open(enc_temp_file, 'wb')) as fout:
        fout.write(enc_seed_key)

    from ABEPrimitives import decrypt

    # Decrypt with ABE using given public key and secret key
    decrypt(dec_outfile=dec_temp_file, pk_file=pk_file, sk_file=sk_file, ciphertext_file=enc_temp_file, debug=debug)

    from Const import H, SYM_KEY_DEFAULT_SIZE, SEED_LENGTH
    import struct

    with(open(dec_temp_file, 'rb')) as fin:

        # Get decrypted values from decryption output file
        seed, key, re_enc_length = struct.unpack('%ds%dsH' % (SEED_LENGTH, SYM_KEY_DEFAULT_SIZE),
                                                 fin.read(SEED_LENGTH + SYM_KEY_DEFAULT_SIZE + H))

    if debug:  # ONLY USE FOR DEBUG
        print('DECRYPTED SEED = (%d) %s' % (len(seed), seed))
        print('DECRYPTED KEY = (%d) %s' % (len(key), key))
        print('DECRYPTED RE_ENC_LENGTH = %d' % re_enc_length)

    # Delete temporary files
    os.remove(dec_temp_file)

    return seed, key, re_enc_length


def remove_re_enc(ciphertext_infile=None, seed=None, k=None, re_enc_length=None, iv=None, tag=None, debug=0):
    """

    :param ciphertext_infile:
    :param seed:
    :param k:
    :param re_enc_length:
    :param iv:
    :param tag:
    :param debug:
    :return:
    """

    from Log import log
    import os.path

    # Check if ciphertext infile is set and it exists
    if ciphertext_infile is None or not os.path.isfile(ciphertext_infile):
        log('[ERROR] remove_re_enc ciphertext infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_enc ciphertext infile')
        raise Exception

    # Check if key is set
    if k is None:
        log('[ERROR] remove_re_enc key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_enc key')
        raise Exception

    # Get ciphertext offset and length from the file
    ciphertext_offset, ciphertext_length = get_ciphertext_info(ciphertext_infile, debug)

    # Check if full ciphertext needs to be decrypted
    if seed is None:  # Full re-encryption

        # Read transformed ciphertext from file
        with(open(ciphertext_infile, 'rb+')) as fin:

            from Const import H
            import struct

            # Retrieve ciphertext to re-encrypt
            fin.seek(ciphertext_offset)
            ciphertext, re_enc_num = struct.unpack('%dsH', fin.read(ciphertext_length + H))

            if debug:  # ONLY USE FOR DEBUG
                from binascii import hexlify
                print('CIPHERTEXT = (%d) %s -> %s' % (len(ciphertext), ciphertext, hexlify(ciphertext).decode()))
                print('RE-ENCRYPTION NUM = %d' % re_enc_num)

            from SymEncPrimitives import sym_encrypt

            # Re-encrypt ciphertext
            re_enc_ciphertext, tag = sym_encrypt(key=k, iv=iv, plaintext=ciphertext, associated_data=None, debug=debug)

            if debug:  # ONLY USE FOR DEBUG
                print('RE-ENC CIPHERTEXT LENGTH = %d vs CIPHERTEXT LENGTH = %d' % (len(re_enc_ciphertext),
                                                                                   ciphertext_length))

            # Check if lengths are incompatible
            if len(re_enc_ciphertext) != ciphertext_length:
                if debug:  # ONLY USE FOR DEBUG
                    print('[ERROR] Re-encryption and original lengths incompatibility')
                raise Exception

            # Update number of re-encryptions
            re_enc_num -= 1

            if debug:  # ONLY USE FOR DEBUG
                from binascii import hexlify
                print('RE-ENCRYPTED CIPHERTEXT = (%d) %s -> %s' % (len(re_enc_ciphertext), re_enc_ciphertext,
                                                                   hexlify(re_enc_ciphertext).decode()))
                print('UPDATE RE-ENCRYPTION NUM = %d' % re_enc_num)

            # Create struct with data to write
            data_to_write = struct.pack('%dsH' % len(re_enc_ciphertext), re_enc_ciphertext, re_enc_num)

            if debug:  # ONLY USE FOR DEBUG
                print('DATA TO WRITE ON FILE = %s' % data_to_write)

            # Overwrite previous ciphertext and re-encryptions number
            fin.seek(- len(re_enc_ciphertext) - H, 1)
            fin.write(data_to_write)

    else:  # Apply punctured encryption

        # Get random re-encrypted bytes to decrypt
        bytes_to_re_enc, re_enc_indexes = get_bytes_to_re_enc(ciphertext_infile, ciphertext_offset, ciphertext_length,
                                                              re_enc_length, seed, debug)

        if debug:  # ONLY USE FOR DEBUG
            print('SEED = (%d) %s' % (len(seed), seed))
            print('RE-ENCRYPTED BYTES TO DECRYPT = (%d) %s' % (len(bytes_to_re_enc), bytes_to_re_enc))
            print('RE-ENCRYPTED INDEXES TO DECRYPT = (%d) %s' % (len(re_enc_indexes), re_enc_indexes))

        from SymEncPrimitives import sym_decrypt

        # Re-encrypt ciphertext
        dec_ciphertext = sym_decrypt(key=k, associated_data=None, iv=iv, ciphertext=bytes_to_re_enc, tag=tag,
                                     debug=debug)

        if debug:  # ONLY USE FOR DEBUG
            from binascii import hexlify
            print('DECRYPTED CIPHERTEXT = (%d) %s -> %s' % (len(dec_ciphertext), dec_ciphertext,
                                                            hexlify(dec_ciphertext).decode()))

        replace_re_enc_bytes(ciphertext_infile, dec_ciphertext, re_enc_indexes, debug)

        # Update number of re-encryptions
        with(open(ciphertext_infile, 'rb+')) as fin:

            from Const import H
            import struct

            # Retrieve previous re-encryptions number from file
            fin.seek(ciphertext_offset + ciphertext_length)
            re_enc_num = struct.unpack('H', fin.read(H))[0]

            if debug:  # ONLY USE FOR DEBUG
                print('RE-ENCRYPTION NUM = %d' % re_enc_num)

            # Update number of re-encryptions
            re_enc_num -= 1

            if debug:  # ONLY USE FOR DEBUG
                print('UPDATE RE-ENCRYPTION NUM = %d' % re_enc_num)

            # Overwrite re-encryptions number
            fin.seek(- H, 1)
            fin.write(struct.pack('H', re_enc_num))

    #     # Set default value for number of re-encrypted bits
    #     if re_enc_length is None:
    #
    #         from Const import RE_ENC_LENGTH
    #
    #         re_enc_length = RE_ENC_LENGTH*8
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('RE_ENC_LENGTH =', re_enc_length)
    #
    #     from binascii import unhexlify
    #
    #     # Get positions of bits to decrypt
    #     bits_to_dec_positions = ind(s=unhexlify(seed), l=re_enc_length, dataset=range(ciphertext_length), debug=debug)
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('INDEXES =', bits_to_dec_positions)
    #
    #     bits_to_dec_positions.sort()
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('SORTED INDEXES =', bits_to_dec_positions)
    #
    #     # Converts ciphertext in bits string
    #     ciphertext_bits = bin(int(ciphertext, 16))[2:]
    #
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('CIPHERTEXT IN BITS (%d) = %s' % (len(ciphertext_bits), ciphertext_bits))
    #
    #     # Check if trailing zeros have been cut
    #     diff_bits_num = ciphertext_length - len(ciphertext_bits)
    #
    #     if debug:
    #         print('%d trailing zeros have been cut in bits_to_re_enc' % diff_bits_num)
    #
    #     # Fill cut trailing zeros
    #     if diff_bits_num > 0:
    #         ciphertext_bits = '0' * diff_bits_num + ciphertext_bits
    #
    #     bits_to_dec = ''
    #
    #     # Create a string consists of the bits in the randomly generated positions
    #     for index in bits_to_dec_positions:
    #
    #         if debug:  # ONLY USE FOR DEBUG
    #             print('BIT #%d IN CIPHERTEXT = %d' % (index, int(ciphertext_bits[index])))
    #
    #         bits_to_dec += ciphertext_bits[index]
    #
    # # Check if trailing zeros have been cut
    # diff_bits_num = re_enc_length - len(bits_to_dec)
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('%d trailing zeros have been cut in bits_to_re_enc' % diff_bits_num)
    #
    # # Fill cut trailing zeros
    # if diff_bits_num > 0:
    #     bits_to_dec = '0' * diff_bits_num + bits_to_dec
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('BITS TO DECRYPT = (%d) %s -> %s' % (len(bits_to_dec), bits_to_dec, hex(int(bits_to_dec, 2))))
    #
    # # Convert bits to hex for decryption
    # bytes_to_dec = bytes.fromhex(hex(int(bits_to_dec, 2))[2:].zfill(int(len(bits_to_dec)/4)))
    #
    # from binascii import hexlify
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('HEX TO DECRYPT = (%d) %s -> %s' % (len(bytes_to_dec), bytes_to_dec, hexlify(bytes_to_dec)))
    #
    # from SymEncPrimitives import sym_decrypt
    #
    # # Decrypt re-encrypted bits
    # dec_bytes = sym_decrypt(key=key, associated_data=None, iv=iv, ciphertext=bytes_to_dec, tag=tag, debug=debug)
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('DECRYPTED BYTES = (%d) %s -> %s' % (len(dec_bytes), dec_bytes, hexlify(dec_bytes).decode()))
    #
    # # Convert decryption result from bytes to bin
    # dec_bits = bin(int(hexlify(dec_bytes).decode(), 16))[2:]
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('DECRYPTED BITS = (%d) %s' % (len(dec_bits), dec_bits))
    #
    # # Replace decrypted bits in the ciphertext
    # dec_re_enc_ciphertext = replace_re_enc_bits(ciphertext=ciphertext, re_enc_bits=dec_bits,
    #                                             re_enc_indexes=bits_to_dec_positions, re_enc_length=len(bits_to_dec),
    #                                             debug=debug)
    #
    # if debug:  # ONLY USE FOR DEBUG
    #     print('DECRYPTED CIPHERTEXT = (%d) %s' % (len(dec_re_enc_ciphertext), dec_re_enc_ciphertext))
    #
    # return dec_re_enc_ciphertext
