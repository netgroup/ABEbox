"""
This file contains all functions used during decryption process. To perform this procedure, firstly, all re-encryption
operations have to be decrypted. Next the resulting ciphertext needs to be anti-transformed and, finally, last hybrid
encryption has to be decrypted.
"""

from crypto.Const import AONT_DEFAULT_ENCODING, AONT_DEFAULT_N, AONT_DEFAULT_K0, OUTPUT_PATH


def decrypt_file(ciphertext_infile=None, pk_files=None, sk_files=None, debug=None):
    """
    Decrypt the ciphertext input file. This file contains encrypted plaintext and multiple re-encryption operations. So,
    the first step is remove all the re-encryptions, then anti-transform the resulting ciphertext and finally decrypt
    the anti-transformed ciphertext.
    :param ciphertext_infile: file to decrypt
    :param pk_files: public keys set used during re-encryptions
    :param sk_files: secret keys set used to remove re-encryptions
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging
    import os.path

    # Check if ciphertext_infile is set and it exists
    if ciphertext_infile is None or not os.path.exists(ciphertext_infile):
        logging.error('decrypt_file ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_file ciphertext_infile')
        raise Exception

    # Check if pk_files is set
    if pk_files is None:
        logging.error('decrypt_file pk_files exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_file pk_files')
        raise Exception

    # Check if each element of the pk_files exists
    for pk_file in pk_files:
        if not os.path.exists(pk_file):
            logging.error('decrypt_file pk_files element exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in decrypt_file pk_files element')
            raise Exception

    # Check if sk_files is set
    if sk_files is None:
        logging.error('decrypt_file sk_files exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_file sk_files')
        raise Exception

    # Check if each element of the sk_files exists
    for sk_file in sk_files:
        if not os.path.exists(sk_file):
            logging.error('decrypt_file sk_files element exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in decrypt_file sk_files element')
            raise Exception

    # Remove re-encryptions with ABE using given public and secret keys
    remove_re_encryptions(ciphertext_infile, pk_files, sk_files, debug)

    # Create output plaintext file
    path_split = str(ciphertext_infile).rsplit('/', 1)
    plaintext_outfile = OUTPUT_PATH + '/dec_' + path_split[1]

    # Decrypt ciphertext file to get plaintext
    decrypt_ciphertext(ciphertext_infile, plaintext_outfile, pk_files[0], sk_files[0], debug)


def remove_re_encryptions(infile=None, pk_files=None, sk_files=None, debug=0):
    """
    Decrypt all the re-encryptions applied to the ciphertext.
    :param infile: file to decrypt
    :param pk_files: public keys set used during re-encryptions
    :param sk_files: secret keys set used to remove re-encryptions
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging
    import os.path

    # Check if infile is set and it exists
    if infile is None or not os.path.exists(infile):
        logging.error('remove_re_encryptions infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_encryptions infile')
        raise Exception

    # Check if pk_files is set
    if pk_files is None:
        logging.error('remove_re_encryptions pk_files exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_encryptions pk_files')
        raise Exception

    # Check if each element of the pk_files exists
    for pk_file in pk_files:
        if not os.path.exists(pk_file):
            logging.error('remove_re_encryptions pk_files element exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in remove_re_encryptions pk_files element')
            raise Exception

    # Check if sk_files is set
    if sk_files is None:
        logging.error('remove_re_encryptions sk_files exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_encryptions sk_files')
        raise Exception

    # Check if each element of the sk_files exists
    for sk_file in sk_files:
        if not os.path.exists(sk_file):
            logging.error('remove_re_encryptions sk_files element exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in remove_re_encryptions sk_files element')
            raise Exception

    from crypto.ReEncPrimitives import re_decrypt

    # Remove all re-encryptions from the ciphertext file (reverse order: start from last re-encryption)
    for i in range(len(pk_files)):

        # Get public and secret keys to use for decryption
        pk_file = pk_files[-1-i]
        sk_file = sk_files[-1-i]

        # Decrypt re-encryption
        re_decrypt(infile, pk_file, sk_file, debug)


def decrypt_ciphertext(infile=None, outfile=None, pk_file=None, sk_file=None, debug=0):
    """
    Decrypt the ciphertext: remove hybrid encryption and all-or-nothing transformation applied directly to the
    plaintext.
    :param infile: file with the ciphertext to decrypt
    :param outfile: file where decrypted plaintext will be saved
    :param pk_file: public key used for asymmetric encryption
    :param sk_file: secret key to use for asymmetric decryption
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging
    import os.path

    # Check if infile is set and it exists
    if infile is None or not os.path.exists(infile):
        logging.error('decrypt_ciphertext infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_ciphertext infile')
        raise Exception

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.exists(pk_file):
        logging.error('decrypt_ciphertext pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_ciphertext pk_file')
        raise Exception

    # Check if sk_file is set and it exists
    if sk_file is None or not os.path.exists(sk_file):
        logging.error('[ERROR] decrypt_ciphertext infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_ciphertext sk_file')
        raise Exception

    # If outfile is not defined, set a default value
    if outfile is None:
        outfile = OUTPUT_PATH + 'dec_' + infile

    # Get encryption parameters
    enc_sym_key, iv, n, k0, ciphertext_length, transf_ciphertext_length, transf_ciphertext_offset = \
        get_encryption_params(infile, debug)

    # Decrypt symmetric key using ABE with given public and secret keys
    sym_key = decrypt_sym_key(enc_sym_key, pk_file, sk_file, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('DECRYPTED SYMMETRIC KEY = (%d) %s' % (len(sym_key), sym_key))
        print('IV = (%d) %s' % (len(iv), iv))

    # Remove all-or-nothing transformation and symmetric encryption from the ciphertext
    remove_aont_enc(ciphertext_infile=infile, plaintext_outfile=outfile, n=n, k0=k0,
                    ciphertext_length=ciphertext_length, sym_key=sym_key, iv=iv,
                    transf_ciphertext_offset=transf_ciphertext_offset,
                    transf_ciphertext_length=transf_ciphertext_length, debug=debug)


def get_encryption_params(infile=None, debug=0):
    """
    Retrieve encryption and transformation parameters from the given file.
    :param infile: file where parameters are written
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: encryption params (encrypted symmetric key, IV), transformation params (n, k0) and ciphertext params
    (ciphertext length, transformed ciphertext length, transformed ciphertext offset)
    """

    import logging
    import os.path

    # Check if infile is set and it exists
    if infile is None or not os.path.exists(infile):
        logging.error('get_encryption_params infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_encryption_params infile')
        raise Exception

    # Retrieve params from the given file
    with(open(infile, 'rb')) as fin:

        from crypto.Const import B, H, Q, IV_DEFAULT_SIZE
        import struct

        # Get required params
        fin.seek(B + B)
        n, k0, enc_key_length = struct.unpack('HHH', fin.read(3 * H))
        enc_key, iv, ciphertext_length = struct.unpack('%ds%dsQ' % (enc_key_length, IV_DEFAULT_SIZE),
                                                       fin.read(enc_key_length + IV_DEFAULT_SIZE + Q + 5))
        transf_ciphertext_length = (ciphertext_length * 8 // (n - k0) + 1) * n // 8

        fin.seek(H, 1)
        transf_ciphertext_offset = fin.tell()

        if debug:  # ONLY USE FOR DEBUG
            print('READ N = %d' % n)
            print('READ K0 = %d' % k0)
            print('READ ENC SYM KEY = (%d) %s' % (enc_key_length, enc_key))
            print('READ IV = (%d) %s' % (len(iv), iv))
            print('READ CIPHERTEXT LENGTH = %d' % ciphertext_length)
            print('TRANSFORMED CIPHERTEXT LENGTH = %d' % transf_ciphertext_length)
            print('TRANSFORMED CIPHERTEXT OFFSET = %d' % transf_ciphertext_offset)

    return enc_key, iv, n, k0, ciphertext_length, transf_ciphertext_length, transf_ciphertext_offset


def decrypt_sym_key(enc_key=None, pk_file=None, sk_file=None, debug=0):
    """
    Decrypt asymmetrically encrypted symmetric key.
    :param enc_key: symmetric key to decrypt
    :param pk_file: public key used to encrypt the symmetric key
    :param sk_file: secret key to use to decrypt the symmetric key
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: decrypted symmetric key
    """

    import logging
    import os.path

    # Check if enc_key is set
    if enc_key is None:
        logging.error('decrypt_sym_key enc_key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_sym_key enc_key')
        raise Exception

    # Check if pk_file is set and it exists
    if pk_file is None or not os.path.exists(pk_file):
        logging.error('decrypt_sym_key pk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_sym_key pk_file')
        raise Exception

    # Check if sk_file is set and it exists
    if sk_file is None or not os.path.exists(sk_file):
        logging.error('decrypt_sym_key sk_file exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in decrypt_sym_key sk_file')
        raise Exception

    # Create temporary files for symmetric key decryption
    temp_enc_sym_key_file = 'enc_sym_key'
    temp_dec_sym_key_file = 'dec_' + temp_enc_sym_key_file

    # Write encrypted symmetric key on a temporary file
    with(open(temp_enc_sym_key_file, 'wb')) as fout:
        fout.write(enc_key)

    from crypto.ABEPrimitives import decrypt

    # Decrypt encrypted symmetric key file with ABE using given public and secret keys
    decrypt(dec_outfile=temp_dec_sym_key_file, pk_file=pk_file, sk_file=sk_file, ciphertext_file=temp_enc_sym_key_file,
            debug=debug)

    # Read decrypted symmetric key from decryption output file
    with(open(temp_dec_sym_key_file, 'rb')) as fin:
        dec_sym_key = fin.read()

    # Remove temporary files
    os.remove(temp_dec_sym_key_file)

    return dec_sym_key


def remove_aont_enc(ciphertext_infile=None, plaintext_outfile=None, n=AONT_DEFAULT_N, k0=AONT_DEFAULT_K0,
                    encoding=AONT_DEFAULT_ENCODING, ciphertext_length=None, sym_key=None, iv=None,
                    transf_ciphertext_offset=None, transf_ciphertext_length=None, chunk_size=AONT_DEFAULT_N // 8,
                    debug=0):
    """
    Remove All-Or-Nothing transformation and symmetric encryption applied to the ciphertext.
    :param ciphertext_infile: file with the ciphertext to anti-transform and decrypt
    :param plaintext_outfile: file where plaintext will be saved
    :param n: transformation chunk size in bytes
    :param k0: random number length in bytes
    :param encoding: used encoding
    :param ciphertext_length: length of the anti-transformed ciphertext
    :param sym_key: symmetric key to use for decryption
    :param iv: initialisation vector to use for decryption
    :param transf_ciphertext_offset: transformed ciphertext position in the given file
    :param transf_ciphertext_length: transformed ciphertext length
    :param chunk_size: number of bytes of each chunk of the ciphertext to anti-transform and decrypt
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging
    import os.path

    # Check if ciphertext_infile is set and it exists
    if ciphertext_infile is None or not os.path.exists(ciphertext_infile):
        logging.error('remove_aont_enc ciphertext_infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont_enc ciphertext_infile')
        raise Exception

    # Check if plaintext_outfile is set and it exists
    if plaintext_outfile is None or not os.path.exists(plaintext_outfile):
        logging.error('remove_aont_enc plaintext_outfile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont_enc plaintext_outfile')
        raise Exception

    # Check if ciphertext_length is set
    if ciphertext_length is None:
        logging.error('remove_aont_enc ciphertext_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont_enc ciphertext_length')
        raise Exception

    # Check if sym_key is set
    if sym_key is None:
        logging.error('remove_aont_enc sym_key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont_enc sym_key')
        raise Exception

    # Check if iv is set
    if iv is None:
        logging.error('remove_aont_enc IV exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont_enc IV')
        raise Exception

    # Check if transf_ciphertext_offset is set
    if transf_ciphertext_offset is None:
        logging.error('remove_aont_enc transf_ciphertext_offset exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont_enc transf_ciphertext_offset')
        raise Exception

    # Check if transf_ciphertext_length is set
    if transf_ciphertext_length is None:
        logging.error('remove_aont_enc transf_ciphertext_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont_enc transf_ciphertext_length')
        raise Exception

    # Anti-transform and decrypt a data chunk read from the ciphertext input file
    with(open(ciphertext_infile, 'rb')) as fin:

        # Shift file pointer to transformed ciphertext starting byte
        fin.seek(transf_ciphertext_offset)

        # Remove transformation and encryption from data chunks until all transformed ciphertext is anti-transformed and
        # decrypted
        while transf_ciphertext_length > 0:

            # Read chunk
            transf_ciphertext_chunk = fin.read(chunk_size)

            # Decrease number of remaining bytes to read
            transf_ciphertext_length -= chunk_size

            # Anti-transform ciphertext chunk
            ciphertext_chunk = remove_aont(transf_ciphertext_chunk, n, k0, encoding, min(chunk_size, ciphertext_length),
                                           debug)

            # Decrease remaining ciphertext length
            ciphertext_length -= (n - k0) // 8

            from crypto.SymEncPrimitives import sym_decrypt

            # Decrypt chunk
            dec_plaintext_chunk = sym_decrypt(key=sym_key, iv=iv, ciphertext=ciphertext_chunk, debug=debug)

            if debug:  # ONLY USE FOR DEBUG
                print('DECRYPTED PLAINTEXT = (%d) %s' % (len(dec_plaintext_chunk), dec_plaintext_chunk))

            from FunctionUtils import write_bytes_on_file

            # Write decrypted plaintext chunk on output file
            write_bytes_on_file(plaintext_outfile, dec_plaintext_chunk, 'ab', 0, debug)


def remove_aont(data=None, n=None, k0=None, encoding=None, ciphertext_length=None, debug=0):
    """
    Remove All-Or-Nothing transformation from the given data.
    :param data: data to anti-transform
    :param n: transformation chunk size in bytes
    :param k0: random number length in bytes
    :param encoding: used encoding
    :param ciphertext_length: length of the anti-transformed ciphertext
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: anti-transformed data
    """

    import logging

    # Check if data is set
    if data is None:
        logging.error('remove_aont data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont data')
        raise Exception

    # Check if n is set
    if n is None:
        logging.error('remove_aont n exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont n')
        raise Exception

    # Check if k0 is set
    if k0 is None:
        logging.error('remove_aont k0 exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont k0')
        raise Exception

    # Check if encoding is set
    if encoding is None:
        logging.error('remove_aont encoding exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont encoding')
        raise Exception

    # Check if ciphertext_length is set
    if ciphertext_length is None:
        logging.error('remove_aont ciphertext_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_aont ciphertext_length')
        raise Exception

    from binascii import hexlify

    # Initialise variables
    anti_transformed_ciphertext = ''

    # Divide data in chunks to perform the anti-transformation
    step = n // 8
    for i in range(0, len(data), step):

        # Compute next chunk starting byte
        next_i = i + step

        if debug:  # ONLY USE FOR DEBUG
            print('CHUNK = (%d) %s' % (len(data[i: next_i]), data[i: next_i]))

        # Get a chunk of fixed length from data
        to_anti_transform = bin(int(hexlify(data[i: next_i]).decode(), 16))[2:].zfill(n)

        if debug:  # ONLY USE FOR DEBUG
            print('TO_ANTI_TRANSFORM = (%d) %s' % (len(to_anti_transform), to_anti_transform))

        from crypto.OAEPbis import init, unpad

        # Initialise anti-transformation parameters
        init(n=n, k0=k0, enc=encoding)

        # Apply anti-transformation to transformed chunk
        anti_transformed_ciphertext_chunk = unpad(to_anti_transform, debug)

        if debug:  # ONLY USE FOR DEBUG
            print('ANTI-TRANSFORMED CIPHERTEXT CHUNK BITS = (%d) %s' % (len(anti_transformed_ciphertext_chunk),
                                                                        anti_transformed_ciphertext_chunk))

        # Convert anti-transformed chunk from binary to hexadecimal and fill it with leading zeros
        anti_transformed_ciphertext_chunk_hex = hex(int(anti_transformed_ciphertext_chunk, 2))[2:]\
            .zfill(len(anti_transformed_ciphertext_chunk) // 4)

        # Append transformed data chunk to the final transformation result
        anti_transformed_ciphertext += anti_transformed_ciphertext_chunk_hex

    # Truncate any existing padding trailing zeros
    anti_transformed_ciphertext = anti_transformed_ciphertext[: ciphertext_length * 2]

    if debug:  # ONLY USE FOR DEBUG
        print('ANTI-TRANSFORMED CIPHERTEXT = (%d) %s' % (len(anti_transformed_ciphertext), anti_transformed_ciphertext))

    from binascii import unhexlify

    # Return anti-transformed ciphertext bytes
    return unhexlify(anti_transformed_ciphertext)

