"""
This file contains All-Or-Nothing Transformation implemented with OAEP scheme primitives. The very first two methods,
'transform' and 'anti_transform', are the API interfaces those are called. OAEP primitives have been slightly modified
starting from the ones provided from B. Everhart.
Full details about his library can be found at the following link:
https://github.com/Brandon-Everhart/OAEP/blob/master/OAEP.py.
"""

from binascii import hexlify, unhexlify
from secrets import SystemRandom  # Generate secure random numbers

import hashlib  # SHA-256
import logging
import os

# Global OAEP configuration parameters
nBits = 1024
k0BitsInt = 256
n_k0BitsFill = '0' + str(nBits - k0BitsInt) + 'b'
k0BitsFill = '0' + str(k0BitsInt) + 'b'
encoding = 'utf-8'
endian = 'big'
errors = 'surrogatepass'
file_chunk_size = (nBits - k0BitsInt) // 8              # FILE BYTES TO PROCESS (USE A MULTIPLE OF THIS VALUE)


def transform(infile=None, outfile=None, args=None, debug=0):
    """
    Apply All-Or-Nothing Transformation to the input file and save the result on the output file.
    :param infile: file to transform
    :param outfile: file where transformation output will be saved
    :param args: AONT configuration parameters to pass to the init function
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if infile is set and it exists
    if infile is None or not os.path.exists(infile):

        logging.error('[AONT] In transform: infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('[AONT] In transform: infile exception')
        raise Exception

    # Flag for file renaming if outfile is not set
    to_rename = False

    # Check if outfile is set, otherwise it will be the infile
    if outfile is None:

        logging.info('[AONT] In transform: outfile not set; output will be saved in infile')
        if debug:  # ONLY USE FOR DEBUG
            print('[AONT] In transform: outfile not set; output will be saved in infile')

        outfile = 'transf_' + infile
        to_rename = True

    # Read data chunk from the input file
    with(open(infile, 'rb')) as fin:

        # Transform chunks until all the input file is transformed
        for infile_chunk in iter(lambda: fin.read(file_chunk_size), ''):

            # Last read is empty, so processing will be skipped
            if not len(infile_chunk):
                return

            if debug:  # ONLY USE FOR DEBUG
                print('[AONT] INFILE CHUNK = (%d) %s -> %s' % (len(infile_chunk), infile_chunk, hexlify(infile_chunk)))

            # Apply All-Or-Nothing Transformation to input file chunk
            transf_infile_chunk = apply_aont(data=infile_chunk, args=args, debug=debug)

            if debug:  # ONLY USE FOR DEBUG
                print('[AONT] TRANSFORMED INFILE CHUNK = (%d) %s -> %s'
                      % (len(transf_infile_chunk), transf_infile_chunk, hexlify(transf_infile_chunk)))

            # Write transformed input file chunk on output file
            with(open(outfile, 'ab')) as fout:
                fout.write(transf_infile_chunk)

    # Replace input file content with temporary output file one
    if to_rename:
        os.remove(infile)
        os.rename(outfile, infile)


def anti_transform(infile=None, outfile=None, args=None, debug=0):
    """
    Remove All-Or-Nothing Transformation to the input file and save the result on the output file.
    :param infile: file to anti-transform
    :param outfile: file where anti-transformation output will be saved
    :param args: AONT configuration parameters to pass to the init function
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if infile is set and it exists
    if infile is None or not os.path.exists(infile):
        logging.error('[AONT] In anti-transform: infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('[AONT] In anti-transform: infile exception')
        raise Exception

    # Flag for file renaming if outfile is not set
    to_rename = False

    # Check if outfile is set, otherwise it will be the infile
    if outfile is None:

        logging.info('[AONT] In anti-transform: outfile not set; output will be saved in infile')
        if debug:  # ONLY USE FOR DEBUG
            print('[AONT] In anti-transform: outfile not set; output will be saved in infile')

        outfile = 'anti_transf_' + infile
        to_rename = True

    # Read data chunk from the input file
    with(open(infile, 'rb')) as fin:

        chunk_size = nBits // 8
        original_data_length = args.pop('original_data_length', None)

        # Anti-transform chunks until all the input file is anti-transformed
        for infile_chunk in iter(lambda: fin.read(chunk_size), ''):

            # Last read is empty, so processing will be skipped
            if not len(infile_chunk):
                return

            if debug:  # ONLY USE FOR DEBUG
                print('[AONT] INFILE CHUNK = (%d) %s -> %s' % (len(infile_chunk), infile_chunk, hexlify(infile_chunk)))

            # Remove All-Or-Nothing Transformation to input file chunk
            anti_transf_infile_chunk = remove_aont(data=infile_chunk, args=args,
                                                   data_length=min(chunk_size, original_data_length), debug=debug)

            if debug:  # ONLY USE FOR DEBUG
                print('[AONT] ANTI-TRANSFORMED INFILE CHUNK = (%d) %s -> %s'
                      % (len(anti_transf_infile_chunk), anti_transf_infile_chunk, hexlify(anti_transf_infile_chunk)))

            # Write transformed input file chunk on output file
            with(open(outfile, 'ab')) as fout:
                fout.write(anti_transf_infile_chunk)

            # Decrease remaining original data length
            original_data_length -= (nBits - k0BitsInt) // 8

    # Replace input file content with temporary output file one
    if to_rename:
        os.remove(infile)
        os.rename(outfile, infile)


def apply_aont(data=None, args=None, debug=0):
    """
    Apply All-Or-Nothing Transformation to the given data
    :param data: data to transform
    :param args: AONT configuration parameters
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if data is set
    if data is None:
        logging.error('[AONT] in apply_aont: data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('[AONT] in apply_aont: data exception')
        raise Exception

    if debug:  # ONLY USE FOR DEBUG
        print('DATA BYTES = (%d) %s' % (len(data), data))

    # Initialise AONT parameters
    init(args=args)

    # Apply transformation to data
    transformed_data = pad(data.decode(encoding), debug)

    if debug:  # ONLY USE FOR DEBUG
        print('TRANSFORMED DATA BITS = (%s) (%d) %s' % (type(transformed_data), len(transformed_data),
                                                        transformed_data))

    # Convert transformation result from character binary string to bytes and fill it with leading zeros
    transformed_data_bytes = unhexlify(hex(int(transformed_data, 2))[2:].zfill(len(transformed_data) // 4))

    if debug:  # ONLY USE FOR DEBUG
        print('TRANSFORMED DATA BYTES = (%d) %s\n' % (len(transformed_data_bytes), transformed_data_bytes))

    return transformed_data_bytes


def remove_aont(data=None, args=None, data_length=None, debug=0):
    """
    Remove All-Or-Nothing Transformation from the given data
    :param data: data to transform
    :param args: AONT configuration parameters
    :param data_length: data length
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if data is set
    if data is None:
        logging.error('[AONT] in remove_aont: data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('[AONT] in remove_aont: data exception')
        raise Exception

    # Check if data length is set
    if data_length is None:
        logging.error('[AONT] in remove_aont: data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('[AONT] in remove_aont: data exception')
        raise Exception

    if debug:  # ONLY USE FOR DEBUG
        print('DATA BYTES = (%d) %s' % (len(data), data))

    # Initialise AONT parameters
    init(args=args)

    # Remove transformation to data
    anti_transformed_data = unpad(bin(int(hexlify(data).decode(), 16))[2:].zfill(nBits), debug)

    if debug:  # ONLY USE FOR DEBUG
        print('ANTI-TRANSFORMED DATA BITS = (%s) (%d) %s' % (type(anti_transformed_data), len(anti_transformed_data),
                                                             anti_transformed_data))

    # Convert anti-transformation result from character string to bytes
    anti_transformed_data_bytes = bytes(anti_transformed_data.encode(encoding))

    # Truncate any existing padding trailing zeros
    anti_transformed_data_bytes = anti_transformed_data_bytes[: data_length]

    if debug:  # ONLY USE FOR DEBUG
        print('ANTI-TRANSFORMED DATA BYTES = (%d) %s\n' % (len(anti_transformed_data_bytes), anti_transformed_data_bytes))

    return anti_transformed_data_bytes


# ============================================== OAEP scheme primitives ============================================== #


def chars_to_binary(msg, end=endian, err=errors):
    """
    Helper function to change a character string into a binary string, making sure to have full byte output
    (don't drop leading 0's).
    :param msg: a charater string
    :param end: endian encoding
    :param err: used when encoding the msg
    :return: a binary string
    """

    bits = bin(int.from_bytes(msg.encode(encoding, err), end))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def binary_to_chars(bits, end=endian, err=errors):
    """
    Helper function to change a binary string into a character string.
    :param bits: a binary string
    :param end: endian encoding
    :param err: used when decoding the bits
    :return: a character string
    """

    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, end).decode(encoding, err) or '\0'


# def hex_to_binary(msg):
#     """
#     Convert a hexadecimal string into a binary one and fill with leading zeros.
#     :param msg: hexadecimal string to convert
#     :return: binary string with leading zeros
#     """
#
#     # Convert hex to bin
#     bits = bin(int(msg, 16))[2:]
#
#     # Return bin with leading 0s
#     return bits.zfill(8 * ((len(bits) + 7) // 8))
#
#
# def binary_to_hex(bits):
#     """
#     Convert a binary string into a hexadecimal one.
#     :param bits: binary string to convert
#     :return: hexadecimal string
#     """
#
#     return hex(int(bits, 2))


def init(args=None):
    """
    Initialise OAEP parameters.
    :param args: configuration parameters
    """

    if args is None or len(args) == 0:
        return

    global nBits, k0BitsInt, n_k0BitsFill, k0BitsFill, encoding, endian, errors

    nBits = args['nBits']
    k0BitsInt = args['k0BitsInt']
    n_k0BitsFill = '0' + str(nBits - k0BitsInt) + 'b'
    k0BitsFill = '0' + str(k0BitsInt) + 'b'
    encoding = args['encoding']
    endian = args['endian']
    errors = args['errors']


def pad(msg, debug=0):
    """
    Apply OAEP to the given message.
    :param msg: string to pad
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: string of 0s and 1s representing the concatenation of OAEP result, X and Y
    """

    # Create two oracles using sha-256 hash function
    oracle1 = hashlib.sha256()  # used to hash a random integer
    oracle2 = hashlib.sha256()  # used to hash the result of XOR(paddedMsg, hash(randBitStr))

    # Generate a random integer that has a size of k0bits. Format the random int as a binary string making sure to
    # maintain leading zeros with the K0BitsFill argument
    rand_bit_str = format(SystemRandom().getrandbits(k0BitsInt), k0BitsFill)

    if debug:  # ONLY USE FOR DEBUG
        print('RAND BIT STRING = (%d) %s' % (len(rand_bit_str), rand_bit_str))

    # Change msg string to a binary string
    bin_msg = chars_to_binary(msg)

    if debug:  # ONLY USE FOR DEBUG
        print('BIN MSG = (%d) %s' % (len(bin_msg), bin_msg))

    zero_padded_msg = bin_msg

    # If the input msg has a binary length shorter than (nBits-k0Bits) then append k1Bits 0s to the end of the msg
    # (where k1Bits is the number of bits to make len(binMsg) = (nBits-k0Bits))
    if len(bin_msg) <= (nBits - k0BitsInt):
        k1_bits = nBits - k0BitsInt - len(bin_msg)
        zero_padded_msg += ('0' * k1_bits)

    if debug:  # ONLY USE FOR DEBUG
        print('ZERO PADDED MSG = (%d) %s' % (len(zero_padded_msg), zero_padded_msg))

    # Use the hashlib update method to pass the values we wish to be hashed to the oracle. Then use the hashlib
    # hexdigest method to hash the value placed in the oracle by the update method, and return the hex representation of
    # this hash. Change our hash output, zeroPaddedMsg, and randBitStr to integers to use XOR operation. Format the
    # resulting ints as binary strings. Hashing and XOR ordering follows OAEP algorithm
    oracle1.update(rand_bit_str.encode(encoding))
    x = format(int(zero_padded_msg, 2) ^ int(oracle1.hexdigest(), 16), n_k0BitsFill)

    if debug:  # ONLY USE FOR DEBUG
        print('X = ', x)

    oracle2.update(x.encode(encoding))
    y = format(int(oracle2.hexdigest(), 16) ^ int(rand_bit_str, 2), k0BitsFill)

    if debug:  # ONLY USE FOR DEBUG
        print('Y = ', y)

    return x + y


def unpad(msg, debug=0):
    """
    Remove OAEP from the given message.
    :param msg: string to unpad
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: string of 0s and 1s containing message previously padded with OAEP (NOTE: it contains k1Bits trailing 0s)
    """

    # Create two oracles using sha-256 hash function
    oracle1 = hashlib.sha256()  # used to hash the random r to recover the message with trailing zeros
    oracle2 = hashlib.sha256()  # used to hash X to recover the random r

    # Extract X and Y from given message
    x = msg[0: nBits - k0BitsInt]
    y = msg[nBits - k0BitsInt:]

    if debug:  # ONLY USE FOR DEBUG
        print('X = (%d) %s' % (len(x), x))
        print('Y = (%d) %s' % (len(y), y))

    # Reconstruct the random r as the result of XOR(Y, hash2(X))
    oracle2.update(x.encode(encoding))
    r = format(int(y, 2) ^ int(oracle2.hexdigest(), 16), k0BitsFill)

    if debug:  # ONLY USE FOR DEBUG
        print('EXTRACTED RANDOM = ', r)

    # Reconstruct the message with k1Bits trailing zeros as the result of XOR(X, hash(r))
    oracle1.update(r.encode(encoding))
    msg_with_0s = format(int(x, 2) ^ int(oracle1.hexdigest(), 16), n_k0BitsFill)

    if debug:  # ONLY USE FOR DEBUG
        print('EXTRACTED MSG = ', msg_with_0s)

    return binary_to_chars(msg_with_0s)
