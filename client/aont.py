"""
This file contains All-Or-Nothing Transformation implemented as an OAEP variation but with very same scheme primitives.
We only changed OAEP oracle G(), usually realised with hash function, with a PRF for arbitrary string expansion.
The very first two methods in this file, 'transform' and 'anti_transform', are the API interfaces those are called.
OAEP primitives have been slightly modified starting from the ones provided from B. Everhart.
Full details about his library can be found at the following link:
https://github.com/Brandon-Everhart/OAEP/blob/master/OAEP.py.
"""

from binascii import hexlify, unhexlify
from secrets import SystemRandom  # Generate secure random numbers

import hashlib
import logging
import random   # WARNING: NOT CRYPTOGRAPHICALLY SECURE

# Global OAEP configuration parameters
nBits = 1024
k0BitsInt = 256                                     # MINIMUM RANDOM BITS LENGTH FOR SECURITY REASON
n_k0BitsFill = '0' + str(nBits - k0BitsInt) + 'b'
k0BitsFill = '0' + str(k0BitsInt) + 'b'
encoding = 'utf-8'
endian = 'big'
errors = 'surrogatepass'
max_expansion_bits_len = 127 * 1024                 # WARNING: MAXIMUM DEPENDS ON CHOSEN EXPANSION FUNCTION


def transform(data=None, args=None, debug=0):
    """
    Apply All-Or-Nothing Transformation to the given data and return the result.
    :param data: data to transform
    :param args: AONT configuration parameters to pass to the init function
    :param debug: if 1, # prints will be shown during execution; default 0, no # prints are shown
    :return a string containing transformation result
    """

    # Check if data is set
    if data is None:
        logging.error('[AONT] In transform: data exception')
        # if debug:  # ONLY USE FOR DEBUG
            # print('[AONT] In transform: data exception')
        raise Exception

    # if debug:  # ONLY USE FOR DEBUG
        # print('[AONT] DATA = (%d) %s' % (len(data), data))

    # Initialise AONT parameters
    init(args=args)

    # Apply All-Or-Nothing Transformation to data
    transformed_data = pad(hexlify(data).decode(encoding), debug)

    # if debug:  # ONLY USE FOR DEBUG
        # print('TRANSFORMED DATA BITS = (%s) (%d) %s' % (type(transformed_data), len(transformed_data),
        #                                                 transformed_data))

    # Convert transformation result from character binary string to bytes and fill it with leading zeros
    return unhexlify(hex(int(transformed_data, 2))[2:].zfill(len(transformed_data) // 4))


def anti_transform(data=None, args=None, debug=0):
    """
    Remove All-Or-Nothing Transformation to the given data and return the result.
    :param data: data to anti-transform
    :param args: AONT configuration parameters to pass to the init function
    :param debug: if 1, # prints will be shown during execution; default 0, no # prints are shown
    :return a string containing anti-transformation result
    """

    # Check if data is set
    if data is None:
        logging.error('[AONT] In anti-transform: data exception')
        # if debug:  # ONLY USE FOR DEBUG
            # print('[AONT] In anti-transform: data exception')
        raise Exception

    # if debug:  # ONLY USE FOR DEBUG
        # print('[AONT] DATA = (%d) %s' % (len(data), data))

    # Initialise AONT parameters
    init(args=args)

    # Remove All-Or-Nothing Transformation from data chunk
    anti_transformed_data = unpad(bin(int(hexlify(data).decode(), 16))[2:].zfill(nBits), debug)

    # if debug:  # ONLY USE FOR DEBUG
        # print('ANTI-TRANSFORMED DATA BITS = (%s) (%d) %s' % (type(anti_transformed_data), len(anti_transformed_data),
        #                                                    anti_transformed_data))

    # Convert anti-transformation result from character string to bytes
    return unhexlify(hex(int(anti_transformed_data, 2))[2:].zfill(len(anti_transformed_data) // 4))


# ============================================== OAEP scheme primitives ============================================== #

def hex_to_binary(msg=None, debug=0):
    """
    Convert a hexadecimal string into a binary one and fill with leading zeros.
    :param msg: hexadecimal string to convert
    :param debug: if 1, # prints will be shown during execution; default 0, no # prints are shown
    :return: binary string with leading zeros
    """

    # Check if msg is set
    if msg is None:
        logging.error('[AONT] in hex_to_binary: msg exception')
        # if debug:  # ONLY USE FOR DEBUG
            # print('[AONT] in hex_to_binary: msg exception')
        raise Exception

    # if debug:  # ONLY USE FOR DEBUG
        # print('IN HEX TO BIN: msg = (%s) (%d) %s' % (type(msg), len(msg), msg))

    # Convert hex to bin
    bits = bin(int(msg, 16))[2:]

    # if debug:  # ONLY USE FOR DEBUG
        # print('IN HEX TO BIN: bits = (%s) (%d) %s' % (type(bits), len(bits), bits))

    # Return bits with leading 0s
    return bits.zfill(len(msg) * 4)


def init(args=None, debug=0):
    """
    Initialise OAEP parameters.
    :param args: configuration parameters
    :param debug: if 1, # prints will be shown during execution; default 0, no # prints are shown
    """

    # Check if args is set and it contains some values
    if args is None or len(args) == 0:
        return

    # if debug:  # ONLY USE FOR DEBUG
        # print('IN AONT INIT: args =', args)

    global nBits, k0BitsInt, n_k0BitsFill, k0BitsFill, encoding, endian, errors

    if 'nBits' in args.keys():
        nBits = args['nBits']
        n_k0BitsFill = '0' + str(nBits - k0BitsInt) + 'b'
    if 'k0BitsInt' in args.keys():
        k0BitsInt = args['k0BitsInt']
        n_k0BitsFill = '0' + str(nBits - k0BitsInt) + 'b'
        k0BitsFill = '0' + str(k0BitsInt) + 'b'
    if 'encoding' in args.keys():
        encoding = args['encoding']
    if 'endian' in args.keys():
        endian = args['endian']
    if 'errors' in args.keys():
        errors = args['errors']


def pad(msg, debug=0):
    """
    Apply OAEP variation to the given message.
    :param msg: string to pad
    :param debug: if 1, # prints will be shown during execution; default 0, no # prints are shown
    :return: string of 0s and 1s representing the concatenation of OAEP result, X and Y
    """

    # Generate a random integer that has a size of k0bits. Format the random int as a binary string making sure to
    # maintain leading zeros with the K0BitsFill argument.
    rand_bytes = int(format(SystemRandom().getrandbits(k0BitsInt), k0BitsFill), 2).to_bytes(k0BitsInt // 8,
                                                                                            byteorder=endian)

    # if debug:  # ONLY USE FOR DEBUG
        # print('RANDOM BYTES = (%d) %s' % (len(rand_bytes), rand_bytes))

    # Convert msg string to a binary string
    bin_msg = hex_to_binary(msg, debug)

    # Using generated random bytes as seed for prng, generate random strings until their concatenation has a length
    # equal to zero_padded_msg's one (expansion of r, G(r))
    random.seed(a=rand_bytes)
    g_r = b''
    remaining_bits_len = len(bin_msg)

    while len(g_r) * 8 < len(bin_msg):

        # if debug:  # ONLY USE FOR DEBUG
            # print('REMAINING BITS LEN =', remaining_bits_len)

        # Compute number of bits to generate
        random_bits_len = min(max_expansion_bits_len, remaining_bits_len)

        # if debug:  # ONLY USE FOR DEBUG
            # print('RANDOM BITS LEN =', random_bits_len)

        # Generate a chunk of random bits
        random_bits = random.getrandbits(random_bits_len).to_bytes(random_bits_len // 8, endian)

        # if debug:  # ONLY USE FOR DEBUG
            # print('RANDOM BITS = (%d) %s' % (len(random_bits), random_bits))

        # Append random chunk
        g_r += random_bits

        # Update remaining bits to generate
        remaining_bits_len -= len(random_bits) * 8

    # if debug:  # ONLY USE FOR DEBUG
        # print('G(r) = (%d) %s' % (len(g_r), g_r))

    # Compute X as zero_padded_msg XOR G(r)
    x = format(int(bin_msg, 2) ^ int.from_bytes(g_r, byteorder=endian), n_k0BitsFill)
    # x = format(int(bin_msg, 2), n_k0BitsFill)

    # if debug:  # ONLY USE FOR DEBUG
        # print('X = (%d) %s' % (len(x), x))

    # Create an oracle using sha-256 hash function for H()
    oracle2 = hashlib.sha256()

    # Hash the result of XOR(paddedMsg, hash(randBitStr)), computing H(X)
    oracle2.update(x.encode(encoding))
    h_x = oracle2.digest()

    # if debug:  # ONLY USE FOR DEBUG
        # print('H(X) = (%d) %s' % (len(h_x), h_x))

    # Compute Y as H(X) XOR r
    y = format(int.from_bytes(h_x, byteorder=endian) ^ int.from_bytes(rand_bytes, byteorder=endian), k0BitsFill)

    # if debug:  # ONLY USE FOR DEBUG
        # print('Y = (%d) %s' % (len(y), y))

    # y = '1' * 256
    return x + y


def unpad(msg, debug=0):
    """
    Remove OAEP variation from the given message.
    :param msg: string to unpad
    :param debug: if 1, # prints will be shown during execution; default 0, no # prints are shown
    :return: string of 0s and 1s containing message previously padded with OAEP (NOTE: it contains k1Bits trailing 0s)
    """

    # Extract X and Y from given message
    x = msg[0: len(msg) - k0BitsInt]
    y = msg[len(msg) - k0BitsInt:]

    # if debug:  # ONLY USE FOR DEBUG
        # print('X = (%d) %s' % (len(x), x))
        # print('Y = (%d) %s' % (len(y), y))

    # Create an oracle using sha-256 hash function for H()
    oracle2 = hashlib.sha256()

    # Compute H(X)
    oracle2.update(x.encode(encoding))
    h_x = oracle2.digest()

    # if debug:  # ONLY USE FOR DEBUG
        # print('H(X) = (%d) %s' % (len(h_x), h_x))

    # Recover the random r as the result of H(X) XOR Y
    r_bits_string = format(int.from_bytes(h_x, byteorder=endian) ^ int(y, 2), k0BitsFill)
    r = bytes.fromhex(hex(int(r_bits_string, 2))[2:].zfill(len(r_bits_string) // 4))

    # if debug:  # ONLY USE FOR DEBUG
        # print('EXTRACTED RANDOM BITS STRING = (%d) %s' % (len(r_bits_string), r_bits_string))
        # print('EXTRACTED RANDOM BYTES = (%d) %s' % (len(r), r))

    # Using recovered random as seed for prng, generate random strings until their concatenation has a length
    # equal to zero_padded_msg's one (expansion of r, G(r))
    random.seed(a=r)
    g_r = b''
    remaining_bits_len = len(x)

    while len(g_r) * 8 < len(x):

        # if debug:  # ONLY USE FOR DEBUG
            # print('REMAINING BITS LEN =', remaining_bits_len)

        # Compute number of bits to generate
        random_bits_len = min(max_expansion_bits_len, remaining_bits_len)

        # if debug:  # ONLY USE FOR DEBUG
            # print('RANDOM BITS LEN =', random_bits_len)

        # Generate a chunk of random bits
        random_bits = random.getrandbits(random_bits_len).to_bytes(random_bits_len // 8, endian)

        # if debug:  # ONLY USE FOR DEBUG
            # print('RANDOM BITS = (%d) %s' % (len(random_bits), random_bits))

        # Append random chunk
        g_r += random_bits

        # Update remaining bits to generate
        remaining_bits_len -= len(random_bits) * 8

    # if debug:  # ONLY USE FOR DEBUG
        # print('G(r) = (%d) %s' % (len(g_r), g_r))

    # Recover original message as X XOR G(r)
    msg = format(int(x, 2) ^ int.from_bytes(g_r, byteorder=endian), n_k0BitsFill)
    # msg = format(int(x, 2), n_k0BitsFill)

    # if debug:  # ONLY USE FOR DEBUG
        # print('EXTRACTED MSG = (%d) %s' % (len(msg), msg))

    return msg
