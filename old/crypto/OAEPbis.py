"""
This file contains OAEP scheme primitives. These functions have been slightly modified starting from the ones provided
from B. Everhart. Full details about his library can be found at the following link
https://github.com/Brandon-Everhart/OAEP/blob/master/OAEP.py.
"""

import hashlib                      # SHA-256
from secrets import SystemRandom    # Generate secure random numbers
from old.crypto.Const import AONT_DEFAULT_N, AONT_DEFAULT_ENCODING, AONT_DEFAULT_K0, AONT_DEFAULT_K0_FILL, \
    AONT_DEFAULT_N_K0_FILL

# Global variables
nBits = AONT_DEFAULT_N
k0BitsInt = AONT_DEFAULT_K0
k0BitsFill = AONT_DEFAULT_K0_FILL
n_k0BitsFill = AONT_DEFAULT_N_K0_FILL
encoding = AONT_DEFAULT_ENCODING


def init(n=AONT_DEFAULT_N, enc=AONT_DEFAULT_ENCODING, k0=AONT_DEFAULT_K0):
    """
    Initialise OAEP parameters.
    :param n: OAEP block size in bits
    :param enc: encoding format
    :param k0: OAEP random size in bits
    """

    global nBits, k0BitsInt, k0BitsFill, n_k0BitsFill, encoding

    nBits = n
    encoding = enc
    k0BitsInt = k0
    k0BitsFill = '0' + str(k0) + 'b'
    n_k0BitsFill = '0' + str(n - k0) + 'b'


def hex_to_binary(msg):
    """
    Convert a hexadecimal string into a binary one and fill with leading zeros.
    :param msg: hexadecimal string to convert
    :return: binary string with leading zeros
    """

    # Convert hex to bin
    bits = bin(int(msg, 16))[2:]

    # Return bin with leading 0s
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def binary_to_hex(bits):
    """
    Convert a binary string into a hexadecimal one.
    :param bits: binary string to convert
    :return: hexadecimal string
    """

    return hex(int(bits, 2))


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
    bin_msg = hex_to_binary(msg)

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

    return msg_with_0s
