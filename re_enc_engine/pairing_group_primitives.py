"""
This file contains all the primitives for parameters creation from a Pairing Group.
"""

from charm.core.engine.util import objectToBytes
from charm.toolbox.pairinggroup import hashPair, GT, PairingGroup, ZR
from const import SEED_LENGTH, SYM_KEY_MIN_SIZE, SYM_KEY_DEFAULT_SIZE
from function_utils import clamp

import logging
import math
import sys


def pairing_group_create(curve='MNT224'):
    """
    Create the pairing group related to the given curve.
    :param curve: string representing the curve to use
    :return: the pairing group object
    """
    return PairingGroup(curve)


def sym_key_gen(pairing_group=None, sym_key_size=None, debug=0):
    """
    Generate a random symmetric key with given size.
    :param pairing_group: pairing group which the symmetric key is generated from
    :param sym_key_size: length in bytes of the symmetric key
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the randomly generated symmetric key
    """

    # If sym_key_size is not defined, set a default value
    if sym_key_size is None:
        sym_key_size = SYM_KEY_DEFAULT_SIZE

    # Clamp the size between SYM_KEY_MIN_SIZE and the system maximum possible value
    size = clamp(sym_key_size, SYM_KEY_MIN_SIZE, sys.maxsize)

    # Check if an error occurred during clamping
    if size is None:
        logging.error('sym_key_gen clamp size exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_key_gen clamp size')
        raise Exception

    # Check if size is a power of 2
    if not math.log2(size).is_integer():
        logging.error('sym_key_gen size exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in sym_key_gen size')
        raise Exception

    # Generate and return a random symmetric key with the given size
    return random_string_gen(pairing_group, sym_key_size)


def random_string_gen(pairing_group=None, length=SEED_LENGTH):
    """
    Generate a random string with given size.
    :param pairing_group: pairing group which the string is generated from
    :param length: bytes length of the string to generate
    :return: the randomly generated string
    """

    # Generate a random element of the pairing group
    rand_pg_elem = random_pairing_group_elem_gen(pairing_group)

    # Convert the random element in a string with the given length
    rand_str = objectToBytes(rand_pg_elem, pairing_group)[: length]

    # Return the random string and the random element
    return rand_str, rand_pg_elem


def random_pairing_group_elem_gen(pairing_group=None, pg_set=GT):
    """
    Generate a random element from the given pairing group.
    :param pairing_group: pairing group which the random element is extracted from
    :param pg_set: set which the random element is extracted from
    :return: the random element
    """

    # Return a random element from the given pairing group and set
    return pairing_group.random(pg_set)


def hash_chain(pairing_group=None, start_pg_elem=None, hops_num=0):
    """
    Compute the pairing group element after the given number of hops using the hash chain by the given starting pairing
    group element.
    :param pairing_group: pairing group used for the hash chain
    :param start_pg_elem: starting pairing group element
    :param hops_num: number of hash operations to perform
    :return: the resulting pairing group element
    """

    # Compute the hash chain hops
    res_pg_elem = start_pg_elem
    for i in range(hops_num):
        r = pairing_group.init(ZR, int(hashPair(res_pg_elem).decode('utf-8'), 16))
        res_pg_elem = res_pg_elem ** r

    return res_pg_elem
