from binascii import unhexlify
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.policytree import PolicyParser

import abe_primitives as abe
import const
import function_utils as fu
import logging
import pairing_group_primitives as pg
import re_enc_primitives as re_enc
import sym_enc_primitives as sym


# def apply_new_re_enc(data=None, max_data_length=None, re_enc_length=None, pk=None, policy=None,
#                      pairing_group=pg.pairing_group_create(), init_val=None, debug=0):
#     """
#     Apply a new re-encryption to the given data using the given re-encryption parameters.
#     :param data: data which re-encryption needs to be applied to
#     :param max_data_length: maximum data length
#     :param re_enc_length: number of bytes to re-encrypt
#     :param pk: ABE public key
#     :param policy: ABE policy
#     :param pairing_group: pairing group for parameters generation
#     :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
#     :return: re-encrypted data
#     """
#
#     # Check if data is set
#     if data is None:
#         logging.error('apply_new_re_enc data exception')
#         if debug:  # ONLY USE FOR DEBUG
#             print('EXCEPTION in apply_new_re_enc data')
#         raise Exception
#
#     # Check if re_enc_length is set
#     if re_enc_length is None:
#         logging.error('apply_new_re_enc re_enc_length exception')
#         if debug:  # ONLY USE FOR DEBUG
#             print('EXCEPTION in apply_new_re_enc re_enc_length')
#         raise Exception
#
#     # Check if pk is set
#     if pk is None:
#         logging.error('apply_new_re_enc pk exception')
#         if debug:  # ONLY USE FOR DEBUG
#             print('EXCEPTION in apply_new_re_enc pk')
#         raise Exception
#
#     # Check if re_enc_length is set
#     if re_enc_length is None:
#         logging.error('apply_new_re_enc policy exception')
#         if debug:  # ONLY USE FOR DEBUG
#             print('EXCEPTION in apply_new_re_enc policy')
#         raise Exception
#
#     # Check if init_val is set
#     if init_val is None:
#         logging.error('apply_new_re_enc init_val exception')
#         if debug:  # ONLY USE FOR DEBUG
#             print('EXCEPTION in apply_new_re_enc init_val')
#         raise Exception
#
#     # Create re-encryption parameters
#     seed, seed_pg_elem, key, key_pg_elem, iv, re_enc_length = get_new_re_enc_params(max_data_length, re_enc_length,
#                                                                                     debug)
#
#     if debug:  # ONLY USE FOR DEBUG
#         print('\nMAX DATA LENGTH = %d' % max_data_length)
#         print('SEED = (%d) %s' % (len(seed), seed))
#         if seed:
#             print('SEED = (%d) %s' % (len(seed), seed))
#             print('SEED PG ELEM = (%s) %s' % (type(seed_pg_elem), seed_pg_elem))
#         else:
#             print('SEED =', seed)
#             print('SEED PG ELEM =', seed_pg_elem)
#         print('KEY = (%d) %s' % (len(key), key))
#         print('KEY PG ELEM = (%s) %s' % (type(key_pg_elem), key_pg_elem))
#         print('IV = (%d) %s' % (len(iv), iv))
#         print('RE-ENC LEN =', re_enc_length)
#
#     # Apply re-encryption
#     re_enc_data = re_enc.re_encrypt(data, re_enc_length, seed, key, iv, init_val, 0)
#
#     # Encrypt re-encryption parameters those need to be protected
#     enc_seed = objectToBytes(abe.encrypt(seed_pg_elem, pairing_group, bytesToObject(pk, pairing_group), policy,
#                                          debug), pairing_group) if seed is not None else seed
#     enc_key = objectToBytes(abe.encrypt(key_pg_elem, pairing_group, bytesToObject(pk, pairing_group), policy,
#                                         debug), pairing_group)
#
#     if debug:  # ONLY USE FOR DEBUG
#         if enc_seed:
#             print('ENC SEED = (%d) %s' % (len(enc_seed), enc_seed))
#         else:
#             print('ENC SEED =', enc_seed)
#         print('ENC KEY = (%d) %s' % (len(enc_key), enc_key))
#
#     return re_enc_data, re_enc_length, enc_seed, enc_key, iv


def apply_old_re_enc(data=None, re_enc_info=None, debug=0):
    """
    Apply an old re-encryption to the given data using the given re-encryption information.
    :param data: data which re-encryption needs to be applied to
    :param re_enc_info: information containing re-encryption parameters
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: re-encrypted data
    """

    # Check if data is set
    if data is None:
        logging.error('apply_old_re_enc data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_enc data')
        raise Exception

    # Check if re_enc_info is set
    if re_enc_info is None:
        logging.error('apply_old_re_enc re_enc_info exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in apply_old_re_enc re_enc_info')
        raise Exception

    # Extract re-encryption parameters
    seed, key, iv, re_enc_length, init_val = get_re_enc_params(re_enc_info, debug)

    # Apply re-encryption
    return re_enc.re_encrypt(data, re_enc_length, seed, key, iv, init_val, 0)


def remove_re_enc(data=None, re_enc_info=None, debug=0):
    """
    Remove re-encryption from the given data using the given re-encryption information.
    :param data: data which re-encryption needs to be removed from
    :param re_enc_info: information containing re-encryption parameters
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: data without re-encryption
    """

    # Check if data is set
    if data is None:
        logging.error('remove_re_enc data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_enc data')
        raise Exception

    # Check if re_enc_info is set
    if re_enc_info is None:
        logging.error('remove_re_enc re_enc_info exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in remove_re_enc re_enc_info')
        raise Exception

    # Extract re-encryption parameters
    seed, key, iv, re_enc_length, init_val = get_re_enc_params(re_enc_info, debug)

    # Remove re-encryption
    return re_enc.re_decrypt(data, re_enc_length, seed, key, iv, init_val, 0)


# def get_new_re_enc_params(max_data_length=None, re_enc_length=None, pairing_group=pg.pairing_group_create(), debug=0):
#     """
#     Generate all parameters required for a new re-encryption operation.
#     :param max_data_length: maximum data length
#     :param re_enc_length: number of bytes to re-encrypt
#     :param pairing_group: pairing group for parameters generation
#     :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
#     :return: re-encryption parameters
#     """
#
#     # Check if max_data_length is set
#     if max_data_length is None:
#         logging.error('get_new_re_enc_params max_data_length exception')
#         if debug:  # ONLY USE FOR DEBUG
#             print('EXCEPTION in get_new_re_enc_params max_data_length')
#         raise Exception
#
#     # Check if re_enc_length is set
#     if re_enc_length is None:
#         logging.error('get_new_re_enc_params re_enc_length exception')
#         if debug:  # ONLY USE FOR DEBUG
#             print('EXCEPTION in get_re_enc_params re_enc_length')
#         raise Exception
#
#     # Generate re-encryption parameters
#     seed = None
#     seed_pg_elem = None
#     if re_enc_length < max_data_length:
#         seed, seed_pg_elem = pg.random_string_gen(pairing_group, const.SEED_LENGTH)
#     key, key_pg_elem = pg.sym_key_gen(pairing_group, const.SYM_KEY_DEFAULT_SIZE, debug)
#     iv = sym.iv_gen(const.IV_DEFAULT_SIZE, debug)
#
#     # Clamp the number of bytes to re-encrypt between RE_ENC_MIN_LENGTH and the chunk size
#     re_enc_length = fu.clamp(re_enc_length, const.RE_ENC_MIN_LENGTH, max_data_length, debug)
#
#     if debug:  # ONLY USE FOR DEBUG
#         print('\nMAX DATA LENGTH = %d' % max_data_length)
#         if seed:
#             print('SEED = (%d) %s' % (len(seed), seed))
#             print('SEED PG ELEM = (%s) %s' % (type(seed_pg_elem), seed_pg_elem))
#         else:
#             print('SEED =', seed)
#             print('SEED PG ELEM =', seed_pg_elem)
#         print('KEY = (%d) %s' % (len(key), key))
#         print('KEY PG ELEM = (%s) %s' % (type(key_pg_elem), key_pg_elem))
#         print('IV = (%d) %s' % (len(iv), iv))
#         print('RE-ENC LEN =', re_enc_length)
#
#     # Convert seed, key and re_enc_length from pairing group elements to useful values
#     seed = objectToBytes(seed, pairing_group)[: const.SEED_LENGTH] if seed is not None else seed
#     key = objectToBytes(key, pairing_group)[: const.SYM_KEY_DEFAULT_SIZE]
#
#     return seed, seed_pg_elem, key, key_pg_elem, iv, re_enc_length


def get_re_enc_params(re_enc_info=None, debug=0):
    """
    Extract all parameters required for re-encryption operation.
    :param re_enc_info: dictionary containing at least re-encryption parameters
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: re-encryption parameters
    """

    if debug:  # ONLY USE FOR DEBUG
        print('RE-ENC INFOS =', re_enc_info)

    # Required re-encryption parameters
    #re_enc_params = ['pk', 'sk', 'seed', 'key', 're_enc_length', 'iv', 'policy', 'pairing_group', 'init_val']
    re_enc_params = ['seed', 'key', 're_enc_length', 'iv', 'pairing_group', 'init_val']

    for param in re_enc_params:
        if param not in re_enc_info.keys():
            logging.error('get_re_enc_params re_enc_info exception')
            if debug:  # ONLY USE FOR DEBUG
                print('EXCEPTION in get_re_enc_params re_enc_info')
            raise Exception

    # Extracting re-encryption params
    #pk = re_enc_info[re_enc_params[0]]
    #sk = re_enc_info[re_enc_params[1]]
    pairing_group = re_enc_info[re_enc_params[4]]
    seed = bytesToObject(unhexlify(re_enc_info[re_enc_params[0]]), pairing_group) \
        if re_enc_info[re_enc_params[0]] is not None else None
    key = bytesToObject(unhexlify(re_enc_info[re_enc_params[1]]), pairing_group)
    re_enc_length = re_enc_info[re_enc_params[2]]
    iv = unhexlify(re_enc_info[re_enc_params[3]])
    #policy = str(PolicyParser().parse(re_enc_info[re_enc_params[6]]))
    init_val = re_enc_info[re_enc_params[5]]

    if debug:  # ONLY USE FOR DEBUG
        print('EXTRACTED RE-ENC PARAMS:\nSEED = %s\nKEY = %s\nRE-ENC LENGTH = %d\n'
              'IV = (%d) %s' % (seed, key, re_enc_length, len(iv), iv))
        #print('EXTRACTED RE-ENC PARAMS:\nPK = %s\nSK = %s\nSEED = %s\nKEY = %s\nRE-ENC LENGTH = %d\n'
        #      'IV = (%d) %s\nPOLICY = %s' % (pk, sk, seed, key, re_enc_length, len(iv), iv, policy))

    # Check if parameters are set
    # if pk is None:
    #     logging.error('get_re_enc_params pk exception')
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('EXCEPTION in get_re_enc_params pk')
    #     raise Exception
    #
    # if sk is None:
    #     logging.error('get_re_enc_params sk exception')
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('EXCEPTION in get_re_enc_params sk')
    #     raise Exception

    if seed is None:
        logging.error('get_re_enc_params seed exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_re_enc_params seed')
        raise Exception

    if key is None:
        logging.error('get_re_enc_params key exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_re_enc_params key')
        raise Exception

    if re_enc_length is None:
        logging.error('get_re_enc_params re_enc_length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_re_enc_params re_enc_length')
        raise Exception

    if iv is None:
        logging.error('get_re_enc_params iv exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_re_enc_params iv')
        raise Exception

    # if policy is None:
    #     logging.error('get_re_enc_params policy exception')
    #     if debug:  # ONLY USE FOR DEBUG
    #         print('EXCEPTION in get_re_enc_params policy')
    #     raise Exception

    if init_val is None:
        logging.error('get_re_enc_params init_val exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_re_enc_params init_val')
        raise Exception

    # Decrypt seed, key and re_enc_length with ABE using given public and secret keys
    # seed = None
    # if enc_seed is not None:
    #     enc_seed['policy'] = str(policy)
    #     seed = abe.decrypt(enc_seed, pk, sk, pairing_group, debug)
    # enc_key['policy'] = str(policy)
    # key = abe.decrypt(enc_key, pk, sk, pairing_group, debug)

    if debug:  # ONLY USE FOR DEBUG
        print('SEED =', seed)
        print('KEY =', key)
        print('RE-ENC LENGTH =', re_enc_length)

    # Convert seed, key and re_enc_length from pairing group elements to useful values
    seed = objectToBytes(seed, pairing_group)[: const.SEED_LENGTH] if seed is not None else None
    key = objectToBytes(key, pairing_group)[: const.SYM_KEY_DEFAULT_SIZE]

    return seed, key, iv, re_enc_length, init_val
