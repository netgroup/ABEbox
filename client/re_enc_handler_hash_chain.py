from binascii import unhexlify
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.policytree import PolicyParser

import abe_primitives as abe
import const
import function_utils as fu
import logging
import pairing_group_primitives as pg
import re_enc_primitives as re_enc


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

    if debug:  # ONLY USE FOR DEBUG
        print('SEED = (%d) %s' % (len(seed), seed))
        print('KEY = (%d) %s' % (len(key), key))
        print('IV = (%d) %s' % (len(iv), iv))

    # Apply re-encryption
    return re_enc.re_encrypt(data, re_enc_length, seed, key, iv, init_val, debug)


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

    if debug:  # ONLY USE FOR DEBUG
        print('SEED = (%d) %s' % (len(seed), seed))
        print('KEY = (%d) %s' % (len(key), key))
        print('IV = (%d) %s' % (len(iv), iv))

    # Remove re-encryption
    return re_enc.re_decrypt(data, re_enc_length, seed, key, iv, init_val, 0)


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
    #re_enc_params = ['pk', 'sk', 'seed', 'key', 're_enc_length', 'iv', 'policy', 'pairing_group', 'init_val',
    re_enc_params = ['seed', 'key', 're_enc_length', 'iv', 'pairing_group', 'init_val', 'last_re_enc_num',
                     'current_re_enc_num']

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
    last_re_enc_num = re_enc_info[re_enc_params[6]]
    current_re_enc_num = re_enc_info[re_enc_params[7]]

    if debug:  # ONLY USE FOR DEBUG
        print('EXTRACTED RE-ENC PARAMS:\nSEED = %s\nKEY = %s\nRE-ENC LENGTH = %d\nIV = (%d) %s\nCIPHER INIT VALUE = %d'
              '\nLAST RE-ENC NUM = %d\nCURRENT RE-ENC NUM = %d'
        #print('EXTRACTED RE-ENC PARAMS:\nPK = %s\nSK = %s\nSEED = %s\nKEY = %s\nRE-ENC LENGTH = %d\n'
              #'IV = (%d) %s\nPOLICY = %s\nCIPHER INIT VALUE = %d\nLAST RE-ENC NUM = %d\nCURRENT RE-ENC NUM = %d'
              % (seed, key, re_enc_length, len(iv), iv, init_val, last_re_enc_num, current_re_enc_num))
              #% (pk, sk, seed, key, re_enc_length, len(iv), iv, policy, init_val,
              #   last_re_enc_num, current_re_enc_num))

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

    if last_re_enc_num is None:
        logging.error('get_re_enc_params last_re_enc_num exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_re_enc_params last_re_enc_num')
        raise Exception

    if current_re_enc_num is None:
        logging.error('get_re_enc_params current_re_enc_num exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in get_re_enc_params current_re_enc_num')
        raise Exception

    # Decrypt seed, key and re_enc_length with ABE using given public and secret keys
    #seed = None
    #if enc_seed is not None:
    #    enc_seed['policy'] = str(policy)
    #    seed = abe.decrypt(enc_seed, pk, sk, pairing_group, debug)
    #enc_key['policy'] = str(policy)
    #key = abe.decrypt(enc_key, pk, sk, pairing_group, debug)

    seed = pg.hash_chain(pairing_group, seed, last_re_enc_num - current_re_enc_num)
    key = pg.hash_chain(pairing_group, key, last_re_enc_num - current_re_enc_num)
    iv = fu.hash_chain(iv, current_re_enc_num)

    if debug:  # ONLY USE FOR DEBUG
        print('SEED =', seed)
        print('KEY =', key)
        print('IV =', iv)
        print('RE-ENC LENGTH =', re_enc_length)

    # Convert seed, key and re_enc_length from pairing group elements to useful values
    seed = objectToBytes(seed, pairing_group)[: const.SEED_LENGTH] if seed is not None else None
    key = objectToBytes(key, pairing_group)[: const.SYM_KEY_DEFAULT_SIZE]

    return seed, key, iv, re_enc_length, init_val
