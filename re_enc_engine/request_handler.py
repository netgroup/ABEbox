"""
This file contains all functions used to handle requests the web server receives and other minor functions.
"""

from hashlib import sha256

import dramatiq
import json
import logging
import os
import re_enc_engine.const as const
import re_enc_engine.function_utils as fu
import re_enc_engine.re_encryptor as re_enc
import time


def check_request_params(request_params, required_params):
    """
    Check if request parameters match the required ones.
    :param request_params: request parameters
    :param required_params: required parameters
    :return: true or false
    """

    for param in required_params:

        print('Checking param =', param)

        # Check if required parameter is not into the request ones
        if param not in request_params:
            return False

    return True


def get_company_root_dir(company_id=None, debug=0):
    """
    Create an unique ID for the given company ID that will be used as root directory.
    :param company_id: ID to make unique
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the unique ID
    """

    # Check if company_id is set
    if company_id is None:
        logging.error('[get_company_root_dir] Company ID is not set')
        if debug:  # ONLY USE FOR DEBUG
            print('[get_company_root_dir] Company ID = None')
        return None

    # Get used unique IDs from database
    used_ids_list = get_used_ids(debug)

    # Create a unique company ID
    while True:

        # Append to company ID a random string
        extended_company_id = company_id + str(fu.generate_random_string(const.RANDOM_LENGTH, debug))

        # Apply hash function to the concatenated string
        hashed_company_id = sha256(extended_company_id.encode(const.ENCODING)).hexdigest()

        # Test if the hashed company ID already exists in the database
        if hashed_company_id not in used_ids_list:
            break

    logging.info('Company ID = %s uniquely converted in %s' % (company_id, hashed_company_id))

    return hashed_company_id


def get_used_ids(debug=0):
    """
    Get unique IDs contains in the database.
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: used IDs list
    """

    # TODO get used IDs from database

    return []


def get_files_list(directory=None, debug=0):
    """
    Get all files in the given directory.
    :param directory: directory to scan
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the files list
    """

    # Check if directory is set
    if directory is None:
        logging.error('[get_files_list] Directory is not set')
        if debug:  # ONLY USE FOR DEBUG
            print('[get_files_list] Directory = None')
        return None

    # Check if directory exists
    if os.path.isdir(directory):

        file_names = []

        # Scan the directory tree and get files in the given directory
        for path, sub_dirs, files in os.walk(directory):
            for file in files:
                file_names.append(os.path.join(path, file))

        return file_names

    logging.error('[get_files_list] Directory does not exist')

    if debug:  # ONLY USE FOR DEBUG
        print('[get_files_list] Directory does not exist')

    return None


@dramatiq.actor
def send_re_enc_info(data=None, debug=0):
    """
    Handle re-encryption operations: save public keys file and execute re-encryptions.
    :param data: re-encryption parameters
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: Success or error
    """

    # Check if data is set
    if data is None:
        logging.error('[send_re_enc_info] Data is not set')
        if debug:  # ONLY USE FOR DEBUG
            print('[send_re_enc_info] Data = None')
        return const.BAD_REQ[0], const.BAD_REQ[1]

    logging.info('Retrieving re-encryption parameters from data...')

    if debug:  # ONLY USE FOR DEBUG
        print('Retrieving re-encryption parameters from data...')

    # Retrieve re-encryption parameter from data
    company_id = data[const.COMPANY_ID]
    time_interval = int(data[const.TIME_INTERVAL])
    full = int(data[const.FULL])
    re_enc_data = json.loads(data[const.RE_ENC_DATA])

    print('RE-ENC INFOs =', company_id, time_interval, full, re_enc_data)

    logging.info('Re-encryption parameters from data obtained!')
    logging.info('Saving sent public key files...')

    if debug:  # ONLY USE FOR DEBUG
        print('Re-encryption parameters from data obtained!')
        print('Saving sent public key files...')

    if not full:  # File-level re-encryption

        logging.info('File-level re-encryption is running...')

        if debug:  # ONLY USE FOR DEBUG
            print('File-level re-encryption is running...')

        for file_params in re_enc_data:

            print(file_params)

            # Check if required file re-encryption parameters are set
            if not check_request_params([key for key in file_params.keys()], const.SEND_RE_ENC_INFO_NESTED_PARAMS) and \
                    const.FILE_NAME not in file_params.keys():

                logging.error('Missing params!')
                logging.error('File re-encryption will be skipped!')

                if debug:  # ONLY USE FOR DEBUG
                    print('Missing params!')
                    print('File re-encryption will be skipped!')

                continue

            file_re_enc_worker(file_params, company_id, time_interval, debug)

    else:  # Full repository re-encryption

        logging.info('Full repository re-encryption is running...')

        if debug:  # ONLY USE FOR DEBUG
            print('Full repository re-encryption is running...')

        full_re_enc_worker.send(re_enc_data, company_id, time_interval, debug)

    return None


def save_files(files=None, dest_dir=None, debug=0):
    """
    Save given files in the specified destination directory
    :param files: files to save
    :param dest_dir: saving destination directory
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    # Check if files is set
    if files is None:
        logging.error('[save_files] Files are not set')
        if debug:  # ONLY USE FOR DEBUG
            print('[save_files] Files = None')
        return None

    # Check if dest_dir is set
    if dest_dir is None:
        logging.error('[save_files] Destination directory are not set')
        if debug:  # ONLY USE FOR DEBUG
            print('[save_files] Destination directory = None')
        return None

    # Create destination directory if it does not exist
    if not os.path.isdir(dest_dir):
        os.mkdir(dest_dir)

    # Save files in the specific destination
    for i in range(len(files)):

        file_name = '%s%d' % (const.PK_FILE, i)
        files[file_name].save(dest_dir + '/' + file_name)


@dramatiq.actor
def file_re_enc_worker(file_params=None, root_dir=None, time_interval=0, debug=0):
    """
    Create a different flow that handles file-level re-encryption operations.
    :param file_params: file-level re-encryption parameters
    :param root_dir: root directory for files
    :param time_interval: seconds between re-encryption operations
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: None if some error occurs
    """

    # Check if file_params is set
    if file_params is None:
        logging.error('[file_re_enc_worker] File parameters is not set')
        if debug:  # ONLY USE FOR DEBUG
            print('[file_re_enc_worker] File parameters = None')
        return None

    # Check if root_dir is set
    if root_dir is None:
        logging.error('[file_re_enc_worker] Root directory is not set')
        if debug:  # ONLY USE FOR DEBUG
            print('[file_re_enc_worker] Root directory = None')
        return None

    # Retrieve file-specific re-encryption parameters
    file_name = file_params[const.FILE_NAME]
    pub_keys = file_params[const.PUB_KEYS]
    policies = file_params[const.POLICIES]
    re_enc_lengths = file_params[const.RE_ENC_LENGTHS]

    print('FILE NAME =', file_name)
    print('PKs =', pub_keys)
    print('POLICIES =', policies)
    print('RE-ENC LENs =', re_enc_lengths)

    # Check if re-encryption parameters are correct
    if not os.path.isdir(root_dir):
        return const.BAD_REQ[0], const.BAD_REQ[1]

    print('dir esiste', root_dir + '/' + const.STORAGE_PATH + file_name)

    if file_name is None or not os.path.exists(root_dir + '/' + const.STORAGE_PATH + file_name):
        return const.BAD_REQ[0], const.BAD_REQ[1]

    print('file esiste')

    if len(pub_keys) == 0 or len(policies) == 0 or len(re_enc_lengths) == 0:
        return const.BAD_REQ[0], const.BAD_REQ[1]

    print('array a 0')

    if len(pub_keys) != 1 and len(pub_keys) != len(policies):
        return const.BAD_REQ[0], const.BAD_REQ[1]

    if len(re_enc_lengths) != 1 and len(re_enc_lengths) != len(policies):
        return const.BAD_REQ[0], const.BAD_REQ[1]

    # TODO check if previous re-encryptions on the given files are already running, choose what to do?

    for i in range(len(policies)):  # [NOTE: policies number is equal to number of re-encryptions]

        file_path = root_dir + '/' + const.STORAGE_PATH + file_name
        pub_key = root_dir + '/' + const.KEY_PATH

        # Get proper public key
        if len(pub_keys) == 1:
            pub_key += pub_keys[0]
        else:
            pub_key += pub_keys[i]

        # Get proper re-encryption length
        if len(re_enc_lengths) == 1:
            re_enc_length = re_enc_lengths[0]
        else:
            re_enc_length = re_enc_lengths[i]

        print('RE-ENC PARAMs =', file_path, re_enc_length, pub_key, policies[i])

        # Re-encrypt the specific file with related parameters
        re_enc.apply_re_encryption(file_path, re_enc_length, pub_key, policies[i], debug)

        if time_interval == 0:  # Single re-encryption operation
            break
        else:  # Periodic re-encryption
            time.sleep(time_interval)


@dramatiq.actor
def full_re_enc_worker(re_enc_params=None, root_dir=None, time_interval=0, debug=0):
    """
    Create a different flow that handles full root directory re-encryption operations.
    :param re_enc_params: repository-level re-encryption parameters
    :param root_dir: root directory for files
    :param time_interval: seconds between re-encryption operations
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: None if some error occurs
    """

    # Check if re_enc_params is set
    if re_enc_params is None:
        logging.error('[full_re_enc_worker] Re-encryption parameters is not set')
        if debug:  # ONLY USE FOR DEBUG
            print('[full_re_enc_worker] Re-encryption parameters = None')
        return None

    # Check if root_dir is set
    if root_dir is None or not os.path.isdir(root_dir):
        logging.error('[re_enc_worker] Root directory is not set or it does not exist')
        if debug:  # ONLY USE FOR DEBUG
            print('[re_enc_worker] Root directory = None OR isdir() = False')
        return None

    print(re_enc_params)

    if not check_request_params([key for key in re_enc_params.keys()], const.SEND_RE_ENC_INFO_NESTED_PARAMS):

        logging.error('Missing params!')

        if debug:  # ONLY USE FOR DEBUG
            print('Missing params!')

        return const.BAD_REQ[0], const.BAD_REQ[1]

    # Retrieve file-specific re-encryption parameters
    pub_keys = re_enc_params[const.PUB_KEYS]
    policies = re_enc_params[const.POLICIES]
    re_enc_lengths = re_enc_params[const.RE_ENC_LENGTHS]

    # Check if re-encryption parameters are correct
    if len(pub_keys) == 0 or len(policies) == 0 or len(re_enc_lengths) == 0:
        return const.BAD_REQ[0], const.BAD_REQ[1]

    if len(pub_keys) != 1 and len(pub_keys) != len(policies):
        return const.BAD_REQ[0], const.BAD_REQ[1]

    if len(re_enc_lengths) != 1 and len(re_enc_lengths) != len(policies):
        return const.BAD_REQ[0], const.BAD_REQ[1]

    # TODO check if previous re-encryptions on the given files are already running, choose what to do?

    # Get file in the directory
    files_list = get_files_list(root_dir + '/' + const.STORAGE_PATH, debug)

    for i in range(len(policies)):  # [NOTE: policies number is equal to number of re-encryptions]

        pub_key = root_dir + '/' + const.KEY_PATH

        # Get proper public key
        if len(pub_keys) == 1:
            pub_key += pub_keys[0]
        else:
            pub_key += pub_keys[i]

        # Get proper re-encryption length
        if len(re_enc_lengths) == 1:
            re_enc_length = re_enc_lengths[0]
        else:
            re_enc_length = re_enc_lengths[i]

        for file_name in files_list:

            # Re-encrypt the specific file with related parameters
            re_enc.apply_re_encryption(file_name, re_enc_length, pub_key, policies[i], debug)

        if time_interval == 0:  # Single re-encryption operation
            break
        else:  # Periodic re-encryption
            time.sleep(time_interval)


def is_valid_ip(ip=None, debug=0):
    """
    Check if the given IP address is valid.
    :param ip: IP address
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: true if the IP address is correct; otherwise, false
    """

    # Check if ip is set
    if ip is None:
        logging.error('IP address is not set')
        if debug:  # ONLY USE FOR DEBUG
            print('IP address = None')
        return False

    try:  # Test if IP address is IPv4 OR IPv6 AND all its values are in [0, 256], OR it is 'localhost'
        return (ip.count('.') == 3 or ip.count('.') == 5) and \
               all(0 <= int(num) < 256 for num in ip.rstrip().split('.')) or ip == 'localhost'

    except ValueError:  # Error during tests
        if debug:  # ONLY USE FOR DEBUG
            print('Invalid IP address')
        return False
