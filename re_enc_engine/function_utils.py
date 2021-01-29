"""
This file contains all the common basic functions used from the software.
"""


def generate_random_string(length=None, debug=0):
    """
    Generate a random byte string with the given length.
    :param length: length in bytes of the string to generate
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the random bytes string
    """

    import logging

    # Check if length is set
    if length is None:
        logging.error('generate_random_string length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in generate_random_string length')
        raise Exception

    import os

    # Return a random string with the given length
    return os.urandom(length)


def clamp(value=None, lower_bound=None, upper_bound=None, debug=0):
    """
    Clamp the given value between lower and upper bounds.
    :param value: value to clamp
    :param lower_bound: minimum value
    :param upper_bound: maximum value
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: the clamped value
    """

    # Check if params are set
    if value is None or lower_bound is None or upper_bound is None:
        return None

    # if debug:  # ONLY USE FOR DEBUG
    #     print('Clamping: value = %d\tlower_bound = %d\tupper_bound = %d' % (value, lower_bound, upper_bound))

    # Return the clamped value
    return max(lower_bound, min(value, upper_bound))


def read_bytes_from_file(infile=None, debug=0):
    """
    Read all bytes in the given file.
    :param infile: file to read
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    :return: read bytes
    """

    import logging
    import os.path

    # Check if infile is set and it exists
    if infile is None or not os.path.isfile(infile):
        logging.error('read_file_bytes infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in read_file_bytes infile')
        raise Exception

    # Return data from the infile
    return open(infile, 'rb').read()


def write_bytes_on_file(outfile=None, data=None, mode='wb', offset=0, debug=0):
    """
    Write the given data to the specified offset in the given file with the specified mode.
    :param outfile: file where data will be written
    :param data: data to write
    :param mode: file opening mode
    :param offset: file offset
    :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
    """

    import logging

    # Check if outfile is set
    if outfile is None:
        logging.error('write_bytes_on_file outfile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in write_bytes_on_file outfile')
        raise Exception

    # Check if data is set
    if data is None:
        logging.error('write_bytes_on_file data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in write_bytes_on_file data')
        raise Exception

    # Write data on the outfile
    with(open(outfile, mode)) as fout:
        fout.seek(offset)
        fout.write(data)


def clear_folder(folder_path=None, debug=0):
    """
    Delete data files in the specified folder generated from previous executions.
    :param folder_path: directory whose files have to be deleted
    """

    import logging
    import os

    # Check if folder_path is set and it exists
    if folder_path is None or not os.path.isdir(folder_path):
        logging.error('clear_folder folder_path exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in clear_folder folder_path')
        raise Exception

    # Get files from the directory
    for filename in os.listdir(folder_path):

        # Get file path
        file_path = os.path.join(folder_path, filename)

        # Remove the file
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)


def init_logger():
    """
    Initialise logger
    """

    from re_enc_engine.const import LOG_FILE_PATH, LOG_FILE_NAME
    from datetime import datetime
    import logging
    import os.path

    # Create log file directory if it does not exist
    if not os.path.isdir(LOG_FILE_PATH):
        os.mkdir(LOG_FILE_PATH)

    # Get current time
    current_time = datetime.now()

    # Define log file
    log_file = LOG_FILE_PATH + LOG_FILE_NAME + current_time.strftime('%Y_%m_%d')

    # Set logger configuration
    logging.basicConfig(filename=log_file, filemode='a', format='%(asctime)s\t[%(levelname)s] %(name)s : %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
