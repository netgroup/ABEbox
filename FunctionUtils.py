# This file contains all the common basic functions used from the software.


# Generate a random string of length bytes.
# Params:
# - length = length in bytes of the string to generate
# - debug = if 1, prints will be shown during execution; default 0, no prints are shown
def generate_random_string(length=None, debug=0):

    from Log import log

    # Check if length is set
    if length is None:
        log('[ERROR] Generate random string length exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in generate_random_string length')
        raise Exception

    import os

    # Return a random string with the given length
    return os.urandom(length)


# Clamp the value between lower and upper bounds.
# Params:
# - value: integer to clamp
# - lower_bound: the minimum value
# - upper_bound: the maximum value
def clamp(value=None, lower_bound=None, upper_bound=None, debug=0):

    if value is None or lower_bound is None or upper_bound is None:
        return None

    if debug:
        print('Clamping: value = %d\tlower_bound = %d\tupper_bound = %d' % (value, lower_bound, upper_bound))

    return max(lower_bound, min(value, upper_bound))


def read_bytes_from_file(infile=None, debug=0):

    import os.path
    from Log import log

    # Check if infile is set and exists
    if infile is None or not os.path.isfile(infile):
        log('[ERROR] read_file_bytes infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in read_file_bytes infile')
        raise Exception

    # Return data from the infile
    return open(infile, 'rb').read()


def write_bytes_on_file(outfile=None, data=None, mode='wb', offset=0, debug=0):

    from Log import log

    # Check if outfile is set
    if outfile is None:
        log('[ERROR] write_bytes_on_file outfile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in write_bytes_on_file outfile')
        raise Exception

    # Write data on the outfile
    with(open(outfile, mode)) as fout:
        fout.seek(offset)
        fout.write(data)


def clear_folder(folder_path=None):

    import os

    for filename in os.listdir(folder_path):

        file_path = os.path.join(folder_path, filename)

        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)


def init_logger():

    from crypto.Const import LOG_FILE_PATH, LOG_FILE_NAME
    from datetime import datetime
    import logging

    current_time = datetime.now()
    log_file = LOG_FILE_PATH + LOG_FILE_NAME + current_time.strftime('%Y_%m_%d')
    logging.basicConfig(filename=log_file, filemode='a', format='%(asctime)s\t[%(levelname)s] %(name)s : %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

    logging.warning('FUNCTION UTILS LOG')
