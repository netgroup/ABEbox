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


def write_bytes_on_file(outfile=None, data=None, debug=0):

    from Log import log

    # Check if outfile is set
    if outfile is None:
        log('[ERROR] write_bytes_on_file outfile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in write_bytes_on_file outfile')
        raise Exception

    # Write data on the outfile
    open(outfile, 'wb').write(data)


# Read JSON data from the given file.
# Params:
# - infile: file to read
# - debug = if 1, prints will be shown during execution; default 0, no prints are shown
def read_json_file(infile=None, debug=0):

    import os
    from Log import log

    # Check if infile is set and exists
    if infile is None or not os.path.isfile(infile):
        log('[ERROR] Read json file infile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in read_json_file infile')
        raise Exception

    import json

    # Return data from the input file
    with open(infile) as json_file:
        return json.load(json_file)


# Write JSON data to the given file.
# Params:
# - data: JSON data to write
# - outfile: file where data will be written
# - debug = if 1, prints will be shown during execution; default 0, no prints are shown
def write_json_file(data=None, outfile=None, debug=0):

    from Log import log

    # Check if data is set
    if data is None:
        log('[ERROR] Write json file data exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in write_json_file data')
        raise Exception

    # Check if file is set
    if outfile is None:
        log('[ERROR] Read json file outfile exception')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in read_json_file outfile')
        raise Exception

    import json

    # Write data on the output file
    with open(outfile, 'w') as json_file:
        return json.dump(data, json_file)
