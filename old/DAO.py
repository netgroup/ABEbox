"""
This file contains all the functions to interact with a SQL database.
"""

import mysql.connector as sql
import logging


def connect(host='', user='', passw='', debug=0):
    """
    Establish the connection with SQL database using credentials.
    :param host: database address (it can also contains the port)
    :param user: user for authentication
    :param passw: password for authentication
    """

    # Verify correctness of parameters
    if host == '' or user == '' or passw == '':
        logging.error('connect DB params')
        if debug:  # ONLY USE FOR DEBUG
            print('EXCEPTION in connect DB params')
        raise Exception

    # Execute connection
    return sql.connect(host=host, username=user, password=passw)
