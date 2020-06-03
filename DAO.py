from Const import DEFAULT_AUTH_SOURCE, DEFAULT_AUTH_MECHANISM

import mysql.connector as sql


# Establish the connection with MongoDB using credentials
def connect(host=None, user=None, passw=None):
    if host is None or user is None or passw is None:
        raise Exception
    return sql.connect(host=host, username=user, password=passw)
