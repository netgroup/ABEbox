from Const import DEFAULT_AUTH_SOURCE, DEFAULT_AUTH_MECHANISM
from pymongo import MongoClient


# Establish the connection with MongoDB using credentials
def connect(host=None, port=None, user=None, passw=None, authDB=DEFAULT_AUTH_SOURCE):
    if host is None or port is None or user is None or passw is None:
        raise Exception
    return MongoClient(host=host, port=port, username=user, password=passw, authSource=authDB,
                       authMechanism=DEFAULT_AUTH_MECHANISM)
