import mysql.connector as sql


# Establish the connection with SQL using credentials
# Params:
# - host = DB address (it can also contains the port)
# - user = user for authentication
# - passw = password for authentication
def connect(host=None, user=None, passw=None):

    # Verify correctness of parameters
    if host is None or user is None or passw is None:
        raise Exception

    # Execute connection
    return sql.connect(host=host, username=user, password=passw)
