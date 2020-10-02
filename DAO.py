import mysql.connector as sql


# Establish the connection with SQL using credentials
# Params:
# - host = DB address (it can also contains the port)
# - user = user for authentication
# - passw = password for authentication
def connect(host='', user='', passw=''):

    # Verify correctness of parameters
    if host == '' or user == '' or passw == '':
        raise Exception

    # Execute connection
    return sql.connect(host=host, username=user, password=passw)
