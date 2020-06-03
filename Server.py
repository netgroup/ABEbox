import subprocess
from DAO import connect

#conn = connect(host='172.25.0.3', port=27017, user='root', passw='abebox')
try:
    print('Trying connecting ABEbox DB...\n')
    conn = connect(host='172.25.0.3:3307', user='root', passw='abebox')
except:
    print('[ERROR] Connection failed!')
    exit()
print('Connection successful')
insert = conn.users.insert_one({'user': 'serse', 'pwd': 'serse', 'roles': [{'role': "readWrite", 'db': "users"}]})
print('Insertion:', insert)
result = conn.users.find_one({'user': 'serse'})
print('Query:', result)
exit()

bashCommand = "cpabe-setup"
bashCommand2 = "cpabe-enc pub_key (sysadmin and (hire_date < 946702800 or security_team)) or " \
               "(business_staff and 2 of (executive_level >= 5, audit_group, strategy_team))"
process = subprocess.Popen(bashCommand.split(),  stdout=subprocess.PIPE)
output, error = process.communicate()
print(output)
