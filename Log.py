from crypto.Const import LOG_FILE_PATH, LOG_FILE_NAME
from datetime import datetime

import os


# Return current time
def get_current_time():
    return datetime.now()


# Write message on a daily log file
# Params:
# - message = text to write
def log(message):
    current_time = get_current_time()
    if not os.path.exists(LOG_FILE_PATH):
        os.makedirs(LOG_FILE_PATH)
    log_file = open(LOG_FILE_PATH + LOG_FILE_NAME + current_time.strftime('%Y%m%d'), 'a+')
    log_file.write('['+str(get_current_time())+'] ' + message)
