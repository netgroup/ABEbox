"""
This file contains all constant and default values used in the Re-Encryption Engine.
"""

# HEADER PARAMS
VERSION = 1

# APPLICATION DIRECTORY
ROOT_PATH = './'   # FOR DEPLOY, CHANGE TO ABSOLUTE PATH
PARENT_DIR = '../'

# FLASK DIRECTORY
FLASK_ROOT_PATH = 'web/'              # FOR DEPLOY, CHANGE TO ABSOLUTE PATH

# LOG DIRECTORY AND FILES
LOG_FILE_PATH = 'logs/'            # FOR DEPLOY, CHANGE TO ABSOLUTE PATH
LOG_FILE_NAME = 'log'

# TEMP DIRECTORY
TEMP_PATH = 'old/tmp/'                    # FOR DEPLOY, CHANGE TO ABSOLUTE PATH

# OUTPUT DIRECTORY
OUTPUT_PATH = 'old/output/'               # FOR DEPLOY, CHANGE TO ABSOLUTE PATH

# TEST DIRECTORY
TEST_PATH = 'old/test/'                   # FOR DEPLOY, CHANGE TO ABSOLUTE PATH

# KEYS DIRECTORY
KEY_PATH = 'old/keys/'                    # FOR DEPLOY, CHANGE TO ABSOLUTE PATH

# STORAGE DIRECTORY
STORAGE_PATH = 'old/storage/'             # FOR DEPLOY, CHANGE TO ABSOLUTE PATH

# ABE
ABE_PK_FILE = 'pub_key'                 # Default public key file name
ABE_MSK_FILE = 'master_key'             # Default master secret key file name
ABE_SK_FILE = 'priv_key'                # Default secret key file name
PAIRING_GROUP_CURVE = 'MNT224'          # Asymmetric curve with 224-bit base field
POLICY = 'policy'

# SYMMETRIC ENCRYPTION
SYM_KEY_MIN_SIZE = 16                   # 16 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE
SYM_KEY_DEFAULT_SIZE = 32               # 32 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE
IV_DEFAULT_SIZE = 8                     # 8 BYTES  -> [WARNING] CARE WHEN MODIFYING THIS VALUE
IV_MAX_SIZE = 8                         # 8 BYTES  -> [WARNING] CARE WHEN MODIFYING THIS VALUE

# HYBRID RE-ENCRYPTION
RE_ENC_LENGTH = 16                      # 16 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE
RE_ENC_MIN_LENGTH = 12                  # 12 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE
SEED_LENGTH = 32                        # 32 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE

# STRUCT SIZES
B = 1                                   # 1 BYTE
H = 2                                   # 2 BYTES
Q = 8                                   # 8 BYTES

# RANDOMNESS
ENCODING = 'utf-8'
RANDOM_LENGTH = 32                      # 32 BYTES

# HTTP REQUEST FIELDS
COMPANY_ID = 'company_id'
FILES_LIST = 'files_list'
TIMELY = 'timely'
TIME_INTERVAL = 'time_interval'
FULL = 'full'
CHUNK_SIZE = 'chunk_size'
RE_ENC_DATA = 're_enc_data'
RE_ENC_PARAMS = 're_enc_params'
FILE_NAME = 'file_name'
PUB_KEYS = 'pub_keys'
POLICIES = 'policies'
RE_ENC_LENGTHS = 're_enc_lengths'
PK_FILE = 'pk_file'

# HTTP METHODS, ROUTES AND REQUIRED PARAMETERS
GET = 'GET'
POST = 'POST'
GET_COMPANY_ROOT_DIR = 'get_root_dir'
GET_COMPANY_ROOT_DIR_PARAMS = [COMPANY_ID]
GET_FILES_LIST = 'get_files_list'
GET_FILES_LIST_PARAMS = [COMPANY_ID]
SEND_RE_ENC_INFO = 'send_re_enc_info'
SEND_RE_ENC_INFO_PARAMS = [COMPANY_ID, TIME_INTERVAL, FULL, RE_ENC_DATA]
SEND_RE_ENC_INFO_NESTED_PARAMS = [PUB_KEYS, POLICIES, RE_ENC_LENGTHS]

# STATUS AND ERROR
OK = 200
BAD_REQ = ['Bad request', 400]
INVALID_IP = ['[ERROR] Invalid IP address!', 500]
NO_RESULT = ['[ERROR] Invalid operation result!', 500]
