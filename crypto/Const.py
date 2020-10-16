"""
This file contains all constant and default values used in the program.
"""

# HEADER PARAMS
VERSION = 1

# LOG DIRECTORY AND FILES
LOG_FILE_PATH = './logs/'               # FOR DEPLOY, CHANGE TO ABSOLUTE PATH
LOG_FILE_NAME = 'log'

# TEMP DIRECTORY
TEMP_PATH = './tmp/'                    # FOR DEPLOY, CHANGE TO ABSOLUTE PATH

# OUTPUT DIRECTORY
OUTPUT_PATH = './output/'               # FOR DEPLOY, CHANGE TO ABSOLUTE PATH

# TEST DIRECTORY
TEST_PATH = './test/'                   # FOR DEPLOY, CHANGE TO ABSOLUTE PATH

# KEYS DIRECTORY
KEY_PATH = './keys/'                    # FOR DEPLOY, CHANGE TO ABSOLUTE PATH

# ABE
ABE_PK_FILE = 'pub_key'
ABE_MSK_FILE = 'master_key'
ABE_SK_FILE = 'priv_key'

# SYMMETRIC ENCRYPTION
SYM_KEY_MIN_SIZE = 16                   # 16 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE
SYM_KEY_DEFAULT_SIZE = 32               # 32 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE
IV_DEFAULT_SIZE = 16                    # 16 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE

# HYBRID RE-ENCRYPTION
RE_ENC_LENGTH = 16                      # 16 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE
RE_ENC_MIN_LENGTH = 12                  # 12 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE
SEED_LENGTH = 32                        # 32 BYTES -> [WARNING] CARE WHEN MODIFYING THIS VALUE

# ALL-OR-NOTHING TRANSFORMATION
AONT_DEFAULT_N = 1024                   # BITS
AONT_DEFAULT_K0 = 256                   # BITS
AONT_DEFAULT_N_K0_FILL = '0' + str(AONT_DEFAULT_N - AONT_DEFAULT_K0) + 'b'
AONT_DEFAULT_K0_FILL = '0' + str(AONT_DEFAULT_K0) + 'b'
AONT_DEFAULT_ENCODING = 'utf-8'

# FILE CHUNK
CHUNK_SIZE = (AONT_DEFAULT_N - AONT_DEFAULT_K0) // 8  # FILE BYTES TO PROCESS (USE A MULTIPLE OF THIS VALUE)

# STRUCT SIZES
B = 1                                   # 1 BYTE
H = 2                                   # 2 BYTES
Q = 8                                   # 8 BYTES
