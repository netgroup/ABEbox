"""
This file contains all constant and default values used in the Re-Encryption Engine.
"""

# HEADER PARAMS
VERSION = 1

# LOG DIRECTORY AND FILES
LOG_FILE_PATH = 'logs/'            # FOR DEPLOY, CHANGE TO ABSOLUTE PATH
LOG_FILE_NAME = 'log'

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