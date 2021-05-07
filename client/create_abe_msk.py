"""
Utility file: create a test msk and private key
"""

from charm.core.engine.util import objectToBytes, bytesToObject
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from pathlib import Path

import argparse
import hashlib
import json
import pairing_group_primitives as pg


def main(store, abe_keys_outfile):

    # Instantiate a bilinear pairing map. 'MNT224' represents an asymmetric curve with 224-bit base field.
    pairing_group = pg.pairing_group_create('MNT224')

    # CP-ABE
    cpabe = CPabe_BSW07(pairing_group)

    # Run the setup algorithm
    (pk, msk) = cpabe.setup()

    # Generate a user secret key
    user_attr_list = ['DEPT1', 'TEAM1']
    user_key = cpabe.keygen(pk, msk, user_attr_list)

    # Generate keys data structure
    #policy_str = '((PATIENT and SMART-1032702) or (PRACTITIONER and SMART-PRACTITIONER-72004454))'
    #print("---------- PK ----------")
    #print(pk)

    #print("---------- MSK (needed only for debug)----------")
    #print(msk)

    #print("---------- SK ----------")
    #print(user_key)

    data = {
        hashlib.sha256(objectToBytes(pk, pairing_group)).hexdigest(): {
            'pk': objectToBytes(pk, pairing_group).hex(),
            #'msk': msk,
            'sk': objectToBytes(user_key, pairing_group).hex(),
        }
    }

    ## print(json.dumps(data))

    ######
    # abe_keys_file = str(Path.home()) + '/.abe_keys.json'

    # Ask if keys have to be saved
    if not store:
        store = True if input("Should I write them on your " + abe_keys_outfile + "[Y/N]? ").lower() == 'y' else False

    if store:
        with open(abe_keys_outfile, 'w') as f:
            json.dump(data, f)
        print("ABE keys have been saved in", abe_keys_outfile)
    else:
        print("Could we at least be friend?")


if __name__ == "__main__":

    # Parse input arguments
    parser = argparse.ArgumentParser(description='ABE keys creation script',
                                     usage='create_abe_msk.py -y [OPTIONAL: for keys saving] -o <OUTPUT FILE> '
                                           '[OPTIONAL]')
    parser.add_argument('-y', action='store_true', help='Directly save newly generated keys', default=False)
    parser.add_argument('-o', type=str, help='File where keys will be saved',
                        default=str(Path.home()) + '/.abe_keys.json')
    args = parser.parse_args()

    main(args.y, args.o)
