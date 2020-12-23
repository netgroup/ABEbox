"""
Utility file: create a test msk and private key
"""

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.core.engine.util import objectToBytes, bytesToObject

#from bsw07 import BSW07
from ABE.ac17 import AC17CPABE

from pathlib import Path

import hashlib
import json


def main():
    # instantiate a bilinear pairing map
    # 'MNT224' represents an asymmetric curve with 224-bit base field
    pairing_group = PairingGroup('MNT224')

    # CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # run the set up
    (pk, msk) = cpabe.setup()

    # generate a user key
    user_attr_list = ['DEPT1', 'TEAM1']
    user_key = cpabe.keygen(pk, msk, user_attr_list)

    # generate a ciphertext
    #policy_str = '((PATIENT and SMART-1032702) or (PRACTITIONER and SMART-PRACTITIONER-72004454))'
    print("---------- PK ----------")
    print(pk)

    print("---------- MSK (needed only for debug)----------")
    print(msk)

    print("---------- SK ----------")
    print(user_key)

    data = {
        hashlib.sha256(objectToBytes(pk, pairing_group)).hexdigest(): {
            'pk': objectToBytes(pk, pairing_group).hex(),
            #'msk': msk,
            'sk': objectToBytes(user_key, pairing_group).hex(),
        }
    }

    #print(json.dumps(data))

    ######
    abe_keys_file = str(Path.home()) + '/.abe_keys'

    answer = input("Should I write them on your " + abe_keys_file + "[Y/N]? ").lower()
    if answer == 'y':
        with open(abe_keys_file, 'w') as f:
            json.dump(data, f)
        print("Done")
    else:
        print("Could we at least be friend?")



if __name__ == "__main__":
    main()

