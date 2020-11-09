import sys
import os
import secrets
import tempfile
import json
from pathlib import Path

from Crypto.Cipher import AES
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.core.engine.util import objectToBytes, bytesToObject
from ABE.ac17 import AC17CPABE

from fuse import FUSE, FuseOSError, Operations

from passthrough import Passthrough


import logging
logging.basicConfig()
logger = logging.getLogger('fuse')
logger.info("started")

class Abebox(Passthrough):
    def __init__(self, root):
        self.SYM_KEY_LEN = 16
        self.SYM_NONCE_LEN = 8 

        self.CHUNK_SIZE = 1024

        #load abe key
        self._load_abe_keys(str(Path.home()) + '/.abe_keys')

        super(Abebox, self).__init__(root)

    # Utility functions

    def _read_in_chunks(self, file_object, chunk_size=1024):
        """Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k."""
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def _load_abe_keys(self, abe_keys_file):
        """Load public and private abe keys"""

        print("Loading abe keys from " + abe_keys_file)
        with open(abe_keys_file, 'r') as f:
            data = json.load(f)

        self.pairing_group = PairingGroup('MNT224')
        self.abe_pk = bytesToObject(bytes.fromhex(data['pk']), self.pairing_group)
        self.abe_sk = bytesToObject(bytes.fromhex(data['sk']), self.pairing_group)
        self.cpabe = AC17CPABE(self.pairing_group, 2)

    def _create_meta(self):
        """Create meta information about the file with keys
        """
        self.meta = {
                'sym_key': secrets.token_hex(self.SYM_KEY_LEN),
                'sym_nonce': secrets.token_hex(self.SYM_NONCE_LEN),
                'policy': '(DEPT1 and TEAM1)', # hardcoded - TBD
        }
        return self.meta
        

    def _load_meta(self, metafile):
        """Fetch, decrypt and decode the metafile containing keys.
        Create if it does not exist.
        """
        try:
            print("try to open metafile: " + metafile)
            with open(metafile) as f:
                enc_meta = json.load(f)
        except FileNotFoundError:
            print("Metafile not found")
            # TBD: try to recover?

        enc_sym_key = bytearray.fromhex(enc_meta['enc_sym_key'])
        # decrypt the sym key
        sym_key = cpabe.decrypt(self.abe_pk, enc_sym_key, self.abe_sk)

        # create a symmetric cypher
        self.sym_cipher = AES.new(self.sym_key, AES.MODE_CTR, nonce=bytearray.fromhex(self.finfo['nonce']))

        self.meta = {
                'sym_key': enc_meta,
                'nonce': bytearray.fromhex(enc_meta['nonce']),
                'policy': '(DEPT1 and TEAM1)', # hardcoded - TBD
        }
        return self.finfo

    def _dump_meta(self, metafile):
        """Dump the meta information on the meta file
        """
        enc_sym_key = self.cpabe.encrypt(self.abe_pk, self.meta['sym_key'], self.meta['policy'])
        enc_meta = {
            'sym_key': enc_sym_key,        
            'nonce': self.meta['nonce'],        
            'policy': '(DEPT1 and TEAM1)', # hardcoded - TBD
        }
        json.dump(metafile, enc_meta)
        return enc_meta

    # Fuse callbacks

    def read(self, path, length, offset, fh):
        return super(Abebox, self).read(path, length, offset, self.temp_fp)
    
    def write(self, path, buf, offset, fh):
        return super(Abebox, self).write(path, buf, offset, self.temp_fp)

    def open(self, path, flags):
        print("Opening file ", path)
        self.is_new = False

        # load meta information
        self.dirname, self.filename = os.path.split(os.path.dirname(self._full_path(path))) 
        print("dirname {} - filename {}", self.dirname, self.filename)
        self._load_meta(self.dirname + '/.abebox/' + self.filename)

        # open a temporary file
        self.temp_fp = tempfile.TemporaryFile() # could be more secure with mkstemp()

        # TBD reverse AONT and remove re-encryption

        # decrypt the file with the sym key and write it on the temporary file
        with open(self._full_path(path), 'r') as enc_fp:
            for chunk in self._read_in_chunks(enc_fp, self.CHUNK_SIZE):
                self.temp_fp.write(self.cipher.decrypt(chunk))

        return self.temp_fp.fileno()
        #return super(Abebox, self).open(path, flags)
        
    def create(self, path, mode, fi=None):
        print("Creating file ", path)
        # open a temporary file
        self.temp_fp = tempfile.TemporaryFile() # could be more secure with mkstemp() 

        self.dirname, self.filename = os.path.split(os.path.dirname(self._full_path(path))) 
        self.is_new = True

        self._create_meta()

        return self.temp_fp.fileno()


    def release(self, path, fh):
        print("Releasing file ", path)
        # pour the temp file in the dest folder
        self.temp_fp.seek(0)
        with open(self._full_path(path), 'w') as enc_fp:
            for chunk in self._read_in_chunks(self.temp_fp, self.CHUNK_SIZE):
                enc_fp.write(self.cipher.encrypt(chunk))

        self._dump_meta(self.dirname + '/.abebox/' + self.filename)

        self._create_meta(self.dirname + '/.abebox/' + self.filename)

        # ret = os.close(self.temp_fp) # temporary files are automatically deleted


def main(mountpoint, root):
    FUSE(Abebox(root), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Syntax: " + sys.argv[0] + " basedir mountdir")
    main(sys.argv[2], sys.argv[1])
