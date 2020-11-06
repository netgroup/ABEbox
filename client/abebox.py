import sys
import os
from fuse import FUSE, FuseOSError, Operations
from Crypto.Cipher import AES
from passthrough import Passthrough
import secrets

import logging
logging.basicConfig()
logger = logging.getLogger('fuse')
logger.info("started")

class Abebox(Passthrough):
    def __init__(self, root):
        self.symk = None
        self.symnonce = None
        self.SKEYLEN = 16
        self.SNONCELEN = 8 
        super(Abebox, self).__init__(root)

    def read(self, path, length, offset, fh):
        print("Read with symk ", self.symk, "\t nonce ", self.nonce)
        os.lseek(fh, offset, os.SEEK_SET)
        ct = os.read(fh, length)
        pt = self.cipher.decrypt(ct)
        return pt
    

    def write(self, path, buf, offset, fh):
        print("Write with symk ", self.symk, "\t nonce ", self.nonce)
        os.lseek(fh, offset, os.SEEK_SET)
        ct = self.cipher.encrypt(buf)
        #return os.write(fh, buf)
        return os.write(fh, ct)

    def open(self, path, flags):
        print("open")
        with open(self._full_path(path) + '.meta', 'r') as f:
            buf = f.read()
            self.symk = bytearray.fromhex(buf[:self.SKEYLEN*2])
            self.nonce = bytearray.fromhex(buf[self.SKEYLEN*2:])
            print("Symmetric Key: ", self.symk, "\t nonce: ", self.nonce)
            self.cipher = AES.new(self.symk, AES.MODE_CTR, nonce=self.nonce)
        return super(Abebox, self).open(path, flags)
        
    def create(self, path, mode, fi=None):
        print("Creating file ", path)
        symk = secrets.token_hex(self.SKEYLEN)
        nonce = secrets.token_hex(self.SNONCELEN)

        with open(self._full_path(path) + '.meta', 'w') as f:
            f.write(symk)
            f.write(nonce)

        self.symk = bytearray.fromhex(symk)
        self.nonce = bytearray.fromhex(nonce)
        self.cipher = AES.new(self.symk, AES.MODE_CTR, nonce=self.nonce)

        return super(Abebox, self).create(path, mode, fi)

    def release(self, path, fh):
        print("release")
        return super(Abebox, self).release(path, fh)


def main(mountpoint, root):
    FUSE(Abebox(root), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1])
