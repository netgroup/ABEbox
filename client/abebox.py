import sys
import os
from fuse import FUSE, FuseOSError, Operations
from passthrough import Passthrough

import logging
logging.basicConfig()
logger = logging.getLogger('fuse')
logger.info("started")

class Abebox(Passthrough):
    def __init__(self, root):
        self.root = root

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        #print(type(buf))
        #print(len(buf))
        buf2 = "".join(['x' for i in range(len(buf))])
        #return os.write(fh, buf)
        return os.write(fh, buf2)

def main(mountpoint, root):
    FUSE(Abebox(root), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1])
