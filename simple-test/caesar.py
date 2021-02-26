
from fuse import FUSE, FuseOSError, Operations
from passthrough import Passthrough
import os
import json
from random import seed, randint




class Caesar(Passthrough):
    def __init__(self, root):
        self.metadata_dir = root+"/.caesar"
        self._init_metadata_dir()
        self.metadata_dict = {}
        self.chunk_size = 128 # byte
        super(Caesar, self).__init__(root)
        #seed(100)

    # helper functions
    def _init_metadata_dir(self):
        if not os.path.exists(self.metadata_dir):
            os.makedirs(self.metadata_dir)

    def _load_metadata(self, path):
        with open(self.metadata_dir + path, 'r') as f:
            self.metadata_dict[path] = json.load(f)

    def _create_metadata(self, path):
        self.metadata_dict[path] = {
            "keys": []
        }
        print(self.metadata_dict)
            
    def _save_metadata(self, path):
        with open(self.metadata_dir + path, 'w') as f:
            print(self.metadata_dict)
            json.dump(self.metadata_dict[path], f)
            self.metadata_dict.pop(path)
    
    #remove the metadata folder
    def readdir(self, path, fh):
        full_path = self._full_path(path)
        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        if ".caesar" in dirents:
            dirents.remove(".caesar")       
        for r in dirents:
            yield r

    # file methods
    def open(self, path, flags):
        full_path = self._full_path(path)
        self._load_metadata(path)
        print(self.metadata_dict)
        fd = os.open(full_path, flags)
        print("open: "+str(fd))
        return fd

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        self._create_metadata(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)


    def decode_chunk(self, buf, key):
        return buf

    def encode_chunk(self, buf, key):
        return buf

    def read_chunk(self, path, fh, chunk_num):
        os.lseek(fh, (chunk_num-1)*self.chunk_size, os.SEEK_SET)
        buf = os.read(fh, self.chunk_size)
        # decode
        buf_decoded = self.decode_chunk(buf,0)
        return buf_decoded

    def write_chunk(self, path, fh, chunk_num, buf):
        os.lseek(fh, (chunk_num-1)*self.chunk_size, os.SEEK_SET)
        # encode
        buf_encoded = self.encode_chunk(buf,0)
        return os.write(fh, buf_encoded)


    def read(self, path, length, offset, fh):
        # scopro quanti chunk devo leggere
        os.lseek(fh, offset, os.SEEK_SET)
        buf = os.read(fh, length)
        print("path:{} l:{} o:{} bl:{} data={}".format(path, length, offset,len(buf),buf))
        return buf
        
    def write(self, path, buf, offset, fh):
        # scopro quanti chunk devo scrivere e genero i rand, li cifro e li scrivo
        os.lseek(fh, offset, os.SEEK_SET)
        print("path: "+path)
        print(buf)
        print("offset: "+str(offset))
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        return os.fsync(fh)

    def release(self, path, fh):
        self._save_metadata(path)
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)

    
def main(mountpoint, root):
    FUSE(Caesar(root), mountpoint, nothreads=True, foreground=True)




if __name__ == '__main__':
    main(os.sys.argv[2], os.sys.argv[1])