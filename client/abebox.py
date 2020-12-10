import sys
import os
import secrets
import tempfile
import json
from pathlib import Path

from Crypto.Cipher import AES
from charm.toolbox.pairinggroup import PairingGroup, GT 
from charm.core.math.pairing import hashPair as extractor
#from charm.toolbox.node import BinNode
from charm.toolbox.policytree import PolicyParser
from charm.core.engine.util import objectToBytes, bytesToObject
from ABE.ac17 import AC17CPABE
#from charm.toolbox.symcrypto import SymmetricCryptoAbstraction

from fuse import FUSE, FuseOSError, Operations

from passthrough import Passthrough

import aont

import logging
logging.basicConfig()
logger = logging.getLogger('fuse')
logger.info("started")


class Abebox(Passthrough):

    def __init__(self, root):
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
        #https://jhuisi.github.io/charm/toolbox/symcrypto.html#symcrypto.SymmetricCryptoAbstraction
        el = self.pairing_group.random(GT)

        self.meta = {
                'el': el,
                'sym_key': extractor(el),
                'nonce': secrets.token_bytes(8),
                'policy': '(DEPT1 and TEAM1)', # hardcoded - TBD
        }

        #self.sym_cipher = SymmetricCryptoAbstraction(self.meta['sym_key'])

        return self.meta
        

    def _load_meta(self, metafile):
        """Fetch, decrypt and decode the metafile containing keys.
        Create if it does not exist.
        """
        try:
            print("try to open metafile: " + metafile)
            with open(metafile, 'r') as f:
                enc_meta = json.load(f)
        except FileNotFoundError:
            print("Metafile not found")
            # TBD: try to recover?

        enc_el = bytesToObject(bytearray.fromhex(enc_meta['enc_el']), self.pairing_group)
        policy = PolicyParser().parse(enc_meta['policy'])
        enc_el['policy'] = policy
        # decrypt the group element with ABE
        print("decrypt")
        print("pk: ", self.abe_pk)
        print("sk: ", self.abe_sk)
        print("policy: ", enc_el['policy'])

        el = self.cpabe.decrypt(self.abe_pk, enc_el, self.abe_sk)

        # load all in clear
        self.meta = {
                'el': el,
                'sym_key': extractor(el),
                'nonce': bytearray.fromhex(enc_meta['nonce']),
                'policy': enc_meta['policy'], #'(DEPT1 and TEAM1)', # hardcoded - TBD
                'original_data_length': enc_meta['original_data_length']
        }

        print('IN _LOAD_META:', self.meta['original_data_length'])

        # create a symmetric cypher
        #self.sym_cipher = SymmetricCryptoAbstraction(self.meta['sym_key'])

        return self.meta

    def _dump_meta(self, metafile):
        """Dump the meta information on the meta file
        """
        print("dumping metadata on file ", metafile)
        # we need to handle separately enc_el (charm.toolbox.node.BinNode) as there is no serializer
        enc_el = self.cpabe.encrypt(self.abe_pk, self.meta['el'], self.meta['policy'])
        policy = enc_el.pop('policy')

        print('IN _DUMP_META:', self.meta['original_data_length'])

        # write encrypted data
        enc_meta = {
            'policy': str(policy), 
            'nonce': self.meta['nonce'].hex(),
            'enc_el': objectToBytes(enc_el, self.pairing_group).hex(),
            'original_data_length': self.meta['original_data_length']
        }
        with open(metafile, 'w') as f:
            json.dump(enc_meta, f)
        return enc_meta

    # Fuse callbacks

    def read(self, path, length, offset, fh):
        print("reading ", length, " bytes on tmp fs ", self.temp_fp)
        return super(Abebox, self).read(path, length, offset, self.temp_fp.fileno())
    
    def write(self, path, buf, offset, fh):
        print("writing ", buf, " on ", path, " on tmp fs ", self.temp_fp)
        return super(Abebox, self).write(path, buf, offset, self.temp_fp.fileno())

    def open(self, path, flags):
        print("Opening file ", path)
        self.is_new = False

        # load meta information
        self.dirname, self.filename = os.path.split(self._full_path(path))

        self._load_meta(self.dirname + '/.abebox/' + self.filename)

        # open a temporary file
        self.temp_fp = tempfile.NamedTemporaryFile() #could be more secure with mkstemp()
        print("Created tempfile: ", self.temp_fp.name)

        # open real file
        full_path = self._full_path(path)

        #enc_fp = os.open(full_path, flags)
        enc_fp = open(full_path, 'rb+')

        # TBD reverse AONT and remove re-encryption
        original_data_len = self.meta['original_data_length']

        #decrypt the file with the sym key and write it on the temporary file
        sym_cipher = AES.new(self.meta['sym_key'][:16], AES.MODE_CTR, nonce=self.meta['nonce'])
        #with open(self._full_path(path), 'rb') as enc_fp:
        for chunk in self._read_in_chunks(enc_fp, self.CHUNK_SIZE):
            print("Remove AONT from encrypted data chunk")
            aont_args = {
                'nBits': self.CHUNK_SIZE,
                'k0BitsInt': 256,
                'original_data_length': original_data_len
            }
            chunk, original_data_len = aont.anti_transform(data=chunk, args=aont_args)
            print("AONT successfully removed")
            x = sym_cipher.decrypt(chunk)
            print("got chunk in open: ", x)
            self.temp_fp.write(x)
            #self.temp_fp.write(sym_cipher.decrypt(chunk))

        enc_fp.seek(0)
        self.temp_fp.seek(0)
        #os.lseek(enc_fp, 0, 0)
        return enc_fp.fileno()

        #return self.temp_fp.fileno()
        #return super(Abebox, self).open(path, flags)
        
    def create(self, path, mode, fi=None):
        print("Creating file ", path)
        print("full path", self._full_path(path))
        # open a temporary file
        self.temp_fp = tempfile.NamedTemporaryFile() #could be more secure with mkstemp()
        print("Created tempfile: ", self.temp_fp.name)

        self.dirname, self.filename = os.path.split(self._full_path(path))

        print("Dirname: ", self.dirname)
        print("file name: ", self.filename)
        self.is_new = True

        self._create_meta()

        #return self.temp_fp.fileno()
        #return super(Abebox, self).create(path, mode, fi)
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)


    def release(self, path, fh):
        print("Releasing file ", path)
        # pour the temp file in the dest folder
        sym_cipher = AES.new(self.meta['sym_key'][:16], AES.MODE_CTR, nonce=self.meta['nonce'])
        # rewind file, adjust read_in_chucnk 
        print("Release: closing, removing and open again file ", self._full_path(path))
        os.close(fh)
        print("close done")
        os.remove(self._full_path(path))
        print("rm done")
        #fh = os.open(self._full_path(path), os.O_WRONLY | os.O_CREAT)
        print("re-opening file")
        fh = open(self._full_path(path), 'wb+')
        print("re-opening file done")

        #print("seeking fh")
        #os.lseek(fh, 0, os.SEEK_SET)

        self.temp_fp.seek(0)
        print("Temporary file has size : ", self.temp_fp.seek(0, os.SEEK_END))
        self.temp_fp.seek(0)

        original_data_length = 0

        for chunk in self._read_in_chunks(self.temp_fp, self.CHUNK_SIZE):
            print("release - read chunk", chunk)
            # os.write(fh, sym_cipher.encrypt(chunk))
            # fh.write(sym_cipher.encrypt(chunk))
            enc_chunk = sym_cipher.encrypt(chunk)
            original_data_length += len(enc_chunk)
            print("Applying AONT to newly encrypted chunk")
            aont_args = {
                'nBits': self.CHUNK_SIZE,
                'k0BitsInt': 256
            }
            transf_enc_chunk = aont.transform(data=enc_chunk, args=aont_args)
            print("AONT successfully applied")
            fh.write(transf_enc_chunk)
            print("chunk has been written on file ", fh)
        #with open(self._full_path(path), 'wb+') as enc_fp:
        #    print("Release: file opened with fp ", enc_fp)
        #    print("release: writing back from tempfile", self.temp_fp.file.name)
        #    for chunk in self._read_in_chunks(self.temp_fp, self.CHUNK_SIZE):
        #        print("release - read chunk" , chunk)
        #        enc_fp.write(sym_cipher.encrypt(chunk))
        print("Closing fs")
        fh.close()
        print("Closed")

        self.meta['original_data_length'] = original_data_length
        print('IN RELEASE:', self.meta['original_data_length'])

        meta_directory = self.dirname + '/.abebox/' 
        if not os.path.exists(meta_directory):
            os.makedirs(meta_directory)
        print("dumping meta on :", meta_directory + self.filename)
        self._dump_meta(meta_directory + self.filename)
        return
        #return os.close(fh)
        #return fh.close()
        #return super(Abebox, self).release(path, fh) #os close doesn't return
        # ret = os.close(self.temp_fp) # temporary files are automatically deleted

    def truncate(self, path, length, fh=None):
        #full_path = self._full_path(path)
        self.temp_fp.truncate(length)
        #with open(full_path, 'r+') as f:
        #    f.truncate(length)

    def flush(self, path, fh):
        print("flushing")
        return os.fsync(self.temp_fp)
        #return os.fsync(fh)

    def fsync(self, path, fdatasync, fh):
        print("fsync")
        #return self.flush(path, fh)
        return self.flush(path, self.temp_fp)



def main(mountpoint, root):
    FUSE(Abebox(root), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Syntax: " + sys.argv[0] + " basedir mountdir")
    main(sys.argv[2], sys.argv[1])
