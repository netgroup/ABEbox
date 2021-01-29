import aont
import json
import logging
import math
import os
import re_enc_primitives as re_enc
import secrets
import sys
import tempfile

from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as extractor
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.policytree import PolicyParser
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from Crypto.Cipher import AES
from fuse import FUSE, FuseOSError, Operations
from passthrough import Passthrough
from pathlib import Path


logging.basicConfig()
logger = logging.getLogger('fuse')
logger.info("started")


class Abebox(Passthrough):

    def __init__(self, root, chunk_size=128, random_size=32):

        # Define variables for AONT
        self.chunk_size = chunk_size
        self.random_size = random_size

        # Load ABE keys
        self._load_abe_keys(str(Path.home()) + '/.abe_keys')

        super(Abebox, self).__init__(root)

    # Utility functions

    def _read_in_chunks(self, file_object, chunk_size=128):
        """Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k."""
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def _load_abe_keys(self, abe_keys_file):
        """Load public and private abe keys"""

        # print("Loading abe keys from " + abe_keys_file)
        with open(abe_keys_file, 'r') as f:
            data = json.load(f)

        self.pairing_group = PairingGroup('MNT224')
        self.abe_pk = {}
        self.abe_sk = {}
        for abe_key_pair in data.keys():
            self.abe_pk[abe_key_pair] = bytesToObject(bytes.fromhex(data[abe_key_pair]['pk']), self.pairing_group)
            self.abe_sk[abe_key_pair] = bytesToObject(bytes.fromhex(data[abe_key_pair]['sk']), self.pairing_group)
        self.cpabe = CPabe_BSW07(self.pairing_group)

    def _create_meta(self):
        """Create meta information about the file with keys
        """
        # https://jhuisi.github.io/charm/toolbox/symcrypto.html#symcrypto.SymmetricCryptoAbstraction
        el = self.pairing_group.random(GT)

        self.meta = {
            'el': el,
            'sym_key': extractor(el),
            'nonce': secrets.token_bytes(8),
            'policy': '(DEPT1 and TEAM1)',  # hardcoded - TBD
            'chunk_size': self.chunk_size,
            'random_size': self.random_size,
            're_encs': []
        }

        # self.sym_cipher = SymmetricCryptoAbstraction(self.meta['sym_key'])

        return self.meta
        

    def _load_meta(self, metafile):
        """Fetch, decrypt and decode the metafile containing keys.
        Create if it does not exist.
        """
        try:
            # print("try to open metafile: " + metafile)
            with open(metafile, 'r') as f:
                enc_meta = json.load(f)
        except FileNotFoundError:
            # print("Metafile not found")
            # TBD: try to recover?
            error = 1  # TODO USED ONLY TO FILL PRINT DISABLING

        enc_el = bytesToObject(bytearray.fromhex(enc_meta['enc_el']), self.pairing_group)
        policy = PolicyParser().parse(enc_meta['policy'])
        enc_el['policy'] = str(policy)
        # print('ENC EL = (%s) %s' % (type(enc_el), enc_el))

        # Decrypt the group element with ABE
        # print("decrypt")
        # print("pk: ", next(iter(self.abe_pk.values())))
        # print("sk: ", next(iter(self.abe_sk.values())))
        # print("policy: ", enc_el['policy'])

        el = self.cpabe.decrypt(next(iter(self.abe_pk.values())), next(iter(self.abe_sk.values())), enc_el)
        # print('EL = (%s) %s' % (type(el), el))

        # Load all in clear
        self.meta = {
            'el': el,
            'sym_key': extractor(el),
            'nonce': bytearray.fromhex(enc_meta['nonce']),
            'policy': enc_meta['policy'],  # '(DEPT1 and TEAM1)', # hardcoded - TBD
            'chunk_size': enc_meta['chunk_size'],
            'random_size': enc_meta['random_size'],
            're_encs': enc_meta['re_encs']
        }

        # create a symmetric cypher
        # self.sym_cipher = SymmetricCryptoAbstraction(self.meta['sym_key'])

        return self.meta


    def _dump_meta(self, metafile):
        """Dump the meta information on the meta file
        """
        # print("dumping metadata on file ", metafile)
        # print('EL = (%s) %s' % (type(self.meta['el']), self.meta['el']))
        # we need to handle separately enc_el (charm.toolbox.node.BinNode) as there is no serializer
        enc_el = self.cpabe.encrypt(next(iter(self.abe_pk.values())), self.meta['el'], self.meta['policy'])
        # print('ENC EL = (%s) %s' % (type(enc_el), enc_el))
        policy = enc_el.pop('policy')

        # write encrypted data
        enc_meta = {
            'policy': str(policy), 
            'nonce': self.meta['nonce'].hex(),
            'enc_el': objectToBytes(enc_el, self.pairing_group).hex(),
            'chunk_size': self.meta['chunk_size'],
            'random_size': self.meta['random_size'],
            're_encs': self.meta['re_encs']
        }
        with open(metafile, 'w') as f:
            json.dump(enc_meta, f)

        return enc_meta


    def _create_re_enc_params(self, re_enc_op):
        """
        Create a dictionary with all parameters required for re-encryption operations
        """

        key_pair_label = re_enc_op['pk']
        pk = self.abe_pk[key_pair_label]
        sk = self.abe_sk[key_pair_label]

        return {
            'pk': pk,
            'sk': sk,
            'enc_seed': re_enc_op['enc_seed'],
            'enc_key': re_enc_op['enc_key'],
            're_enc_length': re_enc_op['re_enc_length'],
            'iv': re_enc_op['iv'],
            'policy': re_enc_op['policy'],
            'pairing_group': self.pairing_group
        }


    def _create_aont_transf_params(self, chunk_bytes_len):
        """
        Create a dictionary with all parameters required for AONT transformation
        """

        return {
            'nBits': (chunk_bytes_len + self.meta['random_size']) * 8,
            'k0BitsInt': self.meta['random_size'] * 8
        }


    def _create_aont_anti_transf_params(self, chunk_bytes_len):
        """
        Create a dictionary with all parameters required for AONT anti-transformation
        """

        return {
            'nBits': chunk_bytes_len * 8,
            'k0BitsInt': self.meta['random_size'] * 8
        }


    def _decode(self, full_path, chunk_num, offset, sym_cipher):
        """
        Remove AONT and encryption from the given chunk and write the result on the temporary file
        :param chunk_num: number of file chunk to anti-transform and decrypt
        :param offset: position where the result must be written
        :param sym_cipher: symmetric cipher
        """

        if self.enc_fp.closed:
            self.enc_fp = open(full_path, 'rb+')

        # Move file pointer
        self.enc_fp.seek(chunk_num * self.meta['chunk_size'])

        # Read file chunk
        chunk = self.enc_fp.read(self.meta['chunk_size'])

        # If applied, remove all re-encryption operations
        # print("Remove re-encryptions from file chunk")
        re_enc_ops_num = len(self.meta['re_encs'])
        if re_enc_ops_num > 0:
            for i in range(re_enc_ops_num):
                # Get re-enc parameters
                re_enc_args = self._create_re_enc_params(self.meta['re_encs'][re_enc_ops_num - 1 - i])
                # Remove re-encryption
                chunk = re_enc.re_decrypt(chunk, re_enc_args, 0)
                # print("DE-RE-ENCRYPTED CHUNK = (%d) %s" % (len(chunk), chunk))
                # print("Re-encryption successfully removed")
            # print("Re-encryptions successfully removed")

        # print("Remove AONT from encrypted file chunk")
        # Get AONT anti-transformation parameters
        aont_args = self._create_aont_anti_transf_params(len(chunk))
        # Anti-transform file chunk
        chunk = aont.anti_transform(chunk, aont_args, debug=0)
        # print("ANTI-TRANSFORMED CHUNK = (%d) %s" % (len(chunk), chunk))
        # print("AONT successfully removed")

        # Decrypt the anti-transformed file chunk with the sym key and write it on the temporary file
        x = sym_cipher.decrypt(chunk)
        # x = chunk
        # print("got chunk in _decode: ", x)

        # Write anti-transformed decrypted chunk on the temporary file at its proper position
        # print("writing on temp file at position", offset, "byte ", x)
        self.temp_fp.seek(offset)
        self.temp_fp.write(x)

        # Reset both file pointers
        self.enc_fp.seek(0)
        self.temp_fp.seek(0)


    def _from_plain_to_enc(self, pos):
        """
        Convert a plaintext position to the related in the transformed ciphertext
        """

        return pos + (math.floor(pos / (self.meta['chunk_size'] - self.meta['random_size'])) * self.meta['random_size'])


    def _get_aont_chunks_range(self, length, offset):
        """
        Compute AONT chunks related to the given offset and length (the last chunk is included)
        """

        # Compute offset and last byte to read in transformed encrypted file
        transf_offset = self._from_plain_to_enc(offset)
        transf_last_byte = self._from_plain_to_enc(length) - 1

        # Compute file chunks involved in reading process
        starting_aont_chunk_num = math.floor(transf_offset / self.meta['chunk_size'])
        ending_aont_chunk_num = math.floor(transf_last_byte / self.meta['chunk_size'])

        # print('AONT OFFSET =', transf_offset)
        # print('AONT LAST BYTE =', transf_last_byte)
        # print('STARTING AONT CHUNK NUM =', starting_aont_chunk_num)
        # print('ENDING AONT CHUNK NUM =', ending_aont_chunk_num)

        return starting_aont_chunk_num, ending_aont_chunk_num


    def _get_cipher_initial_value(self, offset):
        """
        Return the initial value to set as cipher block counter for the given offset
        """
        return offset // AES.new(self.meta['sym_key'][:16], AES.MODE_CTR, nonce=self.meta['nonce']).block_size


    def _get_decoded_offset(self, chunk_index):
        """
        Return offset of given chunk index in the decoded file
        """
        return chunk_index * (self.meta['chunk_size'] - self.meta['random_size'])


    def _get_encoded_offset(self, chunk_index):
        """
        Return offset of given chunk index in the encoded file
        """
        return chunk_index * self.meta['chunk_size']


    # Fuse callbacks

    def getattr(self, path, fh=None):

        # print('abebox getattr', path)

        full_path = self._full_path(path)

        st = os.lstat(full_path)
        d = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                 'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

        # Compute the correct file size removing AONT random chunks lengths
        if d['st_size'] > 0:
            d['st_size'] = d['st_size'] - (math.ceil(d['st_size'] / self.chunk_size) * self.random_size)

        # print('D', d)

        return d


    def read(self, path, length, offset, fh):

        # self.enc_fp.close()
        # self.enc_fp = open(self._full_path(path), 'rb')

        full_path = self._full_path(path)

        # print('READ ===============')
        # print('FULL PATH =', full_path)
        # print('PATH =', path)
        # print('OFFSET =', offset)
        # print('LENGTH =', length)

        # Compute length of the plaintext file and the related reading length
        file_size = os.path.getsize(full_path)
        temp_file_size = file_size - (math.ceil(file_size / self.meta['chunk_size']) * self.meta['random_size'])
        real_len = min(offset + length, temp_file_size)

        # Compute file chunks involved in reading process
        starting_aont_chunk_num, ending_aont_chunk_num = self._get_aont_chunks_range(real_len, offset)

        # Variable offset during file decoding
        # decode_offset = offset

        # Create symmetric cipher
        # sym_cipher = AES.new(self.meta['sym_key'][:16], AES.MODE_CTR, nonce=self.meta['nonce'])

        # Check if those chunks have already been processed
        for chunk_num in range(starting_aont_chunk_num, ending_aont_chunk_num + 1):
            # Check if chunk is already in the list, otherwise add it and all previous ones not inside the list
            if str(chunk_num) not in self.file_read_chunks.keys():
                # print('Chunk not in already read list')
                for prev_chunk_num in range(chunk_num + 1):
                    if str(prev_chunk_num) not in self.file_read_chunks.keys():
                        self.file_read_chunks[str(prev_chunk_num)] = 0
                        # print('Adding chunk #%d to the already read list with value %d'
                        #       % (prev_chunk_num, self.file_read_chunks[str(prev_chunk_num)]))
            # Check if chunk has already been processed
            if not self.file_read_chunks[str(chunk_num)]:
                # print('Chunk #%d needs to be processed' % chunk_num)
                # Compute offset on decoded file
                decoded_offset = self._get_decoded_offset(chunk_num)
                # print('DECODED OFFSET =', decoded_offset)
                # Compute initial value of cipher block counter
                init_val = self._get_cipher_initial_value(decoded_offset)
                # print('INITIAL VALUE =', init_val)
                # Create symmetric cipher with proper initial value
                sym_cipher = AES.new(self.meta['sym_key'][:16], AES.MODE_CTR, initial_value=init_val,
                                     nonce=self.meta['nonce'])
                # Anti-transform and decrypt chunk
                self._decode(full_path, chunk_num, decoded_offset, sym_cipher)
                # Set relative array chunk position as read
                self.file_read_chunks[str(chunk_num)] = 1
                # Update reading offset
                # decode_offset = decode_offset + self.meta['chunk_size'] - self.meta['random_size']

        # print("reading ", length, " bytes on tmp fs ", self.temp_fp)
        return super(Abebox, self).read(path, length, offset, self.temp_fp.fileno())


    def write(self, path, buf, offset, fh):

        # self.enc_fp.close()
        # self.enc_fp = open(self._full_path(path), 'wb')

        full_path = self._full_path(path)

        # print('PATH =', path)
        # print('FULL PATH =', full_path)
        # print('FH =', fh)
        # print('OFFSET =', offset)
        # print('BUFF =', buf)
        # print('BUFF LEN =', len(buf))

        # Compute file chunks involved in reading process
        starting_aont_chunk_num, ending_aont_chunk_num = self._get_aont_chunks_range(offset + len(buf), offset)

        # Check if those chunks have already been processed
        for chunk_num in range(starting_aont_chunk_num, ending_aont_chunk_num + 1):
            # Check if chunk is already in the list, otherwise add it and all previous ones not inside the list
            if str(chunk_num) not in self.file_written_chunks.keys():
                # print('Chunk not in already written list')
                for prev_chunk_num in range(chunk_num + 1):
                    if str(prev_chunk_num) not in self.file_written_chunks.keys():
                        self.file_written_chunks[str(prev_chunk_num)] = 1
                        # print('Adding chunk #%d to the already written list with value %d'
                        #       % (prev_chunk_num, self.file_written_chunks[str(prev_chunk_num)]))
            # Check if chunk has already been processed
            elif not self.file_written_chunks[str(chunk_num)]:
                # print('Chunk #%d needs to be processed' % chunk_num)
                # Compute offset on decoded file
                decoded_offset = self._get_decoded_offset(chunk_num)
                # print('DECODED OFFSET =', decoded_offset)
                # Compute initial value of cipher block counter
                init_val = self._get_cipher_initial_value(decoded_offset)
                # print('INITIAL VALUE =', init_val)
                # Create symmetric cipher with proper initial value
                sym_cipher = AES.new(self.meta['sym_key'][:16], AES.MODE_CTR, initial_value=init_val,
                                     nonce=self.meta['nonce'])
                # Anti-transform and decrypt chunk
                self._decode(full_path, chunk_num, decoded_offset, sym_cipher)
                # Set relative array chunk position as read
                self.file_written_chunks[str(chunk_num)] = 1

        # print("writing ", buf, " on ", path, " on tmp fs ", self.temp_fp)
        return super(Abebox, self).write(path, buf, offset, self.temp_fp.fileno())


    def open(self, path, flags):

        # print("Opening file ", path)
        self.is_new = False

        # load meta information
        self.dirname, self.filename = os.path.split(self._full_path(path))

        self._load_meta(self.dirname + '/.abebox/' + self.filename)

        # print('loaded meta')

        # Open a temporary file with given size
        self.temp_fp = tempfile.NamedTemporaryFile()  # could be more secure with mkstemp()
        # Compute temporary file size
        file_size = os.path.getsize(self._full_path(path))
        temp_file_size = file_size - (math.ceil(file_size / self.meta['chunk_size']) * self.meta['random_size'])
        # print('PATH = %s\nSIZE = %d' % (self._full_path(path), temp_file_size))
        self.temp_fp.seek(temp_file_size - 1)
        self.temp_fp.write(b'\0')
        # print("Created tempfile: ", self.temp_fp.name)
        # print('Wrote \\0 in position #', self.temp_fp.tell() - 1)

        # open real file
        full_path = self._full_path(path)

        # enc_fp = os.open(full_path, flags)
        # self.enc_fp.close()
        self.enc_fp = open(full_path, 'rb+')

        # Create two arrays: the first one to track already read file chunks; the second for modified ones
        self.file_read_chunks = {str(i): 0 for i in
                                 range(math.ceil(os.path.getsize(self._full_path(path)) / self.meta['chunk_size']))}
        self.file_written_chunks = {str(i): 0 for i in
                                    range(math.ceil(os.path.getsize(self._full_path(path)) / self.meta['chunk_size']))}

        # Reset file pointers
        self.enc_fp.seek(0)  # TODO PROBABILMENTE NON SERVE
        self.temp_fp.seek(0)
        #os.lseek(enc_fp, 0, 0)
        return self.enc_fp.fileno()
        #return self.temp_fp.fileno()
        #return super(Abebox, self).open(path, flags)


    def create(self, path, mode, fi=None):

        # print("Creating file ", path)
        # print("full path", self._full_path(path))

        # Open a temporary file with given size
        self.temp_fp = tempfile.NamedTemporaryFile()  # could be more secure with mkstemp()
        # print("Created tempfile: ", self.temp_fp.name)

        self.dirname, self.filename = os.path.split(self._full_path(path))

        # print("Dirname: ", self.dirname)
        # print("file name: ", self.filename)
        self.is_new = True

        # Create two empty arrays: the first one to track already read file chunks; the second for modified ones
        self.file_read_chunks = {}
        self.file_written_chunks = {}

        self._create_meta()

        # return self.temp_fp.fileno()
        # return super(Abebox, self).create(path, mode, fi)
        full_path = self._full_path(path)
        self.enc_fp = open(full_path, 'wb')
        # return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
        return self.enc_fp.fileno()


    def release(self, path, fh):

        # print("Releasing file ", path)

        # Create AES cipher
        # sym_cipher = AES.new(self.meta['sym_key'][:16], AES.MODE_CTR, nonce=self.meta['nonce'])
        # rewind file, adjust read_in_chucnk
        # # print("Release: closing, removing and open again file ", self._full_path(path))
        # os.close(fh)
        # # print("close done")
        # os.remove(self._full_path(path))
        # # print("rm done")
        # fh = os.open(self._full_path(path), os.O_WRONLY | os.O_CREAT)
        # # print("re-opening file")
        # fh = open(self._full_path(path), 'wb+')
        # # print("re-opening file done")

        # # print("seeking fh")
        # os.lseek(fh, 0, os.SEEK_SET)

        # Reset file pointer
        self.temp_fp.seek(0)
        # print("Temporary file has size : ", self.temp_fp.seek(0, os.SEEK_END))
        # self.temp_fp.seek(0)

        # Write only modified file chunks
        for chunk_num in self.file_written_chunks.keys():

            # print('CHUNK NUM # =', chunk_num, self.file_written_chunks[chunk_num])

            if self.file_written_chunks[chunk_num]:
                # print("release written chunk #", chunk_num)
                # # print("release - read chunk #", chunk)
                # os.write(fh, sym_cipher.encrypt(chunk))
                # fh.write(sym_cipher.encrypt(chunk))
                # Read file chunk
                # Set file pointer to file chunk starting byte
                self.temp_fp.seek(int(chunk_num) * (self.meta['chunk_size'] - self.meta['random_size']))
                # Read a file chunk from temporary file
                chunk = self.temp_fp.read(self.meta['chunk_size'] - self.meta['random_size'])
                # print('in release, read %d bytes = %s' % (len(chunk), chunk))
                # Compute offset on decoded file
                decoded_offset = self._get_decoded_offset(int(chunk_num))
                # print('DECODED OFFSET =', decoded_offset)
                # Compute initial value of cipher block counter
                init_val = self._get_cipher_initial_value(decoded_offset)
                # print('INITIAL VALUE =', init_val)
                # Create symmetric cipher with proper initial value
                sym_cipher = AES.new(self.meta['sym_key'][:16], AES.MODE_CTR, initial_value=init_val,
                                     nonce=self.meta['nonce'])
                # Encrypt file chunk
                enc_chunk = sym_cipher.encrypt(chunk)
                # enc_chunk = chunk
                # Transform encrypted file chunk
                # print("Applying AONT to newly encrypted chunk")
                # Get AONT parameters
                aont_args = self._create_aont_transf_params(len(enc_chunk))
                # Apply AONT to the encrypted chunk
                transf_enc_chunk = aont.transform(enc_chunk, aont_args, 0)
                # print("AONT successfully applied")
                # If previously applied, re-apply re-encryptions
                re_enc_transf_enc_chunk = transf_enc_chunk
                if len(self.meta['re_encs']) > 0:
                    # print("Re-applying re-encryptions to file chunk")
                    for re_enc_op in self.meta['re_encs']:
                        # Get re-encryption parameters
                        re_enc_args = self._create_re_enc_params(re_enc_op)
                        # Re-encrypt transformed encrypted chunk
                        re_enc_transf_enc_chunk = re_enc.re_encrypt(re_enc_transf_enc_chunk, re_enc_args, 1)
                        # print("RE-ENCRYPTED CHUNK = (%d) %s" % (len(re_enc_transf_enc_chunk), re_enc_transf_enc_chunk))
                        # print("Re-encryption successfully re-applied")
                    # print("Re-encryptions successfully re-applied")

                # print('WRITING FH =', fh)
                # print('CHUNK =', re_enc_transf_enc_chunk)
                # Compute offset on encoded file
                encoded_offset = self._get_encoded_offset(int(chunk_num))
                # Write transformed encrypted chunk
                os.lseek(fh, encoded_offset, os.SEEK_SET)
                os.write(fh, re_enc_transf_enc_chunk)
                # os.write(fh, chunk + 32*b'a')
                # print("chunk (%d) %s has been written on file %d" % (len(re_enc_transf_enc_chunk), re_enc_transf_enc_chunk, fh))
        # with open(self._full_path(path), 'wb+') as enc_fp:
        #    # print("Release: file opened with fp ", enc_fp)
        #    # print("release: writing back from tempfile", self.temp_fp.file.name)
        #    for chunk in self._read_in_chunks(self.temp_fp, self.CHUNK_SIZE):
        #        # print("release - read chunk" , chunk)
        #        enc_fp.write(sym_cipher.encrypt(chunk))
        # print("Closing fs")
        os.close(fh)
        # print("Closed")

        meta_directory = self.dirname + '/.abebox/'
        if not os.path.exists(meta_directory):
            os.makedirs(meta_directory)
        # print("dumping meta on :", meta_directory + self.filename)
        self._dump_meta(meta_directory + self.filename)

        self.enc_fp.close()
        self.temp_fp.close()

        return
        # return os.close(fh)
        # return fh.close()
        # return super(Abebox, self).release(path, fh) #os close doesn't return
        # ret = os.close(self.temp_fp) # temporary files are automatically deleted


    def truncate(self, path, length, fh=None):
        # full_path = self._full_path(path)
        self.temp_fp.truncate(length)
        # with open(full_path, 'r+') as f:
        #    f.truncate(length)

    def flush(self, path, fh):
        # print("flushing")
        return os.fsync(self.temp_fp)
        # return os.fsync(fh)

    def fsync(self, path, fdatasync, fh):
        # print("fsync")
        # return self.flush(path, fh)
        return self.flush(path, self.temp_fp)



def main(mountpoint, root):
    FUSE(Abebox(root), mountpoint, nothreads=True, foreground=True)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        # print("Syntax: " + sys.argv[0] + " basedir mountdir")
        error = 1  # TODO USED ONLY TO FILL PRINT DISABLING
    main(sys.argv[2], sys.argv[1])  # Optionally, you can pass chunk and random bytes sizes (defaults are respectively 128 and 32)
