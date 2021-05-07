from binascii import hexlify, unhexlify
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as extractor
from charm.toolbox.pairinggroup import GT
from charm.toolbox.policytree import PolicyParser
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from Crypto.Cipher import AES
from fuse import FUSE, FuseOSError, Operations
from passthrough import Passthrough
from pathlib import Path
from time import time

import abe_primitives as abe
import aont
import argparse
import const
import function_utils as fu
import hashlib
import json
import logging
import math
import os
import pairing_group_primitives as pg
import abebox_re_enc_handler as re_enc
import secrets
import sym_enc_primitives as sym
import tempfile


# Define logger
logging.basicConfig()
logger = logging.getLogger('fuse')
logger.info("started")


class Abebox(Passthrough):

    def __init__(self, root, chunk_size=128, random_size=32, initial_re_encs_num=0, max_re_encs_num=1024, debug=0):
        """
        Initialise global system parameters
        :param root: intercepted directory
        :param chunk_size: chunk size in bytes for AONT operations
        :param random_size: random part size in bytes for AONT operations
        :param initial_re_encs_num: number of initial re-encryptions to apply to new files [USED ONLY FOR PERFORMANCE EVALUATION]
        :param max_re_encs_num: maximum number of permitted re-encryptions [USED FOR REVERSE HASH CHAINING]
        :param debug: if 1, prints will be shown during execution; default 0, no prints are shown
        """

        # Define starting time in millis for performance evaluation
        self.starting_time = time() * 1000.0

        # Define variables for AONT
        self.chunk_size = chunk_size
        self.random_size = random_size

        # Define re-encryption variables
        self.pairing_group = pg.pairing_group_create(const.PAIRING_GROUP_CURVE)
        self.initial_re_encs_num = initial_re_encs_num
        self.max_re_encs_num = max_re_encs_num
        _, self.last_seed_pg_elem = pg.random_string_gen(self.pairing_group, const.SEED_LENGTH)
        _, self.last_key_pg_elem = pg.sym_key_gen(self.pairing_group, const.SYM_KEY_DEFAULT_SIZE)
        self.root_iv = sym.iv_gen(const.IV_DEFAULT_SIZE)
        self.re_enc_args = [None for _ in range(self.initial_re_encs_num)]

        # Define debug variable
        self.debug = debug

        # Load ABE keys
        self._load_abe_keys(str(Path.home()) + '/.abe_keys.json')

        super(Abebox, self).__init__(root)

    # Utility functions

    # Take the time
    # def __getattribute__(self,name):
    #     attr = object.__getattribute__(self, name)
    #     if hasattr(attr, '__call__'):
    #         def newfunc(*args, **kwargs):
    #             starting_time = time() * 1000.0
    #             result = attr(*args, **kwargs)
    #             elapsed_time = (time() * 1000.0) - starting_time
    #             elapsed_time_from_beginning = (time() * 1000.0) - self.starting_time
    #             print('[{}] [{}] done calling {}'.format(elapsed_time_from_beginning, elapsed_time, attr.__name__))
    #             return result
    #         return newfunc
    #     else:
    #         return attr


    def _read_in_chunks(self, file_object, chunk_size=128):
        """
        Lazy function (generator) to read a file piece by piece
        :param file_object: file object to read
        :param chunk_size: size in bytes of the file chunk to read
        :return: read data
        """

        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data


    def _load_abe_keys(self, abe_keys_file):
        """
        Load ABE public and secret keys from the given file
        :param abe_keys_file: file where keys are stored
        """

        if self.debug:
            print("Loading abe keys from " + abe_keys_file)

        # Read file content
        with open(abe_keys_file, 'r') as f:
            data = json.load(f)

        # Retrieve ABE public and secret keys
        self.abe_pk = {}
        self.abe_sk = {}
        for abe_key_pair in data.keys():
            self.abe_pk[abe_key_pair] = bytesToObject(bytes.fromhex(data[abe_key_pair]['pk']), self.pairing_group)
            self.abe_sk[abe_key_pair] = bytesToObject(bytes.fromhex(data[abe_key_pair]['sk']), self.pairing_group)

        # Create CP-ABE cipher
        self.cpabe = CPabe_BSW07(self.pairing_group)


    def _create_meta(self):
        """
        Create meta information about the file with keys
        :return: created meta information
        """

        # Get a random element of the pairing group used for symmetric key generation
        el = self.pairing_group.random(GT)

        # Create meta information
        self.meta = {
            'el': el,
            'sym_key': extractor(el),
            'nonce': secrets.token_bytes(8),
            'policy': '(DEPT1 and TEAM1)',  # TODO CHANGE FOR REAL USE
            'chunk_size': self.chunk_size,
            'random_size': self.random_size,
            're_encs': []
        }

        # Add re-encryption information
        self._add_initial_re_encs_info(self.initial_re_encs_num)

        return self.meta
        

    def _load_meta(self, metafile):
        """
        Fetch, decrypt and decode the metafile containing keys TODO (create if it does not exist?)
        :param metafile: metadata file
        :return: loaded meta information
        """

        # Read file content
        try:
            if self.debug:
                print("try to open metafile: " + metafile)
            with open(metafile, 'r') as f:
                enc_meta = json.load(f)
        except FileNotFoundError:
            # print("Metafile not found")
            # TBD: try to recover?
            error = 1  # TODO USED ONLY TO FILL PRINT DISABLING

        # Retrieve encrypted pairing group element information
        enc_el = bytesToObject(bytearray.fromhex(enc_meta['enc_el']), self.pairing_group)
        policy = PolicyParser().parse(enc_meta['policy'])
        enc_el['policy'] = str(policy)

        # Decrypt the pairing group element with CP-ABE
        el = abe.decrypt(enc_el, next(iter(self.abe_pk.values())), next(iter(self.abe_sk.values())), self.pairing_group,
                         self.debug)

        if self.debug:
            print("decrypt")
            print("pk: ", next(iter(self.abe_pk.values())))
            print("sk: ", next(iter(self.abe_sk.values())))
            print("policy: ", enc_el['policy'])

        # Load all in clear
        self.meta = {
            'el': el,
            'sym_key': extractor(el),
            'nonce': bytearray.fromhex(enc_meta['nonce']),
            'policy': enc_meta['policy'],
            'chunk_size': enc_meta['chunk_size'],
            'random_size': enc_meta['random_size'],
            're_encs': enc_meta['re_encs']
        }

        # Check if there is re-encryption information
        if len(enc_meta['re_encs']):

            # Retrieve re-encryption public and secret keys
            re_enc_op = enc_meta['re_encs'][0]
            key_pair_label = re_enc_op['pk']
            pk = self.abe_pk[key_pair_label]
            sk = self.abe_sk[key_pair_label]

            #print('LOAD META PRE ABE', re_enc_op)

            # Decrypt seed
            enc_seed = bytesToObject(unhexlify(re_enc_op['enc_seed']), self.pairing_group)
            enc_seed['policy'] = re_enc_op['policy']
            seed = abe.decrypt(enc_seed, pk, sk, self.pairing_group, self.debug)

            # Decrypt symmetric key
            enc_key = bytesToObject(unhexlify(re_enc_op['enc_key']), self.pairing_group)
            enc_key['policy'] = re_enc_op['policy']
            key = abe.decrypt(enc_key, pk, sk, self.pairing_group, self.debug)

            # Add decrypted seed and key, and IV
            self.meta['re_encs'][0]['enc_seed'] = seed
            self.meta['re_encs'][0]['enc_key'] = key
            self.meta['re_encs'][0]['iv'] = unhexlify(re_enc_op['iv'])

            #print('LOAD META POST ABE', self.meta['re_encs'][0])

        return self.meta


    def _dump_meta(self, metafile):
        """
        Dump the meta information on the metafile
        :param metafile: file where meta information will be saved
        :return: encrypted meta information
        """

        if self.debug:
            print("dumping metadata on file ", metafile)

        # Encrypt symmetric key pairing group element with CP-ABE
        enc_el = abe.encrypt(self.meta['el'], self.pairing_group, next(iter(self.abe_pk.values())), self.meta['policy'],
                             self.debug)

        # Prepare encrypted data
        enc_meta = {
            'policy': self.meta['policy'],
            'nonce': self.meta['nonce'].hex(),
            'enc_el': objectToBytes(enc_el, self.pairing_group).hex(),
            'chunk_size': self.meta['chunk_size'],
            'random_size': self.meta['random_size'],
            're_encs': self.meta['re_encs']
        }

        # Check if there is re-encryption information
        if len(enc_meta['re_encs']):

            # Retrieve ABE public key
            re_enc_op = enc_meta['re_encs'][0]
            key_pair_label = re_enc_op['pk']
            pk = self.abe_pk[key_pair_label]

            #print('DUMP ENC META PRE ABE', re_enc_op)

            # Encrypt seed
            enc_seed = objectToBytes(abe.encrypt(re_enc_op['enc_seed'], self.pairing_group, pk, re_enc_op['policy'],
                                                 self.debug), self.pairing_group)

            # Encrypt symmetric key
            enc_key = objectToBytes(abe.encrypt(re_enc_op['enc_key'], self.pairing_group, pk, re_enc_op['policy'],
                                                self.debug), self.pairing_group)

            # Add re-encryption information to encrypted meta information
            enc_meta['re_encs'][0]['enc_seed'] = hexlify(enc_seed).decode()
            enc_meta['re_encs'][0]['enc_key'] = hexlify(enc_key).decode()
            enc_meta['re_encs'][0]['iv'] = hexlify(re_enc_op['iv']).decode()

            #print('DUMP ENC META POST ABE', enc_meta['re_encs'][0])

        # Write encrypted information
        with open(metafile, 'w') as f:
            json.dump(enc_meta, f)

        return enc_meta


    def _add_initial_re_encs_info(self, initial_re_encs_num=0):
        """
        Add initial re-encryption information to meta information
        :param initial_re_encs_num: number of re-encryptions that will be initially applied to new files
        """

        # Add information about initial re-encryptions to apply to metafile
        if initial_re_encs_num > 0:

            # Create re-encryption params
            pk = objectToBytes(next(iter(self.abe_pk.values())), self.pairing_group)    # TODO CHANGE FOR REAL USE
            policy = '(DEPT1 and TEAM1)'                                                # TODO CHANGE FOR REAL USE
            seed = pg.hash_chain(self.pairing_group, self.last_seed_pg_elem, self.max_re_encs_num - initial_re_encs_num, self.cached_seeds, False)
            key = pg.hash_chain(self.pairing_group, self.last_key_pg_elem, self.max_re_encs_num - initial_re_encs_num, self.cached_keys, False)
            re_enc_length = const.RE_ENC_LENGTH

            # Add re-encryption params to metadata file
            self.meta['re_encs'].append({
                'pk': hashlib.sha256(pk).hexdigest(),  # SHA256 of public key as hex
                'policy': policy,
                'enc_seed': seed,
                'enc_key': key,
                'iv': self.root_iv,
                're_enc_length': re_enc_length,
                're_encs_num': initial_re_encs_num
            })


    def _create_re_enc_params(self, re_enc_index):
        """
        Create a dictionary with all parameters required for re-encryption operations, if it does not exist; otherwise,
        return the already existing one
        :param re_enc_index: re-encryption index in re-encryptions list
        :return: re-encryption parameters
        """

        #print('RE ENC INDEX', re_enc_index, self.re_enc_args[re_enc_index])

        # Check if already set
        if not self.re_enc_args or len(self.re_enc_args) < re_enc_index or not self.re_enc_args[re_enc_index]:

            # Get root re-encryption information
            re_enc_op = self.meta['re_encs'][0]

            #print('RE ENC OP', re_enc_op)

            # Derive current seed, key and IV
            seed = pg.hash_chain(self.pairing_group, re_enc_op['enc_seed'], re_enc_index, self.cached_seeds)
            key = pg.hash_chain(self.pairing_group, re_enc_op['enc_key'], re_enc_index, self.cached_keys)
            iv = fu.hash_chain(re_enc_op['iv'], re_enc_index, self.cached_ivs)

            #print('SEED', hexlify(objectToBytes(seed, self.pairing_group)).decode())
            #print('KEY', hexlify(objectToBytes(key, self.pairing_group)).decode())
            #print('IV', hexlify(iv).decode())

            return {
                'pairing_group': self.pairing_group,
                'seed': hexlify(objectToBytes(seed, self.pairing_group)).decode(),
                'key': hexlify(objectToBytes(key, self.pairing_group)).decode(),
                're_enc_length': re_enc_op['re_enc_length'],
                'iv': hexlify(iv).decode(),
            }

        else:

            return self.re_enc_args[re_enc_index]


    def _create_aont_transf_params(self, chunk_bytes_len):
        """
        Create a dictionary with all parameters required for AONT transformation
        :param chunk_bytes_len: chunk length in bytes
        :return: AONT transformation parameters
        """

        return {
            'nBits': (chunk_bytes_len + self.meta['random_size']) * 8,
            'k0BitsInt': self.meta['random_size'] * 8
        }


    def _create_aont_anti_transf_params(self, chunk_bytes_len):
        """
        Create a dictionary with all parameters required for AONT anti-transformation
        :param chunk_bytes_len: chunk length in bytes
        :return: AONT anti-transformation parameters
        """

        return {
            'nBits': chunk_bytes_len * 8,
            'k0BitsInt': self.meta['random_size'] * 8
        }


    def _decode(self, full_path, chunk_num, offset, sym_cipher, re_enc_args):
        """
        Remove AONT and encryption from the given chunk and write the result on the temporary file
        :param chunk_num: number of file chunk to anti-transform and decrypt
        :param offset: position where the result must be written
        :param sym_cipher: symmetric cipher
        """

        if self.enc_fp.closed:
            self.enc_fp = open(full_path, 'rb+')

        self.enc_fp.seek(0, os.SEEK_END)
        file_size = self.enc_fp.tell()
        if file_size <= chunk_num * self.meta['random_size']:
            return

        # Move file pointer
        self.enc_fp.seek(chunk_num * self.meta['chunk_size'])

        # Read file chunk
        chunk = self.enc_fp.read(self.meta['chunk_size'])

        # If applied, remove all re-encryption operations
        if self.debug:
            print("Remove re-encryptions from file chunk")

        re_encs_field = self.meta['re_encs']
        re_enc_init_val = self._get_cipher_initial_value(int(chunk_num) * self.meta['chunk_size'])

        if len(re_encs_field) > 0:

            re_enc_op = re_encs_field[0]
            re_encs_num = re_enc_op['re_encs_num']

            for current_re_enc_index in range(re_encs_num):
                # Add other params to re-encryption params
                re_enc_args[current_re_enc_index]['init_val'] = re_enc_init_val
                # re_enc_args[current_re_enc_index]['current_re_enc_num'] = current_re_enc_index

                #print('RE ENC #', current_re_enc_index, self.re_enc_args[current_re_enc_index])

                # Remove re-encryption
                chunk = re_enc.remove_re_enc(chunk, re_enc_args[current_re_enc_index], self.debug)

                if self.debug:
                    print("DE-RE-ENCRYPTED CHUNK = (%d) %s" % (len(chunk), chunk))
                    print("Re-encryption successfully removed")

            if self.debug:
                print("Re-encryptions successfully removed")

        if self.debug:
            print("Remove AONT from encrypted file chunk")

        # Get AONT anti-transformation parameters
        aont_args = self._create_aont_anti_transf_params(len(chunk))
        # Anti-transform file chunk
        chunk = aont.anti_transform(chunk, aont_args, self.debug)

        if self.debug:
            print("ANTI-TRANSFORMED CHUNK = (%d) %s" % (len(chunk), chunk))
            print("AONT successfully removed")

        # Decrypt the anti-transformed file chunk with the sym key and write it on the temporary file
        x = sym.decrypt(sym_cipher, chunk, self.debug)
        # x = chunk
        if self.debug:
            print("got chunk in _decode: ", x)

        # Write anti-transformed decrypted chunk on the temporary file at its proper position
        if self.debug:
            print("writing on temp file at position", offset, "byte ", x)

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

        if self.debug:
            print('AONT OFFSET =', transf_offset)
            print('AONT LAST BYTE =', transf_last_byte)
            print('STARTING AONT CHUNK NUM =', starting_aont_chunk_num)
            print('ENDING AONT CHUNK NUM =', ending_aont_chunk_num)

        return starting_aont_chunk_num, ending_aont_chunk_num


    def _get_cipher_initial_value(self, offset):
        """
        Return the initial value to set as cipher block counter for the given offset
        """
        return offset // sym.get_cipher(AES.MODE_CTR, None, None, self.meta['sym_key'][:16], self.meta['nonce'])\
            .block_size


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

        if self.debug:
            print('abebox getattr', path)

        full_path = self._full_path(path)

        st = os.lstat(full_path)
        d = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                 'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

        # Compute the correct file size removing AONT random chunks lengths
        if d['st_size'] > 0:
            d['st_size'] = d['st_size'] - (math.ceil(d['st_size'] / self.chunk_size) * self.random_size)

        if self.debug:
            print('D', d)

        return d


    def read(self, path, length, offset, fh):

        #self.starting_time = time() * 1000.0

        # self.enc_fp.close()
        # self.enc_fp = open(self._full_path(path), 'rb')

        full_path = self._full_path(path)

        if self.debug:
            print('READ ===============')
            print('FULL PATH =', full_path)
            print('PATH =', path)
            print('OFFSET =', offset)
            print('LENGTH =', length)

        # Compute length of the plaintext file and the related reading length
        file_size = os.path.getsize(full_path)
        temp_file_size = file_size - (math.ceil(file_size / self.meta['chunk_size']) * self.meta['random_size'])
        real_len = min(offset + length, temp_file_size)

        # Compute file chunks involved in reading process
        starting_aont_chunk_num, ending_aont_chunk_num = self._get_aont_chunks_range(real_len, offset)

        if self.meta['re_encs']:
            re_enc_op = self.meta['re_encs'][0]

        # Check if those chunks have already been processed
        for chunk_num in range(starting_aont_chunk_num, ending_aont_chunk_num + 1):
            # Check if chunk is already in the list, otherwise add it and all previous ones not inside the list
            if str(chunk_num) not in self.file_read_chunks.keys():

                if self.debug:
                    print('Chunk not in already read list')

                for prev_chunk_num in range(chunk_num + 1):
                    if str(prev_chunk_num) not in self.file_read_chunks.keys():
                        self.file_read_chunks[str(prev_chunk_num)] = 0

                        if self.debug:
                            print('Adding chunk #%d to the already read list with value %d'
                                  % (prev_chunk_num, self.file_read_chunks[str(prev_chunk_num)]))

            # Check if chunk has already been processed
            if not self.file_read_chunks[str(chunk_num)]:

                if self.debug:
                    print('Chunk #%d needs to be processed' % chunk_num)

                # Compute offset on decoded file
                decoded_offset = self._get_decoded_offset(chunk_num)

                if self.debug:
                    print('DECODED OFFSET =', decoded_offset)

                # Compute initial value of cipher block counter
                init_val = self._get_cipher_initial_value(decoded_offset)

                if self.debug:
                    print('INITIAL VALUE =', init_val)

                # Create symmetric cipher with proper initial value
                sym_cipher = sym.get_cipher(AES.MODE_CTR, init_val, None, self.meta['sym_key'][:16], self.meta['nonce'],
                                            self.debug)

                # Get re-enc parameters
                if len(self.meta['re_encs']):
                    re_enc_num = self.meta['re_encs'][0]['re_encs_num']
                    #print('READ RE ENC NUM', re_enc_num)
                    for i in range(re_enc_num):  # if len(self.meta['re_encs']):
                        self.re_enc_args[re_enc_num - i - 1] = self._create_re_enc_params(re_enc_num - i - 1)
                        assert(len(self.cached_seeds) >= re_enc_num or chunk_num == 0)
                        #print('RE ENC #', re_enc_num - i - 1, self.re_enc_args[re_enc_num - i - 1])

                # Anti-transform and decrypt chunk
                self._decode(full_path, chunk_num, decoded_offset, sym_cipher, self.re_enc_args)

                # Set relative array chunk position as read
                self.file_read_chunks[str(chunk_num)] = 1

        if self.debug:
            print("reading ", length, " bytes on tmp fs ", self.temp_fp)

        #print('READ', time() * 1000.0 - self.starting_time)

        return super(Abebox, self).read(path, length, offset, self.temp_fp.fileno())


    def write(self, path, buf, offset, fh):

        # self.enc_fp.close()
        # self.enc_fp = open(self._full_path(path), 'wb')

        full_path = self._full_path(path)

        if self.debug:
            print('PATH =', path)
            print('FULL PATH =', full_path)
            print('FH =', fh)
            print('OFFSET =', offset)
            print('BUFF =', buf)
            print('BUFF LEN =', len(buf))

        # Compute file chunks involved in reading process
        starting_aont_chunk_num, ending_aont_chunk_num = self._get_aont_chunks_range(offset + len(buf), offset)

        if self.meta['re_encs']:
            re_enc_op = self.meta['re_encs'][0]

        # Check if those chunks have already been processed
        for chunk_num in range(starting_aont_chunk_num, ending_aont_chunk_num + 1):
            # Check if chunk is already in the list, otherwise add it and all previous ones not inside the list
            if str(chunk_num) not in self.file_written_chunks.keys():

                if self.debug:
                    print('Chunk not in already written list')

                for prev_chunk_num in range(chunk_num + 1):
                    if str(prev_chunk_num) not in self.file_written_chunks.keys():
                        self.file_written_chunks[str(prev_chunk_num)] = 1
                        self.file_read_chunks[str(prev_chunk_num)] = 1

                        if self.debug:
                            print('Adding chunk #%d to the already written list with value %d'
                                  % (prev_chunk_num, self.file_written_chunks[str(prev_chunk_num)]))

            # Check if chunk has already been processed
            elif not self.file_written_chunks[str(chunk_num)]:

                if self.debug:
                    print('Chunk #%d needs to be processed' % chunk_num)

                # Compute offset on decoded file
                decoded_offset = self._get_decoded_offset(chunk_num)

                if self.debug:
                    print('DECODED OFFSET =', decoded_offset)

                # Compute initial value of cipher block counter
                init_val = self._get_cipher_initial_value(decoded_offset)

                if self.debug:
                    print('INITIAL VALUE =', init_val)

                # Create symmetric cipher with proper initial value
                sym_cipher = sym.get_cipher(AES.MODE_CTR, init_val, None, self.meta['sym_key'][:16], self.meta['nonce'],
                                            self.debug)

                # Get re-enc parameters
                # if len(self.meta['re_encs']):
                #     self.re_enc_args = self._create_re_enc_params(re_enc_op)
                if len(self.meta['re_encs']):
                    re_enc_num = self.meta['re_encs'][0]['re_encs_num']
                    #print('WRITE RE ENC NUM', re_enc_num)
                    for i in range(re_enc_num):  # if len(self.meta['re_encs']):
                        self.re_enc_args[re_enc_num - i - 1] = self._create_re_enc_params(re_enc_num - i - 1)
                        #print('RE ENC #', re_enc_num - i - 1, self.re_enc_args[re_enc_num - i - 1])

                # Anti-transform and decrypt chunk
                self._decode(full_path, chunk_num, decoded_offset, sym_cipher, self.re_enc_args)
                # Set relative array chunk position as read
                self.file_written_chunks[str(chunk_num)] = 1
                self.file_read_chunks[str(chunk_num)] = 1

        if self.debug:
            print("writing ", buf, " on ", path, " on tmp fs ", self.temp_fp)

        return super(Abebox, self).write(path, buf, offset, self.temp_fp.fileno())


    def open(self, path, flags):

        #self.starting_time = time() * 1000.0

        if self.debug:
            print("Opening file ", path)

        self.is_new = False

        # load meta information
        self.dirname, self.filename = os.path.split(self._full_path(path))

        self._load_meta(self.dirname + '/.abebox/' + self.filename)

        if self.debug:
            print('loaded meta')

        # Open a temporary file with given size
        self.temp_fp = tempfile.NamedTemporaryFile()  # could be more secure with mkstemp()
        # Compute temporary file size
        file_size = os.path.getsize(self._full_path(path))
        temp_file_size = file_size - (math.ceil(file_size / self.meta['chunk_size']) * self.meta['random_size'])

        if self.debug:
            print('PATH = %s\nSIZE = %d' % (self._full_path(path), temp_file_size))

        self.temp_fp.seek(temp_file_size - 1)
        self.temp_fp.write(b'\0')

        if self.debug:
            print("Created tempfile: ", self.temp_fp.name)
            print('Wrote \\0 in position #', self.temp_fp.tell() - 1)

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
        self.cached_seeds = {}
        self.cached_keys = {}
        self.cached_ivs = {}

        if self.meta['re_encs']:
            self.re_enc_args = [None for i in range(self.meta['re_encs'][0]['re_encs_num'])]

        # Reset file pointers
        self.enc_fp.seek(0)  # TODO PROBABILMENTE NON SERVE
        self.temp_fp.seek(0)

        #print('OPEN', time() * 1000.0 - self.starting_time)

        #os.lseek(enc_fp, 0, 0)
        return self.enc_fp.fileno()
        #return self.temp_fp.fileno()
        #return super(Abebox, self).open(path, flags)


    def create(self, path, mode, fi=None):

        #self.starting_time = time() * 1000.0

        if self.debug:
            print("Creating file ", path)
            print("full path", self._full_path(path))

        # Open a temporary file with given size
        self.temp_fp = tempfile.NamedTemporaryFile()  # could be more secure with mkstemp()

        if self.debug:
            print("Created tempfile: ", self.temp_fp.name)

        self.dirname, self.filename = os.path.split(self._full_path(path))

        if self.debug:
            print("Dirname: ", self.dirname)
            print("file name: ", self.filename)

        self.is_new = True

        # Create two empty arrays: the first one to track already read file chunks; the second for modified ones
        self.file_read_chunks = {}
        self.file_written_chunks = {}
        self.cached_seeds = {}
        self.cached_keys = {}
        self.cached_ivs = {}

        self._create_meta()

        if self.meta['re_encs']:
            self.re_enc_args = [None for i in range(self.meta['re_encs'][0]['re_encs_num'])]

        # return self.temp_fp.fileno()
        # return super(Abebox, self).create(path, mode, fi)
        full_path = self._full_path(path)
        self.enc_fp = open(full_path, 'wb')
        # return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
        return self.enc_fp.fileno()


    def release(self, path, fh):

        #self.starting_time = time() * 1000.0

        if self.debug:
            print("Releasing file ", path)

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

        if self.debug:
            print("Temporary file has size : ", self.temp_fp.seek(0, os.SEEK_END))
        # self.temp_fp.seek(0)

        re_encs_field = self.meta['re_encs']

        # Write only modified file chunks
        for chunk_num in self.file_written_chunks.keys():

            if self.debug:
                print('CHUNK NUM # =', chunk_num, self.file_written_chunks[chunk_num])

            if self.file_written_chunks[chunk_num]:

                if self.debug:
                    print("release written chunk #", chunk_num)
                # print("release - read chunk #", chunk)
                # os.write(fh, sym_cipher.encrypt(chunk))
                # fh.write(sym_cipher.encrypt(chunk))
                # Read file chunk
                # Set file pointer to file chunk starting byte
                self.temp_fp.seek(int(chunk_num) * (self.meta['chunk_size'] - self.meta['random_size']))
                # Read a file chunk from temporary file
                chunk = self.temp_fp.read(self.meta['chunk_size'] - self.meta['random_size'])

                if self.debug:
                    print('in release, read %d bytes = %s' % (len(chunk), chunk))

                # Compute offset on decoded file
                decoded_offset = self._get_decoded_offset(int(chunk_num))
                # Compute initial value of cipher block counter
                init_val = self._get_cipher_initial_value(decoded_offset)
                # Create symmetric cipher with proper initial value
                sym_cipher = sym.get_cipher(AES.MODE_CTR, init_val, None, self.meta['sym_key'][:16], self.meta['nonce'],
                                            self.debug)
                # Encrypt file chunk
                enc_chunk = sym.encrypt(sym_cipher, chunk, self.debug)
                # enc_chunk = chunk
                # Transform encrypted file chunk

                if self.debug:
                    print("Applying AONT to newly encrypted chunk")

                # Get AONT parameters
                aont_args = self._create_aont_transf_params(len(enc_chunk))
                # Apply AONT to the encrypted chunk
                transf_enc_chunk = aont.transform(enc_chunk, aont_args, self.debug)

                if self.debug:
                    print("AONT successfully applied")

                # If previously applied, re-apply re-encryptions
                re_enc_transf_enc_chunk = transf_enc_chunk
                re_enc_init_val = self._get_cipher_initial_value(int(chunk_num) * self.meta['chunk_size'])

                if re_encs_field:

                    if self.debug:
                        print("Re-applying re-encryptions to file chunk")

                    re_enc_op = re_encs_field[0]
                    re_encs_num = re_enc_op['re_encs_num']

                    #print('RELEASE RE ENC NUM', re_encs_num)

                    for current_re_enc_index in range(re_encs_num):

                        index = re_encs_num - 1 - current_re_enc_index

                        # Get re-enc parameters
                        self.re_enc_args[index] = self._create_re_enc_params(index)

                        # Add other params to re-encryption params
                        self.re_enc_args[index]['init_val'] = re_enc_init_val
                        # self.re_enc_args[current_re_enc_index]['current_re_enc_num'] = current_re_enc_index

                        #print('RE ENC #', index, self.re_enc_args[index])
                        #print('RE ENC ARGS LIST', self.re_enc_args)

                        # Re-encrypt transformed encrypted chunk
                        re_enc_transf_enc_chunk = re_enc.apply_old_re_enc(re_enc_transf_enc_chunk, self.re_enc_args[index],
                                                                          self.debug)

                        if self.debug:
                            print("RE-ENCRYPTED CHUNK = (%d) %s" % (len(re_enc_transf_enc_chunk), re_enc_transf_enc_chunk))
                            print("Re-encryption successfully re-applied")

                    if self.debug:
                        print("Re-encryptions successfully re-applied")

                if self.debug:
                    print('WRITING FH =', fh)
                    print('CHUNK =', re_enc_transf_enc_chunk)

                # Compute offset on encoded file
                encoded_offset = self._get_encoded_offset(int(chunk_num))
                # Write transformed encrypted chunk
                os.lseek(fh, encoded_offset, os.SEEK_SET)
                os.write(fh, re_enc_transf_enc_chunk)
                # os.write(fh, chunk + 32*b'a')

                if self.debug:
                    print("chunk (%d) %s has been written on file %d" % (len(re_enc_transf_enc_chunk), re_enc_transf_enc_chunk, fh))

        # with open(self._full_path(path), 'wb+') as enc_fp:
        #    # print("Release: file opened with fp ", enc_fp)
        #    # print("release: writing back from tempfile", self.temp_fp.file.name)
        #    for chunk in self._read_in_chunks(self.temp_fp, self.CHUNK_SIZE):
        #        # print("release - read chunk" , chunk)
        #        enc_fp.write(sym_cipher.encrypt(chunk))
        if self.debug:
            print("Closing fs")

        os.close(fh)

        if self.debug:
            print("Closed")

        meta_directory = self.dirname + '/.abebox/'
        if not os.path.exists(meta_directory):
            os.makedirs(meta_directory)

        if self.debug:
            print("dumping meta on :", meta_directory + self.filename)

        if sum(self.file_written_chunks.values()):
            self._dump_meta(meta_directory + self.filename)

        #print('RELEASE', time() * 1000.0 - self.starting_time)

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

        if self.debug:
            print("flushing")

        return os.fsync(self.temp_fp)
        # return os.fsync(fh)

    def fsync(self, path, fdatasync, fh):

        if self.debug:
            print("fsync")

        # return self.flush(path, fh)
        return self.flush(path, self.temp_fp)



def main(mountpoint, root, chunk_size, random_size, initial_re_encs_num, max_re_encs_num, debug):
    FUSE(Abebox(root, chunk_size, random_size, initial_re_encs_num, max_re_encs_num, debug), mountpoint, nothreads=True,
         foreground=True)


if __name__ == '__main__':

    # Parse input arguments
    parser = argparse.ArgumentParser(description='FUSE-based userspace file system driver',
                                     usage='abebox.py [BASEDIR] [MOUNTDIR] -chunk_size [BYTES_NUM] '
                                           '-random_size [BYTES_NUM] -init_re_encs [INT]')
    parser.add_argument('basedir', nargs=1)
    parser.add_argument('mountdir', nargs=1)
    parser.add_argument('-chunk_size', type=int, help='Chunck size in bytes', default=128)
    parser.add_argument('-random_size', type=int, help='AONT random size in bytes', default=32)
    parser.add_argument('-init_re_encs_num', type=int, help='Number of initial re-encryption operations', default=0)
    parser.add_argument('-max_re_encs_num', type=int, help='Maximum number of re-encryption operations', default=1024)
    parser.add_argument('--debug', action='store_true', default=False)
    args = parser.parse_args()

    if args.debug:
        print('INPUT ARGS =', args)

    main(args.mountdir[0], args.basedir[0], args.chunk_size, args.random_size, args.init_re_encs_num,
         args.max_re_encs_num, args.debug)
