import os
import aont as aont

from Crypto.Cipher import AES
import re_enc_primitives as re_enc
import json

from charm.toolbox.pairinggroup import PairingGroup, ZR
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as extractor
from ABE.ac17 import AC17CPABE
from charm.toolbox.policytree import PolicyParser


if __name__ == '__main__':

    file = 'basedir/test'
    metafile = 'basedir/.abebox/test'

    with(open(metafile)) as f:
        meta = json.load(f)

    with(open('/home/serse/.abe_keys')) as f:
        data = json.load(f)

    abe_pk = {}
    abe_sk = {}
    pairing_group = PairingGroup('MNT224')
    cpabe = AC17CPABE(pairing_group, 2)
    policy = '(DEPT1 and TEAM1)'
    for abe_key_pair in data.keys():
        abe_pk[abe_key_pair] = bytesToObject(bytes.fromhex(data[abe_key_pair]['pk']), pairing_group)
        abe_sk[abe_key_pair] = bytesToObject(bytes.fromhex(data[abe_key_pair]['sk']), pairing_group)

    with(open(file, 'rb')) as fin:

        for chunk in iter(lambda: fin.read(1024), ''):

            print('FILE CHUNK = (%s) (%d) %s' % (type(chunk), len(chunk), chunk))

            if not len(chunk):
                break

            print("Remove re-encryptions from file chunk")
            re_enc_ops_num = len(meta['re_encs'])
            if re_enc_ops_num > 0:
                for i in range(re_enc_ops_num):
                    re_enc_op = meta['re_encs'][re_enc_ops_num - 1 - i]
                    key_pair_label = re_enc_op['pk']
                    pk = abe_pk[key_pair_label]
                    sk = abe_sk[key_pair_label]
                    re_enc_args = {
                        'pk': pk,
                        'sk': sk,
                        'enc_seed': re_enc_op['enc_seed'],
                        'enc_key': re_enc_op['enc_key'],
                        're_enc_length': re_enc_op['re_enc_length'],
                        'iv': re_enc_op['iv'],
                        'policy': re_enc_op['policy'],
                        'pairing_group': pairing_group
                    }
                    chunk = re_enc.re_decrypt(data=chunk, args=re_enc_args, debug=1)
                    print("DE-RE-ENCRYPTED CHUNK = (%d) %s" % (len(chunk), chunk))
                    print("Re-encryption successfully removed")
                print("Re-encryptions successfully removed")

            # Anti-transform file chunk
            print("Remove AONT from encrypted file chunk")
            aont_args = {
                'nBits': len(chunk) * 8,
                'k0BitsInt': 256
            }
            chunk = aont.anti_transform(data=chunk, args=aont_args, debug=0)
            print("ANTI-TRANSFORMED CHUNK = (%d) %s" % (len(chunk), chunk))
            print("AONT successfully removed")

            enc_el = bytesToObject(bytearray.fromhex(meta['enc_el']), pairing_group)
            enc_el['policy'] = PolicyParser().parse(policy)
            el = cpabe.decrypt(next(iter(abe_pk.values())), enc_el, next(iter(abe_sk.values())))
            meta['sym_key'] = extractor(el)
            meta['nonce'] = bytearray.fromhex(meta['nonce'])

            print('SYM KEY =', meta['sym_key'])
            print('SYM KEY 16 =', meta['sym_key'][:16])

            # Decrypt the anti-transformed file chunk with the sym key and write it on the temporary file
            sym_cipher = AES.new(meta['sym_key'][:16], AES.MODE_CTR, nonce=meta['nonce'])
            x = sym_cipher.decrypt(chunk)
            print("got chunk in _decode: ", x)

            exit(0)

            # sym_cipher = AES.new(b'\xab\x00', AES.MODE_CTR, nonce=b'\x00\x11')
            # enc_chunk = sym_cipher.encrypt(chunk)
            # # Transform encrypted file chunk
            # # original_data_length += len(enc_chunk)
            # print("Applying AONT to newly encrypted chunk")
            # aont_args = {
            #     'nBits': 1024,
            #     'k0BitsInt': 256
            # }
            # transf_enc_chunk = aont.transform(data=enc_chunk, args=aont_args, debug=0)
            # print("AONT successfully applied")
            #
            # # TODO RE-APPLY PREVIOUS RE-ENCs
            # re_enc_transf_enc_chunk = transf_enc_chunk
            # print("Re-applying re-encryptions to file chunk")
            # if len(meta['re_encs']) > 0:
            #     for re_enc_op in self.meta['re_encs']:
            #         key_pair_label = re_enc_op['pk']
            #         pk = self.abe_pk[key_pair_label]
            #         sk = self.abe_pk[key_pair_label]
            #         re_enc_args = {
            #             'pk': pk,
            #             'sk': sk,
            #             'enc_params': re_enc_op['enc_params'],
            #             'iv': re_enc_op['iv']
            #         }
            #         re_enc_transf_enc_chunk = re_enc.re_encrypt(data=re_enc_transf_enc_chunk, args=re_enc_args,
            #                                                     debug=0)
            #         print("RE-ENCRYPTED CHUNK = (%d) %s" % (len(re_enc_transf_enc_chunk), re_enc_transf_enc_chunk))
            #         print("Re-encryption successfully re-applied")
            #     print("Re-encryptions successfully re-applied")
            #
            # # Write transformed encrypted chunk
            # os.write(fh, re_enc_transf_enc_chunk)
            # print("chunk (%d) %s has been written on file %d" % (
            # len(re_enc_transf_enc_chunk), re_enc_transf_enc_chunk, fh))

            # args = {
            #     'nBits': len(infile_chunk) * 8 + 256,
            #     'k0BitsInt': 256
            # }
            # transf_chunk = aont.transform(data=infile_chunk, args=args, debug=1)
            # print('TRANSF CHUNK =', transf_chunk, '\n')
            # open(transf_output, 'ab').write(transf_chunk)
            # # enc.apply_aont(open('test_file.txt', 'rb').read(), debug=1)
            # # anti_transf_chunk, length = aont.anti_transform(data=transf_chunk, args={'original_data_length': length}, debug=1)
            # args = {
            #     'nBits': len(infile_chunk) * 8 + 256,
            #     'k0BitsInt': 256
            # }
            # anti_transf_chunk = aont.anti_transform(data=transf_chunk, args=args, debug=1)
            # print('ANTI-TRANSF CHUNK =', anti_transf_chunk, '\n')
            # open(anti_transf_output, 'ab').write(anti_transf_chunk)
