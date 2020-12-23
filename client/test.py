import os
import aont as aont

from Crypto.Cipher import AES

if __name__ == '__main__':

    input = 'test_file.txt'
    transf_output = 'transf_' + input
    anti_transf_output = 'antitransf_' + transf_output
    # length = os.path.getsize(input)

    with(open(input, 'rb')) as fin:

        for infile_chunk in iter(lambda: fin.read(96), ''):

            print('INFILE CHUNK = (%s) (%d) %s' % (type(infile_chunk), len(infile_chunk), infile_chunk))

            if not len(infile_chunk):
                break

            sym_cipher = AES.new(b'\xab\x00', AES.MODE_CTR, nonce=b'\x00\x11')
            enc_chunk = sym_cipher.encrypt(infile_chunk)
            # Transform encrypted file chunk
            # original_data_length += len(enc_chunk)
            print("Applying AONT to newly encrypted chunk")
            aont_args = {
                'nBits': 1024,
                'k0BitsInt': 256
            }
            transf_enc_chunk = aont.transform(data=enc_chunk, args=aont_args, debug=0)
            print("AONT successfully applied")

            # TODO RE-APPLY PREVIOUS RE-ENCs
            re_enc_transf_enc_chunk = transf_enc_chunk
            print("Re-applying re-encryptions to file chunk")
            if len(meta['re_encs']) > 0:
                for re_enc_op in self.meta['re_encs']:
                    key_pair_label = re_enc_op['pk']
                    pk = self.abe_pk[key_pair_label]
                    sk = self.abe_pk[key_pair_label]
                    re_enc_args = {
                        'pk': pk,
                        'sk': sk,
                        'enc_params': re_enc_op['enc_params'],
                        'iv': re_enc_op['iv']
                    }
                    re_enc_transf_enc_chunk = re_enc.re_encrypt(data=re_enc_transf_enc_chunk, args=re_enc_args,
                                                                debug=0)
                    print("RE-ENCRYPTED CHUNK = (%d) %s" % (len(re_enc_transf_enc_chunk), re_enc_transf_enc_chunk))
                    print("Re-encryption successfully re-applied")
                print("Re-encryptions successfully re-applied")

            # Write transformed encrypted chunk
            os.write(fh, re_enc_transf_enc_chunk)
            print("chunk (%d) %s has been written on file %d" % (
            len(re_enc_transf_enc_chunk), re_enc_transf_enc_chunk, fh))

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
