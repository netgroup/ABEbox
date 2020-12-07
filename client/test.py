import os
import aont as aont

#import old.Encryptor as enc

if __name__ == '__main__':

    input = 'test_file.txt'
    transf_output = 'transf_' + input
    anti_transf_output = 'antitransf_' + transf_output
    length = os.path.getsize(input)

    with(open(input, 'rb')) as fin:

        for infile_chunk in iter(lambda: fin.read(96), ''):

            print('INFILE CHUNK = (%s) (%d) %s' % (type(infile_chunk), len(infile_chunk), infile_chunk))

            if not len(infile_chunk):
                break

            transf_chunk = aont.transform(data=infile_chunk, debug=1)
            print('TRANSF CHUNK =', transf_chunk, '\n')
            open(transf_output, 'ab').write(transf_chunk)
            # enc.apply_aont(open('test_file.txt', 'rb').read(), debug=1)
            anti_transf_chunk, length = aont.anti_transform(data=transf_chunk, args={'original_data_length': length}, debug=1)
            print('ANTI-TRANSF CHUNK =', anti_transf_chunk, '\n')
            open(anti_transf_output, 'ab').write(anti_transf_chunk)
