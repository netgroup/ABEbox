import os
import aont as aont

#import old.Encryptor as enc

if __name__ == '__main__':

    input = 'test_file.txt'
    transf_output = 'transf_' + input
    anti_transf_output = 'antitransf_' + transf_output
    len = os.path.getsize(input)

    aont.transform(infile=input, outfile=transf_output, debug=1)
    print('\n\n\n\n')
    # enc.apply_aont(open('test_file.txt', 'rb').read(), debug=1)
    aont.anti_transform(infile=transf_output, outfile=anti_transf_output, args={'original_data_length': len}, debug=1)
