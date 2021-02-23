import aont as aont

from Crypto.Cipher import AES
import re_enc_primitives as re_enc
import json
import pairing_group_primitives as pg
import os, random, string

from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as extractor
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup, ZR, GT, G1, G2, hashPair
from charm.toolbox.policytree import PolicyParser


if __name__ == '__main__':

    write_string = os.urandom(1024*1024*2)
    write_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000000*2))
    with(open('long_test_file', 'w')) as f:
        f.write(write_string)
    exit(0)

    write_string = 'ciao'
    # test create, write, read
    with open('mountdir/prova', 'w+') as f:
        f.write(write_string)
        #f.seek(0, 0)
    with open('mountdir/prova', 'w+') as f:
        read_string = f.read()
        print("written string: {}\t read string: {}".format(write_string, read_string))
        #self.assertEqual(read_string, write_string)

    # with(open('mountdir/prova', 'w+')) as fin:
    #     fin.write('AA')
    #     fin.seek(0, 0)
    #     print(fin.read())

    exit(0)

    pair_g = pg.pairing_group_create()
    # last_elem = pg.random_pairing_group_elem_gen(pair_g)
    # max_hops = 100

    b = b'eJxNU0FuxDAI/EqUcw7g2Ab3K1UVbau97W3bSlXVv5cBnN1DLBtjmBkmv+txfNwu9/txrC/L+v7zeb2v22LR78vt6+rR18bb0nRbZGyL2r6LfXZmqrkMjRsmS2lkBwu2ZgG2ZVi+2K3u8w13u+447VGO2ZZWsMF9sZ3iJcpZSt0jv8+sgmaMG9TesxE6RwEGINSlnqg8GzXjRBJ8KnhJBvpZA7fYUJmkJF879DIx2kFqBohDCCkRZJ6KSItmKAk6Ll6hqBjo93jrhB2kBmNkQDfPIkl+rh02qAzUvU/UI6HVlO1BgylBhjrlPGGsGsgQVc0bcJaeLM/ZQFFPgeJ1n4UxEU0keNBmbuMTAOcUR04+IhKPPA/qwiryFJSW3LyRq4NmqOLUIXlOESjdTmXSlJ5kwp4UCFBkOqfnrCG9TgWR6JrCru7A8XAkurlN3Fzs+TkHzH2kVdwHFBZrqYzk8JwTRMGPohSS1TSBjCeF23SxjpQbLohfiUOscQ4WrkEbfHWczh8pqqba+vb3Dz4zux0='
    el = bytesToObject(b, pair_g)

    import re_enc_engine.pairing_group_primitives as eng_pg

    r = pair_g.init(ZR, int(hashPair(el).decode('utf-8'), 16))
    h_el = el ** r
    # el = pair_g.random(G2)
    # el0 = pair_g.random(G2)
    #el0 = eng_pg.hash_chain(pair_g, el, 1)
    #print('\n\n')
    print(el.type, objectToBytes(el, pair_g))
    print(el.type, objectToBytes(r, pair_g))
    print(el.type, objectToBytes(h_el, pair_g))
    print('\n\n')
    el1 = pair_g.init(ZR, value=1)
    el2 = pair_g.init(ZR, value=2)
    el3 = pair_g.init(ZR, value=4)
    el4 = pair_g.init(ZR, value=int.from_bytes(objectToBytes(el1, pair_g), 'little'))
    #print(objectToBytes(el1, pair_g))
    #print(objectToBytes(el2, pair_g))
    #print(objectToBytes(el3, pair_g))
    #print(objectToBytes(el4, pair_g))

    exit(0)

    eng_el0 = eng_pg.hash_chain(pair_g, last_elem, max_hops)
    eng_el1 = eng_pg.hash_chain(pair_g, last_elem, max_hops - 1)
    eng_el2 = eng_pg.hash_chain(pair_g, last_elem, max_hops - 2)
    eng_el3 = eng_pg.hash_chain(pair_g, last_elem, max_hops - 3)
    eng_el1_3 = eng_pg.hash_chain(pair_g, eng_el1, 2)

    print('\n\n')
    print(objectToBytes(eng_el0, pair_g))
    print(objectToBytes(eng_el1, pair_g))
    print(objectToBytes(eng_el2, pair_g))
    print(objectToBytes(eng_el3, pair_g))
    print(objectToBytes(eng_el1_3, pair_g))

    exit(0)

    for current_re_enc_index in range(2, 0, -1):
        print(current_re_enc_index)

    exit(0)
    import function_utils as fu
    import sym_enc_primitives as sym

    iv = sym.iv_gen(8, 1)
    print(type(iv), iv)
    h_iv = fu.hash_chain(iv, 2)
    print(type(h_iv), h_iv)

    exit(0)

    pairing_group = pg.pairing_group_create('MNT224')
    gt_el = pairing_group.random(GT)
    print(type(gt_el), gt_el)
    hp_gt_el = hashPair(gt_el)
    print(type(hp_gt_el), hp_gt_el)
    int_hp_gt_el = int(hp_gt_el[: 7], 16)
    print(type(int_hp_gt_el), int_hp_gt_el)
    rand_gt_el = pairing_group.random(GT, seed=int_hp_gt_el)
    rand_gt_el1 = pairing_group.random(GT, seed=int_hp_gt_el)
    print(type(rand_gt_el), rand_gt_el)
    print(type(rand_gt_el1), rand_gt_el1)
    print(rand_gt_el == rand_gt_el1)
    exit(0)
    split_gt_el = str(gt_el).split('], [')
    print(split_gt_el)
    first_tuple = split_gt_el[0][1:] + ']'
    print(first_tuple)
    second_tuple = '[' + split_gt_el[1][:-1]
    print(second_tuple)
    pairing_group.init(G2, second_tuple)
    second_tuple_bytes = second_tuple.encode()
    print(second_tuple_bytes)
    # pg_el1 = pairing_group.init(G1)
    # pg_el2 = pairing_group.init(G2)
    r1 = pairing_group.random(G1, seed=5)
    # r1 = pairing_group.init(G1, [5199894555764759087040345653867460927014528476204233044012149897641, 5037320461775929858170285177685335011889738226883925387110449823439])
    r2 = pairing_group.random(G2, seed=5)
    # r2 = pairing_group.init(G2, [[6578933262446802049002559865333981553110661967315234272697440109487, 11049624688096010173269283275001627578816568637537624340976040051485, 14337127813226342822404605279015489583441892860450106513784827473736], [7018750406085748396199850501576771394514240964798624806933776512924, 361088313842283541597269225941790109144397514709652019053837096093, 4933983083366004950461557073740458940959759860961518541427046453981]])
    prod = [[6600367768354583075001198718755641815886585676442862217861530657778, 4122476358479248534787865364863458371595814984725436991604743196958, 13578554949038243024553320882413834088101013371191294623029774067808], [11873469954883722603968697318027660162834144047215988401321451479880, 8100755134891728317494932234269381120907102247793914235041501334578, 11034421580139537587971657884781065708570957208869491398530039422497]]
    pg_gt = pairing_group.pair_prod(lhs=r1, rhs=r2)

    print(r1)
    print(r2)
    print(prod)
    print(pg_gt, '\n\n')

    h_r1 = pairing_group.hash(r1, G1)
    h_r2 = r2
    h_pg_gt = pairing_group.pair_prod(lhs=h_r1, rhs=r2)

    print(h_r1)
    print(h_r2)
    print(h_pg_gt, '\n\n')
    # print(pairing_group.hash('ciao'))
    # print(pairing_group.hash('miao'))

    exit(0)
    # el = pairing_group.random(GT)
    el = pairing_group.random(GT)
    el1 = [[14142659334253412479424150385035484865290227706559363032229907140767, 14838272766019895360758032235360543653671419808593964795168312844174, 2290918559276621129267542842363267550243971456895148743211407022380], [7773731170971168088664482182046038899305970572762297011863647480693, 9524508627875251589330652592473066044564702273484647470308879371822, 8200275185360260975685252777321708294323444250145400948298852820400]]

    #el = pairing_group.random(GT)
    print(type(el), el)
    print(type(el1), el1)
    #c = int.from_bytes(hashlib.sha256(str(el).encode('utf-8')).digest(), byteorder='big')
    #print(type(c), c)
    # el2 = pairing_group.init(GT, c)
    el2 = pairing_group.hash(el, G1)
    el3 = pairing_group.hash(el, G1)
    print(type(el2), el2)

    exit(0)

    a = {'0': 1, '1': 1, '2': 1, '3': 1, '4': 1, '5': 1, '6': 1, '7': 1, '8': 1, '9': 1, '10': 1, '11': 1, '12': 1, '13': 1, '14': 1, '15': 1, '16': 1, '17': 1, '18': 1, '19': 1, '20': 1, '21': 1, '22': 1, '23': 1, '24': 1, '25': 1, '26': 1, '27': 1, '28': 1, '29': 1, '30': 1, '31': 1, '32': 1, '33': 1, '34': 1, '35': 1, '36': 1, '37': 1, '38': 1, '39': 1, '40': 1, '41': 1, '42': 1}

    for i in a.keys():
        print(i, a[i])

    exit(0)


    file = 'basedir/test'
    metafile = 'basedir/.abebox/test'

    with(open(metafile)) as f:
        meta = json.load(f)

    with(open('/home/serse/.abe_keys')) as f:
        data = json.load(f)

    abe_pk = {}
    abe_sk = {}
    pairing_group = pg.pairing_group_create('MNT224')
    # cpabe = AC17CPABE(pairing_group, 2)
    cpabe = CPabe_BSW07(pairing_group)
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
            enc_el['policy'] = str(PolicyParser().parse(policy))
            el = cpabe.decrypt(next(iter(abe_pk.values())), next(iter(abe_sk.values())), enc_el)
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
