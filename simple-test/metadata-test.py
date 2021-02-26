
import os
import json
from random import seed, randint

# FUSE import
from fuse import FUSE, FuseOSError, Operations
from passthrough import Passthrough

# security import
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.pairinggroup import GT
from charm.core.math.pairing import hashPair as extractor
from charm.toolbox.pairinggroup import hashPair, GT, PairingGroup, ZR
import secrets


class AbeboxMetadata:
    def __init__(self, pg, path, chunk_size,random_size ,el):
        """ 
        """
        # https://jhuisi.github.io/charm/toolbox/symcrypto.html#symcrypto.SymmetricCryptoAbstraction
        self.pg = pg
        self.el = el
        self.sym_key = extractor(el)
        self.nonce = secrets.token_bytes(8)
        self.policy = '(DEPT1 and TEAM1)' # hardcoded - TBD
        self.chunk_size = chunk_size
        self.random_size=random_size
        self.chunks = {}

    def setY(self,chunk_num,Y):
        self.chunks[chunk_num] = base64.b64encode(Y).encode()
    
    def getY(self,chunk_num):
        return self.chunks[chunk_num].encode()

    def __str__(self):
        "AM {}".format(self.nonce)
    
    @classmethod
    def to_json(cls, o):

        print(o.chunks)
        
        ret = {
            "el" : objectToBytes(el, o.pg).hex(),
            "nonce" : o.nonce.hex(),
            "policy" : o.policy,
            "chunk_size" :o.chunk_size,
            "random" : o.random_size
            #"chunks" : 
        }
        return ret
    
    @classmethod
    def from_json(cls, json_str):
        json_dict = json.loads(json_str)
        return cls(**json_dict)

pairing_group = PairingGroup('MNT224')
el = pairing_group.random(GT)
path = "TEST"
mt = AbeboxMetadata(pairing_group,path, 128,32,el)
mt.setY(0,secrets.token_bytes(32))
mt.setY(1,secrets.token_bytes(32))
with open("mt.json", 'w') as f:
    json.dump(mt, f, default=AbeboxMetadata.to_json)

with open("mt.json", 'r') as f:
    enc_meta = json.load(f)
    print(enc_meta)

 