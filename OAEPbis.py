import hashlib  # SHA-256
from secrets import SystemRandom  # Generate secure random numbers
from Const import AONT_DEFAULT_N, AONT_DEFAULT_ENCODING, AONT_DEFAULT_K0, AONT_DEFAULT_K0_FILL

# Constants
nBits = AONT_DEFAULT_N
k0BitsInt = AONT_DEFAULT_K0
k0BitsFill = AONT_DEFAULT_K0_FILL
encoding = AONT_DEFAULT_ENCODING


def init(n, enc, k0, k0fill):

	global nBits, k0BitsInt, k0BitsFill, encoding
	nBits = n
	encoding = enc
	k0BitsInt = k0
	k0BitsFill = k0fill


def hex_to_binary(msg, debug=0):

	bits = bin(int(msg, 16))[2:]

	if debug:
		print('Converting msg = (%d) %s to binary = (%d) %s' % (len(msg), msg, len(bits), bits))

	return bits.zfill(8 * (int((len(bits) + 7) / 8)))


def binary_to_hex(bits, debug=0):

	n = int(bits, 2)

	if debug:
		print('Converting binary = (%d) %s to msg = (%d) %s' % (len(bits), bits, len(n), n))

	return hex(n)


def pad(msg, debug=0):
	'''
	Create two oracles using sha-256 hash function.
	oracle1 is our first hash function used. Used to hash a random integer.
	oracle2 is the second hash function used. Used to hash the result of XOR(paddedMsg, hash(randBitStr))'''
	oracle1 = hashlib.sha256()
	oracle2 = hashlib.sha256()

	'''
	Generate a random integer that has a size of k0bits. Format the random int as a binary string making 
	sure to maintain leading zeros with the K0BitsFill argument.'''
	rand_bit_str = format(SystemRandom().getrandbits(k0BitsInt), k0BitsFill)

	if debug:
		print('RAND BIT STRING = (%d) %s' % (len(rand_bit_str), rand_bit_str))

	'''
	Change our msg string to a binary string. '''
	bin_msg = hex_to_binary(msg, debug)

	if debug:
		print('BIN MSG = (%d) %s' % (len(bin_msg), bin_msg))

	zero_padded_msg = bin_msg
	'''
	If the input msg has a binary length shorter than (nBits-k0Bits) then append k1Bits 0's to the end of the msg.
	Where k1Bits is the number of bits to make len(binMsg) = (nBits-k0Bits).'''
	if len(bin_msg) <= (nBits - k0BitsInt):
		k1_bits = nBits - k0BitsInt - len(bin_msg)
		zero_padded_msg += ('0' * k1_bits)

	if debug:
		print('ZERO PADDED MSG = (%d) %s' % (len(zero_padded_msg), zero_padded_msg))

	'''
	Use the hashlib update method to pass the values we wish to be hashed to the oracle. Then use
	the hashlib hexdigest method to hash the value placed in the oracle by the update method, and
	return the hex representation of this hash. Change our hash output, zeroPaddedMsg, and
	randBitStr to integers to use XOR operation. Format the resulting ints as binary strings.
	Hashing and XOR ordering follows OAEP algorithm.'''
	oracle1.update(rand_bit_str.encode(encoding))
	x = format(int(zero_padded_msg, 2) ^ int(oracle1.hexdigest(), 16), '0768b')

	if debug:
		print('X = ', x)

	oracle2.update(x.encode(encoding))
	y = format(int(oracle2.hexdigest(), 16) ^ int(rand_bit_str, 2), k0BitsFill)

	if debug:
		print('Y = ', y)

	return x + y


def unpad(msg, debug=0):
	'''
	Create two oracles using sha-256 hash function.
	oracle1 is our first hash function used. Used to hash a random integer.
	oracle2 is the second hash function used. Used to hash the result of XOR(paddedMsg, hash(randBitStr))'''
	oracle1 = hashlib.sha256()
	oracle2 = hashlib.sha256()

	x = msg[0: nBits - k0BitsInt]
	y = msg[nBits - k0BitsInt:]

	oracle2.update(x.encode(encoding))
	r = format(int(y, 2) ^ int(oracle2.hexdigest(), 16), k0BitsFill)

	if debug:
		print('EXTRACTED RANDOM = ', r)

	oracle1.update(r.encode(encoding))
	msg_with_0s = format(int(x, 2) ^ int(oracle1.hexdigest(), 16), '0768b')

	if debug:
		print('EXTRACTED MSG = ', msg_with_0s)

	return binary_to_hex(msg_with_0s, debug)


'''================================TESTING======================================'''
# #msg =  "This program currently works for msgs that have a length less than nbits. nbits currently=1024."# this still working"
# msg = format(SystemRandom().getrandbits(nBits), '01024b' )
#
# print ("ORIGINAL MSG:\n", msg, "\n" )
#
# output = pad(msg)
# print ( "PADDED MSG:\n", output,
# 	   	"\n\nLENGTH OF PADDED MSG:\n", len(output),
# 	    "\nEXPECTED LENGTH:\n", nBits)
#
# result = unpad(output)
# print ("\nUNPADDED MSG:\n",result)