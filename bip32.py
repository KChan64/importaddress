import os
import hmac
import hashlib
import ecdsa
import struct
import codecs
import warnings

from binascii import unhexlify
from hashlib import sha256
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int
from ecdsa.numbertheory import square_root_mod_prime as sqrt_mod

try:
	from func import check_decode, check_encode, bech32_encode, bech32_decode, ripemd160
	from fver import query_ver,query_lsit
except Exception as e:
	from .func import check_decode, check_encode, bech32_encode, bech32_decode, ripemd160
	from .fver import query_ver,query_lsit



MIN_ENTROPY_LEN = 128        # bits
BIP32_HARDEN    = 0x80000000 # choose from hardened set of child keys
CURVE_GEN       = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER     = CURVE_GEN.order()
FIELD_ORDER     = SECP256k1.curve.p()
INFINITY        = ecdsa.ellipticcurve.INFINITY
#ex_key version, Read more:https://github.com/satoshilabs/slips/blob/master/slip-0132.md


class BIP32Key(object):

	# Static initializers to create from entropy or external formats
	#
	@staticmethod
	def fromEntropy(entropy, public=False, testnet=False):
		"Create a BIP32Key using supplied entropy >= MIN_ENTROPY_LEN"
		if entropy == None:
			entropy = os.urandom(MIN_ENTROPY_LEN/8) # Python doesn't have os.random()
		if not len(entropy) >= MIN_ENTROPY_LEN/8:
			raise ValueError("Initial entropy %i must be at least %i bits" %
								(len(entropy), MIN_ENTROPY_LEN))
		I = hmac.new(b"Bitcoin seed", entropy, hashlib.sha512).digest()
		Il, Ir = I[:32], I[32:]
		# FIXME test Il for 0 or less than SECP256k1 prime field order
		key = BIP32Key(secret=Il, chain=Ir, depth=0, index=0, fpr=b'\0\0\0\0', public=False, testnet=testnet)
		if public:
			key.SetPublic()
		return key

	@staticmethod
	def fromExtendedKey(xkey, public=False):
		"""
		Create a BIP32Key by importing from extended private or public key string

		If public is True, return a public-only key regardless of input type.
		"""
		# Sanity checks
		raw = check_decode(xkey)
		if len(raw) != 78:
			raise ValueError("extended key format wrong length")

		# Verify address version/type
		version = raw[:4]
		tversion = codecs.encode(version,"hex")
		if tversion in query_lsit(testnet=False):
			is_testnet = False
			is_pubkey = False
		elif tversion in query_lsit(testnet=True):
			is_testnet = True
			is_pubkey = False
		elif tversion in query_lsit(public=True):
			is_testnet = False
			is_pubkey = True
		elif tversion in query_lsit(public=True,testnet=True):
			is_testnet = True
			is_pubkey = True
		else:
			raise ValueError("unknown extended key version")

		# Extract remaining fields
		# Python 2.x compatibility
		if type(raw[4]) == int:
			depth = raw[4]
		else:
			depth = ord(raw[4])
		fpr = raw[5:9]
		child = struct.unpack(">L", raw[9:13])[0]
		chain = raw[13:45]
		secret = raw[45:78]

		# Extract private key or public key point
		if not is_pubkey:
			secret = secret[1:]
		else:
			# Recover public curve point from compressed key
			# Python3 FIX
			lsb = secret[0] & 1 if type(secret[0]) == int else ord(secret[0]) & 1
			x = string_to_int(secret[1:])
			ys = (x**3+7) % FIELD_ORDER # y^2 = x^3 + 7 mod p
			y = sqrt_mod(ys, FIELD_ORDER)
			if y & 1 != lsb:
				y = FIELD_ORDER-y
			point = ecdsa.ellipticcurve.Point(SECP256k1.curve, x, y)
			secret = ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1)

		key = BIP32Key(secret=secret, chain=chain, depth=depth, index=child, fpr=fpr, public=is_pubkey, testnet=is_testnet)
		if not is_pubkey and public:
			key = key.SetPublic()
		return key


	# Normal class initializer
	def __init__(self, secret, chain, depth, index, fpr, public=False, testnet=False):
		"""
		Create a public or private BIP32Key using key material and chain code.

		secret   This is the source material to generate the keypair, either a
				 32-byte string representation of a private key, or the ECDSA
				 library object representing a public key.

		chain    This is a 32-byte string representation of the chain code

		depth    Child depth; parent increments its own by one when assigning this

		index    Child index

		fpr      Parent fingerprint

		public   If true, this keypair will only contain a public key and can only create
				 a public key chain.
		"""

		self.public = public
		if public is False:
			self.k = ecdsa.SigningKey.from_string(secret, curve=SECP256k1)
			self.K = self.k.get_verifying_key()
		else:
			self.k = None
			self.K = secret

		self.C = chain
		self.depth = depth
		self.index = index
		self.parent_fpr = fpr
		self.testnet = testnet

	# Internal methods not intended to be called externally
	#
	def hmac(self, data):
		"""
		Calculate the HMAC-SHA512 of input data using the chain code as key.

		Returns a tuple of the left and right halves of the HMAC
		"""         
		I = hmac.new(self.C, data, hashlib.sha512).digest()
		return (I[:32], I[32:])


	def CKDpriv(self, i):
		"""
		Create a child key of index 'i'.

		If the most significant bit of 'i' is set, then select from the
		hardened key set, otherwise, select a regular child key.

		Returns a BIP32Key constructed with the child key parameters,
		or None if i index would result in an invalid key.
		"""
		# Index as bytes, BE
		i_str = struct.pack(">L", i)

		# Data to HMAC
		if i & BIP32_HARDEN:
			data = b'\0' + self.k.to_string() + i_str
		else:
			data = self.PublicKey() + i_str
		# Get HMAC of data
		(Il, Ir) = self.hmac(data)

		# Construct new key material from Il and current private key
		Il_int = string_to_int(Il)
		if Il_int > CURVE_ORDER:
			return None
		pvt_int = string_to_int(self.k.to_string())
		k_int = (Il_int + pvt_int) % CURVE_ORDER
		if (k_int == 0):
			return None
		secret = (b'\0'*32 + int_to_string(k_int))[-32:]
		
		# Construct and return a new BIP32Key
		return BIP32Key(secret=secret, chain=Ir, depth=self.depth+1, index=i, fpr=self.Fingerprint(), public=False, testnet=self.testnet)


	def CKDpub(self, i):
		"""
		Create a publicly derived child key of index 'i'.

		If the most significant bit of 'i' is set, this is
		an error.

		Returns a BIP32Key constructed with the child key parameters,
		or None if index would result in invalid key.
		"""

		if i & BIP32_HARDEN:
			raise Exception("Cannot create a hardened child key using public child derivation")

		# Data to HMAC.  Same as CKDpriv() for public child key.
		data = self.PublicKey() + struct.pack(">L", i)

		# Get HMAC of data
		(Il, Ir) = self.hmac(data)

		# Construct curve point Il*G+K
		Il_int = string_to_int(Il)
		if Il_int >= CURVE_ORDER:
			return None
		point = Il_int*CURVE_GEN + self.K.pubkey.point
		if point == INFINITY:
			return None

		# Retrieve public key based on curve point
		K_i = ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1)

		# Construct and return a new BIP32Key
		return BIP32Key(secret=K_i, chain=Ir, depth=self.depth+1, index=i, fpr=self.Fingerprint(), public=True, testnet=self.testnet)


	# Public methods
	#
	def ChildKey(self, i):
		"""
		Create and return a child key of this one at index 'i'.

		The index 'i' should be summed with BIP32_HARDEN to indicate
		to use the private derivation algorithm.
		"""
		if self.public is False:
			return self.CKDpriv(i)
		else:
			return self.CKDpub(i)


	def SetPublic(self):
		"Convert a private BIP32Key into a public one"
		self.k = None
		self.public = True


	def PrivateKey(self):
		"Return private key as string"
		if self.public:
			raise Exception("Publicly derived deterministic keys have no private half")
		else:
			return self.k.to_string()


	def PublicKey(self):
		"Return compressed public key encoding"
		padx = (b'\0'*32 + int_to_string(self.K.pubkey.point.x()))[-32:]
		if self.K.pubkey.point.y() & 1:
			ck = b'\3'+padx
		else:
			ck = b'\2'+padx
		return ck


	def ChainCode(self):
		"Return chain code as string"
		return self.C


	def Fingerprint(self):
		"Return key fingerprint as string"
		cK = self.PublicKey()
		return ripemd160(sha256(cK).digest()).digest()[:4]


	def WalletImportFormat(self):
		"Returns private key encoded for wallet import"
		if self.public:
			raise Exception("Publicly derived deterministic keys have no private half")
		addressversion = b'\x80' if not self.testnet else b'\xef'
		raw = addressversion + self.k.to_string() + b'\x01' # Always compressed
		return check_encode(raw)


	def ExtendedKey(self, private=True, encoded=True, bip=44, cointype="bitcoin"):
		"Return extended private or public key as string, optionally Base58 encoded"
		if self.public is True and private is True:
			raise Exception("Cannot export an extended private key from a public-only deterministic key")
		
		if isinstance(cointype, str):
			query = query_ver(private=private, bip=bip, cointype=cointype, testnet=self.testnet)
			if not query:
				warnings.warn("Can not find suitable version from database, you can specify it through parameter cointype = (pri, pub)")
				return "Can not compute extended key because database lack of version bytes"
			version = query[0]

		elif isinstance(cointype,(tuple, list)) and len(cointype) == 2:
			# User specified
			version = cointype[0] if private else cointype[1]
			version = codecs.decode(version, "hex")

		else:
			return "Can not compute extended key because database lack of version bytes"
		
		depth = bytes(bytearray([self.depth]))
		fpr = self.parent_fpr
		child = struct.pack('>L', self.index)
		chain = self.C
		if self.public is True or private is False:
			data = self.PublicKey()
		else:
			data = b'\x00' + self.PrivateKey()
		raw = version+depth+fpr+child+chain+data
		if not encoded:
			return raw
		else:
			return check_encode(raw)

'''
network	script type		pub/priv	version bytes	human-readable prefix
mainnet	p2pkh or p2sh	public		0488b21e		xpub
mainnet	p2pkh or p2sh	private		0488ade4		xprv
mainnet	p2wpkh-p2sh		public		049d7cb2		ypub
mainnet	p2wpkh-p2sh		private		049d7878		yprv
mainnet	p2wsh-p2sh		public		0295b43f		Ypub
mainnet	p2wsh-p2sh		private		0295b005		Yprv
mainnet	p2wpkh			public		04b24746		zpub
mainnet	p2wpkh			private		04b2430c		zprv
mainnet	p2wsh			public		02aa7ed3		Zpub
mainnet	p2wsh			private		02aa7a99		Zprv
testnet	p2pkh or p2sh	public		043587cf		tpub
testnet	p2pkh or p2sh	private		04358394		tprv
testnet	p2wpkh-p2sh		public		044a5262		upub
testnet	p2wpkh-p2sh		private		044a4e28		uprv
testnet	p2wsh-p2sh		public		024289ef		Upub
testnet	p2wsh-p2sh		private		024285b5		Uprv
testnet	p2wpkh			public		045f1cf6		vpub
testnet	p2wpkh			private		045f18bc		vprv
testnet	p2wsh			public		02575483		Vpub
testnet	p2wsh			private		02575048		Vprv

'''