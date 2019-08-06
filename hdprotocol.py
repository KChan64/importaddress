import sqlite3
import re
import json
import csv
import os
import hmac
import hashlib
import ecdsa
import struct
import codecs

from binascii import unhexlify
from mnemonic import Mnemonic
from collections import OrderedDict
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int
from ecdsa.numbertheory import square_root_mod_prime as sqrt_mod

try:
		
	from fver import query_ver,query_lsit
	from func import ripemd160, dsha256, sha256, hexlify, bech32_encode, check_encode, check_decode

except Exception as e:
	raise e
	from .fver import query_ver,query_lsit
	from .func import ripemd160, dsha256, sha256, hexlify, bech32_encode, check_encode, check_decode



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


	def Identifier(self):
		"Return key identifier as string"
		cK = self.PublicKey()
		return ripemd160(sha256(cK).digest()).digest()


	def Fingerprint(self):
		"Return key fingerprint as string"
		return self.Identifier()[:4]


	def Address(self):
		"Return compressed public key address"
		addressversion = b'\x00' if not self.testnet else b'\x6f'
		vh160 = addressversion + self.Identifier()
		return check_encode(vh160)

	def P2WPKHoP2SHAddress(self):
		"Return P2WPKH over P2SH segwit address"
		pk_bytes = self.PublicKey()
		assert len(pk_bytes) == 33 and (pk_bytes.startswith(b"\x02") or pk_bytes.startswith(b"\x03")), \
			"Only compressed public keys are compatible with p2sh-p2wpkh addresses. " \
			"See https://github.com/bitcoin/serialize/blob/master/bip-0049.mediawiki."
		pk_hash = self.Identifier()
		push_20 = bytes.fromhex('0014')
		script_sig = push_20 + pk_hash
		address_bytes = ripemd160(sha256(script_sig).digest()).digest()
		prefix = b"\xc4" if self.testnet else b"\x05"
		return check_encode(prefix + address_bytes)

	def P2WPKHAddress(self):
		"Return P2WPKH over P2SH segwit address"
		pk_bytes = self.PublicKey()
		assert len(pk_bytes) == 33 and (pk_bytes.startswith(b"\x02") or pk_bytes.startswith(b"\x03"))
		address_bytes = self.Identifier()
		push_20 = bytes.fromhex('0014')
		l = list(bytearray(push_20 + address_bytes))
		l0 = l[0] - 0x50 if l[0] else 0
		hrp = "bc" if not self.testnet else "tb"
		result = bech32_encode(hrp,l0,l[2:])
		return result
		#return check_encode(push_20 + address_bytes)

	def P2WSHAddress(self):
		pk_bytes = self.PublicKey()
		assert len(pk_bytes) == 33 and (pk_bytes.startswith(b"\x02") or pk_bytes.startswith(b"\x03"))
		pk_added_code = bytes.fromhex('0014') + sha256(b"\x21" + pk_bytes + b"\xac").digest()
		hrp = "bc" if not self.testnet else "tb"
		l = list(bytearray(pk_added_code))
		l0 = l[0] - 0x50 if l[0] else 0
		address = bech32_encode(hrp, l0, l[2:])
		return address

	def WalletImportFormat(self):
		"Returns private key encoded for wallet import"
		if self.public:
			raise Exception("Publicly derived deterministic keys have no private half")
		addressversion = b'\x80' if not self.testnet else b'\xef'
		raw = addressversion + self.k.to_string() + b'\x01' # Always compressed
		return check_encode(raw)


	def ExtendedKey(self, private=True, encoded=True,bip=44,cointype="bitcoin"):
		"Return extended private or public key as string, optionally Base58 encoded"
		if self.public is True and private is True:
			raise Exception("Cannot export an extended private key from a public-only deterministic key")

		version = query_ver(private=private,bip=bip,cointype=cointype,testnet=self.testnet)[0]

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


class bip39(object):

	def __init__(self, entropy = "", words = ""):
		self.entropy = entropy
		self.words = words

	@classmethod
	def to_mnemonic(self, entropy = "", lang="english"):
		entropy = entropy if entropy else self.entropy
		return Mnemonic(lang).to_mnemonic(
			unhexlify(entropy if isinstance(entropy, str) else entropy)
			)

	@classmethod
	def generate(self, strength = 256, lang="english"):
		return bip39(words = Mnemonic(lang).generate(strength))

	@classmethod
	def to_seed(self, words = "", passphrase=""):
		return Mnemonic.to_seed(words if words else self.words, passphrase=passphrase)
		

class serialize(object):
	def __init__(self, entropy = None, passphrase = "", mnemonic = None,
				 path = None, bip=44, cointype="bitcoin", testnet=False):
		self._entropy 		= entropy
		self.seed 			= None
		self.mnemonic 		= mnemonic
		self.path 			= path
		self.passphrase 	= passphrase
		self.BIP32_HARDEN 	= 0x80000000
		self.k 				= None
		self.accounts 		= {}
		self.bip 			= bip
		self.bip32_root_key = None
		self.bip32_ext_key 	= None
		self.cointype		= cointype
		self.testnet		= testnet
		self.initialize

	def root_key2seed(root_key):
		"""
			NotImplementedError this function
		"""
		raise NotImplementedError

	@property
	def initialize(self):
		"""
			Initialize the fundamental parameters that we need through giving data
			Priority: Seed > Mnemonic > Entropy
			
			return None
		"""

		# When see is empty, so create seed if Mnemonic or _entropy has passed
		if self.mnemonic and not self._entropy:
			self.seed = bip39(words = self.mnemonic).to_seed(self.passphrase)

		elif self._entropy:
			tp = bip39.to_mnemonic(entropy = self._entropy)
			self.mnemonic = tp.words
			self.seed = tp.seed(self.passphrase)

		else:
			raise AttributeError("If you must specify entropy or mnemonic.")

		# validate path
		path = self.path.split("/")
		self.path = path + [None] if path[0] == path[-1] else path  
		state = False if self.path[0].lower() != "m" or self.path[1] not in ["44'","49'","84'",None] else True 
		
		if state == False:
			raise RuntimeError("Path error:please give a correct path")

		self.bip = int(path[1][:-1]) if path[-1] else None

		# preparing generate child-key
		self.bip32ex_path()

		# self.entropy = self.mnemonic = self.passphrase = None # clear privacy

	def bip32ex_path(self):
		"""
			analysis the giving path, save rook key and extend key
			return None
		"""
		k = BIP32Key.fromEntropy(self.seed, testnet=self.testnet)

		if not self.bip32_root_key:
			# store root key.
			self.bip32_root_key = (k.ExtendedKey(private=False, encoded=True),
						k.ExtendedKey(private=True, encoded=True))

		if self.path[-1]:
			for _, p in enumerate(self.path):
				if "'" in p and p != 'm':
					k = k.ChildKey(int(p.strip("'"))+self.BIP32_HARDEN)
				elif p != 'm':
					k = k.ChildKey(int(p))
				if _ == 3:
					self.accounts[self.showpath(self.path)[:-1]] = (k.ExtendedKey(),
																	k.ExtendedKey(private=False))
		
		self.k = k
		self.bip32_ext_key = (k.ExtendedKey(private=False, encoded=True),
						k.ExtendedKey(private=True, encoded=True))

	def index(self,n):
		"""
			return ChildKey(n)
		"""
		return self.k.ChildKey(n)

	def account(self):
		"""
			return (Account Extended Private key and Public Key)
		"""
		return self.accounts

	def address(self, k = None):
		"""
			bip44 -> P2PKH
			bip49 -> P2WPKH-nested-in-P2SH 
			bip84 -> P2WPKH
			return address
		"""
		if self.bip == 44:
			return self.k.Address() if not k else k.Address()
		elif self.bip == 49:
			return self.k.P2WPKHoP2SHAddress() if not k else k.P2WPKHoP2SHAddress()
		elif self.bip == 84:
			return self.k.P2WPKHAddress() if not k  else k.P2WPKHAddress()	
		
	def exkey(self):
		"""
			return (BIP32 Extended Private kye and Public Key)
		"""
		return self.k.ExtendedKey(bip=self.bip,cointype=self.cointype),self.k.ExtendedKey(private=False,bip=self.bip,cointype=self.cointype)

	def cokey(self , k = None):
		"""
			return (Derived coin Private key and Public Key)
		"""
		key = (self.k.PrivateKey(),self.k.PublicKey()) if k == None else (k.PrivateKey(),k.PublicKey())
		return  hexlify(key[0]),hexlify(key[1])

	def wif(self, k = None):
		"""
			return WalletImportFormat
		"""
		return self.k.WalletImportFormat() if k == None else k.WalletImportFormat()

	def generator(self, n = 1):
		"""
			`n` is how many accounts you need. 
			create multiple Account that contain `path`, `wif`, `address`, `pubkey`, `prikey`
			return FileStruct
		"""
		main_path = self.showpath(self.path)
		self.next()
		
		gen_list = []
		for i in range(n):
			index = self.index(i)
			subpath = main_path + str(i)
			wif = self.wif(index)
			address = self.address(index)
			key = self.cokey(index) #pri, pub
			gen_list.append([subpath, address, key[1], key[0], wif])

		return self.details(addr=gen_list)

	def showpath(self, p):
		"""
			p -> giving path list
			return path
		"""
		return "".join([s+"/" for s in self.path])

	def next(self):
		self.address()
		self.cokey()
		self.wif()

	def details(self, addr):
		"""
			address -> list of Derived Addresses

			return FileStruct
		"""
		__format = OrderedDict({
			"Entropy": self._entropy,
			"Mnemonic": self.mnemonic,
			"Seed": hexlify(self.seed).decode(),
			"BIP32 Root Key": self.bip32_root_key,
			"Coin": self.cointype,
			"Purpose": self.path[1][:-1],
			"Coin": self.path[2][:-1],
			"Account": self.path[3][:-1],
			"External/Internal": self.path[4],
			"Account Extended Private Key": None,
			"Account Extended Public Key": None,
			"BIP32 Derivation Path": self.showpath(self.path)[:-1],
			"BIP32 Extended Pri/Pub Key": self.bip32_ext_key, 
			"Derived Addresses": addr
		})
		return FileStruct(__format)

class FileStruct(object):

	def __init__(self, details = None):
		self.details = details
		self.__dict__.update({ re.sub(r"\W", "_", k) :v for k,v in details.items()})

	def to_csv(self):
		with open('{}.csv'.format(self.Mnemonic), 'w+', newline='') as csvfile:
			fieldnames = ['Path', 'Address', 'Public Key', 'Private Key', 'Wallet import form']
			writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

			writer.writeheader()
			for path, address, pub, pri, wif in self.Derived_Addresses:
				writer.writerow({'Path': path,
								 'Address': address,
								 "Public Key": pub,
								 "Private Key": pri,
								 "Wallet import form": wif})

	def to_json(self):
		with open('{}.json'.format(self.Mnemonic), "w+") as fd:
			json.dump(self.details, fd, indent=4)

	def to_sql(self):
		"""
			NotImplementedError
		"""
		raise NotImplementedError


if __name__ == '__main__':

	words = "record pencil flock congress slim antenna tongue engage swamp soup stumble uniform collect surface neck snow celery goddess conduct cycle crowd smile secret panel"
	entropy = "b3d45565178cbc13b91a52db39ff5ef6b2d9b464ee6c250c84bb1b63459970a4"
	seed = "b0c32baffae7dc92b61706424ca70077f0b5252f1c75d37eeb3f783caec3bcb45a61f42cd2262398ea97bdf58be668d00266492ac4dddece59112928205970b6"
	assert bip39.to_mnemonic(entropy) == words
	assert bip39.to_seed(words) == unhexlify(seed)

	'''
	entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
	mnemonic = "plate inject impose rigid plug tornado march art vast filter issue village"
	bip44 = serialize(path="m/44'/0'/0'/0",entropy=entropy) # mnemonic = mnemonic
	store44 = bip44.generator(7).Derived_Addresses

	bip49 = serialize(path="m/49'/0'/0'/0",entropy=entropy)
	store49 = bip49.generator(7).Derived_Addresses # P2WPKHoP2SHAddress

	bip84 = serialize(path="m/84'/0'/0'/0",entropy=entropy)
	store84 = bip84.generator(7).Derived_Addresses # p2wpkh

	print(store44, store49, store84)
	'''
