import sqlite3
import re
import json
import csv
import warnings

from binascii import unhexlify
from mnemonic import Mnemonic
from collections import OrderedDict
try:
		
	from func import ripemd160, dsha256, sha256, hexlify, bech32_encode, check_encode, check_decode
	from bip32 import BIP32Key, BIP32_HARDEN
	from address import P2PKH, P2SH, P2WPKHoP2SH, P2WSHoP2SH, P2WPKH, P2WSH

except Exception as e:
	raise e
	from .bip32 import BIP32Key, BIP32_HARDEN
	from .func import ripemd160, dsha256, sha256, hexlify, bech32_encode, check_encode, check_decode
	from .address import P2PKH, P2SH, P2WPKHoP2SH, P2WSHoP2SH, P2WPKH, P2WSH

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

class _serialize(object):
	"""docstring for _serialize"""
	def __init__(self, arg):
		super(_serialize, self).__init__()
		self.arg = arg
		
		

class serialize(object):

	def __init__(self, path, entropy = "", passphrase = "", mnemonic = "",
				  bip = 44, cointype = "bitcoin", testnet = False, custom_addr_type = None):
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
		self.custom_addr_type = None
		self.initialize


	@property
	def initialize(self):
		#	Priority: Seed > Mnemonic > Entropy
		if self.mnemonic and not self._entropy:
			self.seed = bip39(words = self.mnemonic).to_seed(self.passphrase)

		elif self._entropy:
			words = bip39.to_mnemonic(entropy = self._entropy)
			self.mnemonic = words
			self.seed = bip39.to_seed(words, self.passphrase)

		else:
			raise AttributeError("If you must specify entropy or mnemonic.")

		# verify path
		usingbip = True if re.findall(r"(m\/(44|49|84)')(\/\w+'){2}(\/0)", self.path) else False 
		path = self.path.split("/")
		self.path = path + [None] if path[0] == path[-1] else path  
		
		if usingbip == False:
			warnings.warn("Are you using custom module? \
				Specify your address type! Now your address type is {}".format(self.custom_addr_type))

		self.bip = int(path[1][:-1]) if path[-1] else None

		# preparing generate child-key
		self.split_path()

	def split_path(self):
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
		return self.k.ChildKey(n)

	def account(self):
		return self.accounts

	def root_key2seed(root_key):
		raise NotImplementedError


	def check_addr_type(self, addr_type):
		if addr_type not in [P2PKH, P2SH, P2WPKHoP2SH, P2WSHoP2SH, P2WPKH, P2WSH]:
			raise RuntimeError("You have to use P2PKH, P2SH, P2WPKHoP2SH, P2WSHoP2SH, P2WPKH, P2WSH. They inside `address.py`")

	def pk_bytes(self, k = None, addr_type = None):
		# In fact, this function used to reduce duplicate code
		pk_bytes = self.k.PublicKey() if not k else k.PublicKey()
		addr_type = addr_type if addr_type else self.custom_addr_type
		if addr_type != self.custom_addr_type:
			self.custom_addr_type = addr_type

		return pk_bytes, addr_type

	def address(self, k = None, addr_type = None):
		
		pk_bytes, addr_type = self.pk_bytes(k, addr_type)

		if self.bip == 44:
			return P2PKH(pk_bytes).address
		elif self.bip == 49:
			return P2WPKHoP2SH(pk_bytes).address
		elif self.bip == 84:
			return P2WPKH(pk_bytes).address

		self.check_addr_type(addr_type)

		return addr_type(pk_bytes).address

	def scriptpubkey(self, k = None, addr_type = None):

		pk_bytes, addr_type = self.pk_bytes(k, addr_type)

		if self.bip == 44:
			return P2PKH(pk_bytes).scriptpubkey
		elif self.bip == 49:
			return P2WPKHoP2SH(pk_bytes).scriptpubkey
		elif self.bip == 84:
			return P2WPKH(pk_bytes).scriptpubkey

		self.check_addr_type(addr_type)

		return addr_type(pk_bytes).scriptpubkey

	def redeemscript(self, k = None, addr_type = None):
			
		pk_bytes, addr_type = self.pk_bytes(k, addr_type)

		if self.bip == 44:
			return P2PKH(pk_bytes).redeemscript
		elif self.bip == 49:
			return P2WPKHoP2SH(pk_bytes).redeemscript
		elif self.bip == 84:
			return P2WPKH(pk_bytes).redeemscript

		self.check_addr_type(addr_type)
		
		return addr_type(pk_bytes).redeemscript
		
	def exkey(self):
		return self.k.ExtendedKey(bip=self.bip,cointype=self.cointype),self.k.ExtendedKey(private=False,bip=self.bip,cointype=self.cointype)

	def cokey(self , k = None):
		key = (self.k.PrivateKey(),self.k.PublicKey()) if k == None else (k.PrivateKey(),k.PublicKey())
		return  hexlify(key[0]),hexlify(key[1])

	def wif(self, k = None):
		return self.k.WalletImportFormat() if k == None else k.WalletImportFormat()

	def generator(self, n = 1):
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
		return "".join([s+"/" for s in self.path])

	def next(self):
		self.address()
		self.cokey()
		self.wif()

	def details(self, addr):
		__format = OrderedDict({
			"Entropy": self._entropy,
			"Mnemonic": self.mnemonic,
			"Seed": hexlify(self.seed),
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

	@property
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

	@property
	def to_json(self):
		with open('{}.json'.format(self.Mnemonic), "w+") as fd:
			return json.dump(self.details, fd, indent=4)

	def to_sql(self):
		"""
			NotImplementedError
		"""
		raise NotImplementedError

	@property
	def raw(self):
		return self.details


if __name__ == '__main__':

	words = "record pencil flock congress slim antenna tongue engage swamp soup stumble uniform collect surface neck snow celery goddess conduct cycle crowd smile secret panel"
	entropy = "b3d45565178cbc13b91a52db39ff5ef6b2d9b464ee6c250c84bb1b63459970a4"
	seed = "b0c32baffae7dc92b61706424ca70077f0b5252f1c75d37eeb3f783caec3bcb45a61f42cd2262398ea97bdf58be668d00266492ac4dddece59112928205970b6"
	assert bip39.to_mnemonic(entropy) == words
	assert bip39.to_seed(words) == unhexlify(seed)

	
	entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
	mnemonic = "plate inject impose rigid plug tornado march art vast filter issue village"
	bip44 = serialize(path="m/44'/0'/0'/0",entropy=entropy) # mnemonic = mnemonic
	store44 = bip44.generator(7)

	'''
	bip49 = serialize(path="m/49'/0'/0'/0",entropy=entropy)
	store49 = bip49.generator(7).Derived_Addresses # P2WPKHoP2SHAddress

	bip84 = serialize(path="m/84'/0'/0'/0",entropy=entropy)
	store84 = bip84.generator(7).Derived_Addresses # p2wpkh

	print(store44, store49, store84)
	'''
	from pprint import pprint
	pprint(store44.raw)
