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
	from fver import query_path, query_coin_num

except Exception as e:
	from .bip32 import BIP32Key, BIP32_HARDEN
	from .func import ripemd160, dsha256, sha256, hexlify, bech32_encode, check_encode, check_decode
	from .address import P2PKH, P2SH, P2WPKHoP2SH, P2WSHoP2SH, P2WPKH, P2WSH
	from .fver import query_path, query_coin_num

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
				  bip = 44, cointype = "bitcoin", testnet = False, custom_addr_type = None, adapt_path = True):
		self._entropy 		= entropy
		self.seed 			= None
		self.mnemonic 		= mnemonic
		self.path 			= path
		self.passphrase 	= passphrase
		self.BIP32_HARDEN 	= 0x80000000
		self.k 				= None
		self.bip 			= bip
		self.bip32_root_key = None
		self.bip32_ext_key 	= None
		self.cointype		= cointype.lower() if isinstance(cointype, str) else cointype
		self.testnet		= testnet
		self.custom_addr_type = custom_addr_type
		self.adapt_path 	= adapt_path
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

		# checking path
		self.usingbip = True if re.findall(r"(m\/(44|49|84)')(\/\w+'){2}(\/0)", self.path) else False 
		path = self.path.split("/")
		self.path = path + [None] if path[0] == path[-1] else path  
		self.bip = int(path[1][:-1]) if path[-1] else None
		
		# whether using custom module(custom address type)
		if self.usingbip == False and not self.custom_addr_type:
			warnings.warn("Are you using custom module? Specify your address type! Now your address type is {}.".format(self.custom_addr_type))
		
		elif self.usingbip == True and self.custom_addr_type:
			raise RuntimeError("Are you using custom module? Purpose can not be {}.".format(self.bip))

		# whether cointype match path. using tuple or list to trigger custom version bytes
		if isinstance(self.cointype, str):
			# using coin name
			path_from_db = query_path(cointype = self.cointype, testnet = self.testnet, bip = self.bip)
			vers_from_db = query_coin_num(cointype = self.cointype, testnet = self.testnet, bip = self.bip)
			
			if path_from_db:
				if not re.findall(path_from_db, self.showpath(self.path)):
					warnings.warn("Path or Cointype error, the path should start with `{}` if your cointype is `{}`(testnet is {})".format(path_from_db, self.cointype, self.testnet), stacklevel = 2)
			else:
				warnings.warn("Cointype unknown".format(path_from_db, self.cointype, self.testnet))
		
		# Correct path
		if not self.adapt_path:
			if vers_from_db:
				self.path[2] = "{}'".format(vers_from_db)
			else:
				warnings.warn("Can not correct your path, database does not have relative info")
			
		# preparing generate child-key
		self._path()

	def _path(self):
		k = BIP32Key.fromEntropy(self.seed, testnet=self.testnet)

		if not self.bip32_root_key:
			# store root key.
			self.bip32_root_key = self.exkey(k)

		if self.path[-1]:
			for _, p in enumerate(self.path):
				if "'" in p and p != 'm':
					k = k.ChildKey(int(p.strip("'")) + self.BIP32_HARDEN)
				elif p != 'm':
					k = k.ChildKey(int(p))
				if _ == 3:
					self.accounts = self.exkey(k)
		
		self.k = k
		self.bip32_ext_key = self.exkey()

		if isinstance(self.cointype, (tuple, list)):
			self.cointype = "Custom cointype"

	def index(self,n):
		return self.k.ChildKey(n)

	@property
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
			return P2PKH(pk_bytes, testnet = self.testnet).address
		elif self.bip == 49:
			return P2WPKHoP2SH(pk_bytes, testnet = self.testnet).address
		elif self.bip == 84:
			return P2WPKH(pk_bytes, testnet = self.testnet).address

		self.check_addr_type(addr_type)

		return addr_type(pk_bytes, testnet = self.testnet).address

	def scriptpubkey(self, k = None, addr_type = None):

		pk_bytes, addr_type = self.pk_bytes(k, addr_type)

		if self.bip == 44:
			return P2PKH(pk_bytes, testnet = self.testnet).scriptpubkey
		elif self.bip == 49:
			return P2WPKHoP2SH(pk_bytes, testnet = self.testnet).scriptpubkey
		elif self.bip == 84:
			return P2WPKH(pk_bytes, testnet = self.testnet).scriptpubkey

		self.check_addr_type(addr_type)

		return addr_type(pk_bytes, testnet = self.testnet).scriptpubkey

	def redeemscript(self, k = None, addr_type = None):
			
		pk_bytes, addr_type = self.pk_bytes(k, addr_type)

		if self.bip == 44:
			return P2PKH(pk_bytes, testnet = self.testnet).redeemscript
		elif self.bip == 49:
			return P2WPKHoP2SH(pk_bytes, testnet = self.testnet).redeemscript
		elif self.bip == 84:
			return P2WPKH(pk_bytes, testnet = self.testnet).redeemscript

		self.check_addr_type(addr_type)
		
		return addr_type(pk_bytes, testnet = self.testnet).redeemscript
		

	def exkey(self, k = None, encoded = True):
		k = k if k else self.k
		return (k.ExtendedKey(bip = self.bip, cointype = self.cointype, encoded = encoded), 
				k.ExtendedKey(private=False, bip = self.bip, cointype = self.cointype, encoded = encoded))

	def cokey(self , k = None):
		key = (self.k.PrivateKey(),self.k.PublicKey()) if k == None else (k.PrivateKey(),k.PublicKey())
		return  hexlify(key[0]),hexlify(key[1])

	def wif(self, k = None):
		return self.k.WalletImportFormat() if k == None else k.WalletImportFormat()

	def generate(self, n = 1):

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


	def generate_multisig_info(self, m, n):
		if not self.usingbip:
			# go
			pass

		raise RuntimeError("bip44/bip49/bip84 should not be used to create custom address.")

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
			"Cointype": self.cointype,
			"Purpose": self.path[1][:-1],
			"Coin": self.path[2][:-1],
			"Account": self.path[3][:-1],
			"External/Internal": self.path[4],
			"Account Extended Private Key": self.account[0],
			"Account Extended Public Key": self.account[1],
			"BIP32 Derivation Path": self.showpath(self.path)[:-1],
			"BIP32 Extended Pri/Pub Key": self.bip32_ext_key, 
			"Derived Addresses": addr
		})
		return Transition(__format)

class Transition(object):

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

	@property
	def to_importmulti(self):
		raise NotImplementedError

if __name__ == '__main__':
	from pprint import pprint

	words = "record pencil flock congress slim antenna tongue engage swamp soup stumble uniform collect surface neck snow celery goddess conduct cycle crowd smile secret panel"
	entropy = "b3d45565178cbc13b91a52db39ff5ef6b2d9b464ee6c250c84bb1b63459970a4"
	seed = "b0c32baffae7dc92b61706424ca70077f0b5252f1c75d37eeb3f783caec3bcb45a61f42cd2262398ea97bdf58be668d00266492ac4dddece59112928205970b6"
	assert bip39.to_mnemonic(entropy) == words
	assert bip39.to_seed(words) == unhexlify(seed)

	
	# Giving right cointype and path
	# default cointype is bitcoin
	bip44 = serialize(path="m/44'/0'/0'/0", entropy=entropy, cointype = "bitcoin")
	
	# Giving wrong cointype but right path, functions will choose your path first. 
	# If cointype unknown, extended key will be empty. specify version bytes cointype = ("0488b21e", "0488ade4")
	bip44_2 = serialize(path="m/44'/0'/0'/0", entropy=entropy, cointype = "bitcoins")

	bip44_3 = serialize(path="m/44'/0'/0'/0", entropy=entropy, cointype = ("0488b21e", "0488ade4"))
	assert bip44.generate(2).Derived_Addresses == bip44_2.generate(2).Derived_Addresses == bip44_3.generate(2).Derived_Addresses
	

	# Using HD protocol to generate custom address type. purpose can not be 44 49 84.
	custom = serialize(path="m/2'/0", entropy=entropy, cointype = "bitcoin", custom_addr_type = P2WPKH)