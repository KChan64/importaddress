import re
import json
import csv
import warnings
import time

from binascii import unhexlify
from mnemonic import Mnemonic
from collections import OrderedDict
from multiprocessing import Pool as process
from functools import partial


from .bip32 import BIP32Key, BIP32_HARDEN
from .func import hexlify, MoNscript
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

class serialize(object):

	def __init__(self, path, entropy = "", passphrase = "", mnemonic = "", lang = "english", extended_key = "",
				  cointype = "bitcoin", testnet = False,
				  custom_addr_type = None, adapt_path = True, show_extend_key = False, warning = False):
		self._entropy 		= entropy
		self.mnemonic 		= mnemonic
		self.lang 			= lang
		self.path 			= path
		self.passphrase 	= passphrase
		self.BIP32_HARDEN 	= 0x80000000
		self.bip32_root_key = extended_key
		self.show_extend_key= show_extend_key
		self.bip 			= None
		self.cointype		= cointype.lower() if isinstance(cointype, str) else cointype
		self.testnet		= testnet
		self.custom_addr_type = custom_addr_type
		self.adapt_path 	= adapt_path
		self.warning 		= warning
		self.initialize


	@property
	def initialize(self):
		#	Priority: Seed > Mnemonic > Entropy
		if self.mnemonic and not self._entropy:
			self.seed = bip39(words = self.mnemonic).to_seed(self.passphrase)

		elif self._entropy:
			words = bip39.to_mnemonic(entropy = self._entropy, lang = self.lang)
			self.mnemonic = words
			self.seed = bip39.to_seed(words, self.passphrase)

		elif self.bip32_root_key:
			self.seed = None

		else:
			raise AttributeError("If you must specify entropy or mnemonic.")

		# checking path
		self.usingbip = True if re.findall(r"(m\/(44|49|84)')(\/\w+'){2}(\/0)", self.path) else False 
		path = self.path.split("/")
		self.path = path + [None] if path[0] == path[-1] else path
		if not self.custom_addr_type:
			self.bip = int(path[1][:-1]) if path[-1] else None
		
		# whether using custom module(custom address type)
		if not self.usingbip and not self.custom_addr_type and self.warning:
			warnings.warn("Are you using custom module? Specify your address type! Now your address type is {}.".format(self.custom_addr_type))
		
		elif self.usingbip and self.custom_addr_type and self.warning:
			raise RuntimeError("Are you using custom module? Purpose can not be {}.".format(self.bip))

		# whether cointype match path. using tuple or list to trigger custom version bytes
		if isinstance(self.cointype, str) and not self.custom_addr_type:
			# using coin name
			path_from_db = query_path(cointype = self.cointype, testnet = self.testnet, bip = self.bip)
			vers_from_db = query_coin_num(cointype = self.cointype, testnet = self.testnet)
			if self.warning:
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
		if self.seed:
			k = BIP32Key.fromEntropy(self.seed, testnet=self.testnet)

		elif isinstance(self.bip32_root_key, (list, tuple)):
			xkey, ispublic = self.bip32_root_key
			k = BIP32Key.fromExtendedKey(xkey, public = ispublic, testnet=self.testnet)

		else:
			raise RuntimeError("Lack of entropy/mnemonic/extendedkey")

		if not self.bip32_root_key and not self.custom_addr_type and self.show_extend_key:
			# store root key.
			self.bip32_root_key = self.exkey(k)

		if self.path[-1]:
			for _, p in enumerate(self.path):
				if "'" in p and p != 'm':
					k = k.ChildKey(int(p.strip("'")) + self.BIP32_HARDEN)
				elif p != 'm':
					k = k.ChildKey(int(p))
				if _ == 3 and not self.custom_addr_type and self.show_extend_key:
					self.accounts = self.exkey(k)
		
		self.k = k
		if not self.custom_addr_type and self.show_extend_key:
			self.bip32_ext_key = self.exkey()

		if isinstance(self.cointype, (tuple, list)):
			self.cointype = "Custom cointype"

	def index(self,n):
		return self.k.ChildKey(n)

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

	def key(self , k = None):
		key = (self.k.WalletImportFormat(), self.k.PublicKey()) if not k else (k.WalletImportFormat(), k.PublicKey())
		return  [hexlify(key[1]), key[0]]

	def info(self, i, main_path, extra = False):
		# extra parameter is for `importmulti`
		index = self.index(i)
		subpath = main_path + str(i)
		address = self.address(index)
		key = self.key(index) 

		if not extra:
			return [subpath, address] + key

		redeemscript = self.redeemscript(index)
		return [subpath, address] + key + [redeemscript]

	def generate(self, n = 1, sf = 0, poolsize = 8, raw = True):
		n += sf
		poolsize = poolsize if (n - sf) >= poolsize else (n - sf)
		if raw:
			# If false, means user NEED THIS
			raw = False if self.show_extend_key else True
		main_path = self.showpath(self.path)

		info = partial(self.info, main_path = main_path)
		with process(poolsize) as pool:
			result = pool.map(info, range(sf, n))

		if raw:
			return result

		return self.details(addr=result)


	def info_multisig(self, i, main_path):
		# extra parameter is for `importmulti`
		index = self.index(i)
		key = self.key(index)
		return key

	def generate_multisig(self, mon, sf = 0, poolsize = 8):
		m, n = mon
		n += sf
		if not self.usingbip:
			poolsize = poolsize if (n - sf) >= poolsize else (n - sf)
		
			main_path = self.showpath(self.path)

			info = partial(self.info_multisig, main_path = main_path)

			with process(poolsize) as pool:
				result = pool.map(info, range(sf, n))

			path = main_path + "{sf}~{n}".format(sf=sf, n=n)
			key = [r[0] for r in result]
			monscript = MoNscript(m, n, key)
			ins = self.custom_addr_type(monscript, testnet = self.testnet)
			address = ins.address
			redeemscript = ins.redeemscript

			results = [path] + list(zip(*result)) + [address, monscript, redeemscript]

			return results


		raise RuntimeError("bip44/bip49/bip84 should not be used to create custom address.")

	def showpath(self, p):
		return "".join([s+"/" for s in p])


	def details(self, addr):
		
		if not self.custom_addr_type and self.show_extend_key:
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
				"Account Extended Private Key": self.accounts[0],
				"Account Extended Public Key": self.accounts[1],
				"BIP32 Derivation Path": self.showpath(self.path)[:-1],
				"BIP32 Extended Pri/Pub Key": self.bip32_ext_key, 
				"Derived Addresses": addr
			})

		else:
			__format = OrderedDict({
				"Entropy": self._entropy,
				"Mnemonic": self.mnemonic,
				"Seed": hexlify(self.seed),
				"Main path":self.showpath(self.path),
				"Derived Addresses": addr
			})


		return Transition(__format)


	
	def to_importmulti(self, n = 1, sf = 0, poolsize = 8, mon = None):

		__format = OrderedDict({'scriptPubKey': { "address": "" },
		  # "witnessscript": "", multigsig and witness
		  "label": "",
		  "timestamp":"now",
		  "pubkeys":[],
		  # "redeemscript":"", P2SH need
		  "keys":[], # priv key
		  "watchonly": False})
		
		l = []
		
		if not mon:
			n += sf
			poolsize = poolsize if (n - sf) >= poolsize else (n - sf)
		
			main_path = self.showpath(self.path)

			info = partial(self.info, main_path = main_path, extra = True)
			with process(poolsize) as pool:
				results = pool.map(info, range(sf, n))

			for result in results:
				__format["scriptPubKey"]["address"] = result[1]
				__format["label"] = result[0].replace("'","h")
				__format["pubkeys"] = [result[2]]
				__format["keys"] = [result[3]]
				if result[4]:
					# P2WPK-P2SH
					__format["redeemscript"] = result[4]
				l.append(__format)

			return l, json.dumps(l) # original data, importmulti format

		result = self.generate_multisig(mon = mon, poolsize = poolsize, sf = sf)
		__format["scriptPubKey"]["address"] = result[3]
		__format["label"] = result[0].replace("'","h")
		__format["pubkeys"] = result[1]
		__format["keys"] = result[2]
		if self.custom_addr_type != P2SH:
			# P2WSH / P2WSH-PSH
			if result[5]:
				__format["redeemscript"] = result[5]

			__format["witnessscript"] = result[4]
		else:
			# P2SH
			__format["redeemscript"] = result[4]

		return __format, json.dumps([__format])

class Transition(object):

	def __init__(self, details = None):
		self.details = details
		self.__dict__.update({ re.sub(r"\W", "_", k) :v for k,v in details.items()})

	
	def to_csv(self, filename = None):
		filename = filename if filename else self.Entropy
		with open('{}.csv'.format(filename), 'w+', newline='') as csvfile:
			fieldnames = ['Path', 'Address', 'Public Key', 'Wallet import form']
			writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

			writer.writeheader()
			for path, address, pub, wif in self.Derived_Addresses:
				writer.writerow({'Path': path,
								 'Address': address,
								 "Public Key": pub,
								 "Wallet import form": wif})

	
	def to_json(self, filename = None):
		filename = filename if filename else self.Entropy
		with open('{}.json'.format(filename), "w+") as fd:
			return json.dump(self.details, fd, indent=4)


	@property
	def raw(self):
		return self.details
