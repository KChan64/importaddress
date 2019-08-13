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

try:
		
	from func import  hexlify, MoNscript
	from bip32 import BIP32Key, BIP32_HARDEN
	from address import P2PKH, P2SH, P2WPKHoP2SH, P2WSHoP2SH, P2WPKH, P2WSH
	from fver import query_path, query_coin_num

except Exception as e:

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

	def __init__(self, path, entropy = "", passphrase = "", mnemonic = "", lang = "english",
				  cointype = "bitcoin", testnet = False,
				  custom_addr_type = None, adapt_path = True, extend_key = False, warning = True):
		self._entropy 		= entropy
		self.mnemonic 		= mnemonic
		self.lang 			= lang
		self.path 			= path
		self.passphrase 	= passphrase
		self.BIP32_HARDEN 	= 0x80000000
		self.bip32_root_key = None
		self.extend_key		= extend_key
		self.bip 			= None
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
			words = bip39.to_mnemonic(entropy = self._entropy, lang = self.lang)
			self.mnemonic = words
			self.seed = bip39.to_seed(words, self.passphrase)

		else:
			raise AttributeError("If you must specify entropy or mnemonic.")

		# checking path
		self.usingbip = True if re.findall(r"(m\/(44|49|84)')(\/\w+'){2}(\/0)", self.path) else False 
		path = self.path.split("/")
		self.path = path + [None] if path[0] == path[-1] else path
		if not self.custom_addr_type:
			self.bip = int(path[1][:-1]) if path[-1] else None
		
		# whether using custom module(custom address type)
		if not self.usingbip and not self.custom_addr_type and warning:
			warnings.warn("Are you using custom module? Specify your address type! Now your address type is {}.".format(self.custom_addr_type))
		
		elif self.usingbip and self.custom_addr_type and warning:
			raise RuntimeError("Are you using custom module? Purpose can not be {}.".format(self.bip))

		# whether cointype match path. using tuple or list to trigger custom version bytes
		if isinstance(self.cointype, str) and not self.custom_addr_type:
			# using coin name
			path_from_db = query_path(cointype = self.cointype, testnet = self.testnet, bip = self.bip)
			vers_from_db = query_coin_num(cointype = self.cointype, testnet = self.testnet, bip = self.bip)
			if warning:
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

		if not self.bip32_root_key and not self.custom_addr_type and self.extend_key:
			# store root key.
			self.bip32_root_key = self.exkey(k)

		if self.path[-1]:
			for _, p in enumerate(self.path):
				if "'" in p and p != 'm':
					k = k.ChildKey(int(p.strip("'")) + self.BIP32_HARDEN)
				elif p != 'm':
					k = k.ChildKey(int(p))
				if _ == 3 and not self.custom_addr_type and self.extend_key:
					self.accounts = self.exkey(k)
		
		self.k = k
		if not self.custom_addr_type and self.extend_key:
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
			raw = False if self.extend_key else True
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
		
		if not self.custom_addr_type and self.extend_key:
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

		__format = {'scriptPubKey': { "address": "" },
		  # "witnessscript": "", multigsig and witness
		  "label": "",
		  "timestamp":"now",
		  "pubkeys":[],
		  # "redeemscript":"", P2SH need
		  "keys":[], # priv key
		  "watchonly": False}
		
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
					__format["redeemscript"] = result[4]
				l.append(__format)

			return results, json.dumps(l) # original data, importmulti format

		result = self.generate_multisig(mon = mon, poolsize = poolsize, sf = sf)
		__format["scriptPubKey"]["address"] = result[3]
		__format["label"] = result[0].replace("'","h")
		__format["pubkeys"] = result[1]
		__format["keys"] = result[2]
		if result[5]:
			__format["redeemscript"] = result[5]
		__format["witnessscript"] = result[4]

		return result, json.dumps([__format])

class Transition(object):

	def __init__(self, details = None):
		self.details = details
		self.__dict__.update({ re.sub(r"\W", "_", k) :v for k,v in details.items()})

	@property
	def to_csv(self):
		with open('{}.csv'.format(self.Entropy), 'w+', newline='') as csvfile:
			fieldnames = ['Path', 'Address', 'Public Key', 'Wallet import form']
			writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

			writer.writeheader()
			for path, address, pub, wif in self.Derived_Addresses:
				writer.writerow({'Path': path,
								 'Address': address,
								 "Public Key": pub,
								 "Wallet import form": wif})

	@property
	def to_json(self):
		with open('{}.json'.format(self.Entropy), "w+") as fd:
			return json.dump(self.details, fd, indent=4)


	@property
	def raw(self):
		return self.details



if __name__ == '__main__':
	from pprint import pprint
	from time import time
	words = "record pencil flock congress slim antenna tongue engage swamp soup stumble uniform collect surface neck snow celery goddess conduct cycle crowd smile secret panel"
	entropy = "b3d45565178cbc13b91a52db39ff5ef6b2d9b464ee6c250c84bb1b63459970a4"
	seed = "b0c32baffae7dc92b61706424ca70077f0b5252f1c75d37eeb3f783caec3bcb45a61f42cd2262398ea97bdf58be668d00266492ac4dddece59112928205970b6"
	assert bip39.to_mnemonic(entropy) == words
	assert bip39.to_seed(words) == unhexlify(seed)

	# Giving right cointype and path
	# default cointype is bitcoin
	# Be careful, you have to indicate you are using testnet if you want, otherwise the output address will be wrong
	bip44 = serialize(path="m/44'/0'/0'/0", entropy=entropy, cointype = "bitcoin")
	
	# Giving wrong cointype but right path, functions will choose your path first. 
	# If cointype unknown, extended key will be empty. specify version bytes cointype = ("0488b21e", "0488ade4")
	bip44_2 = serialize(path="m/44'/0'/0'/0", entropy=entropy, cointype = "bitcoins")

	bip44_3 = serialize(path="m/44'/0'/0'/0", entropy=entropy, cointype = ("0488b21e", "0488ade4"))
	
	assert (
		bip44.generate(20) 
		== bip44_2.generate(20) 
		== bip44_3.generate(20))

	# Only need one, sf -> start from
	assert(bip44.generate(n = 3, sf = 2, raw = False).Derived_Addresses == bip44.generate(n = 3, sf = 2) == [[
		"m/44'/0'/0'/0/2",
		'15Qry7hqCjqpaJ3pEoSnmFmhP3KhHwbthR',
		'0219b78a84b266c70e8dcd060db655f36f3ea4f442b59158ee09bc7847e41a2135',
		'Kxef5HZq9TUxW3PmHtHRe5XB7khqeTN4MC9NWsCMUNeZ7wCB1AmR']])

	# Using HD protocol to generate custom address type. purpose can not be 44 49 84.
	custom = serialize(path="m/2'/0", entropy=entropy, cointype = "bitcoin", custom_addr_type = P2WPKH)
	assert (custom.generate(5, raw = False).Derived_Addresses == [["m/2'/0/0",
                        'bc1qfpul4zxrc7z35ztxmkycr3298qspsqcg5zddls',
                        '0294e050ca9ad7cee27b87729d2a85336c72782164385b2e03a5d82925328679c2',
                        'KzP7tCafv8xM1RFbnVAjAf14mGj9jBspYFqZ7Bp8Q7JbZyEnG7mG'],
                       ["m/2'/0/1",
                        'bc1qcdfwngf7fczfty67dgsx4c2ghl8uqg74ss5xg3',
                        '033588fa3711f45835c778d46f8b09f6875ecfa64b42d619eb1eeb77e7901da004',
                        'L44zErFTKZZRCpqPEBYF9XiMzLNXGKeazFd987tEBtbETjmagjVu'],
                       ["m/2'/0/2",
                        'bc1q2v6jakyjzjgtsgdy5rgvyzm4qv0megczrl3nzp',
                        '02099e466251b155cd0533c16ac088c157f61305af8188969a419d125509250cdb',
                        'KxzmGnjeJYVp4T2XKJTGVcpnN1yCvhUmoZEjWKdm8f41f1KKTaaN'],
                       ["m/2'/0/3",
                        'bc1qp7wqm426kl459va84nkh4hu9hterdnf6s0fpgp',
                        '02cd2a29e800284cdd7140dca08a43d836a389258a5f9f0afc44cb1c2281051f25',
                        'KyiNkDDErcpm13pQTQAXwmJdwsFxkNPEVWLjjcuJCTFwKPsg3A5q'],
                       ["m/2'/0/4",
                        'bc1q46wyry0j7mmphsy905d7e8lx7frp7wh4yq7cw6',
                        '03a624c0a49da54de87610c2ce4acabaa361eec92892fb7b3b61a8cdd627dbc090',
                        'L2Z77hYwweAsFNpq4hd3G83AoGX8wLnWXsxmEpM9hLUsbaGPztBL']])

	custom2 = serialize(path="m/4'/0", entropy=entropy, custom_addr_type = P2WPKHoP2SH, testnet = True)
	# origin, importmulti = custom2.to_importmulti(2) # whether test succeeded or not, need bitcoin-core

	# multisig 16/16 seems to long.
	custom3 = serialize(path="m/9'/0", entropy=entropy, custom_addr_type = P2WSH, testnet = True)
	result = custom3.generate_multisig(mon = (15,15))
	origin, importmulti2 = custom3.to_importmulti(mon = (15,15))
	assert result == origin
	# test importmulti succeeded `tb1q0zwle25cyned4ywwdnhxufqrtazy26vcat7353jj3raez002w49qdez7dz`
	# In `4bd3c02eb3934aa363d5823859559c4da1d38390501b196a44726ab3e7b0af7b`
	# Out `0ed2b81937bb906f66196f9a209fc6c3dc3d46c5a07853dea87010e7faa8af81`