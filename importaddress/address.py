from .func import (
	check_decode, check_encode,
	bech32_decode, bech32_encode,
	ripemd160, hexlify, sha256,
	MoNscript)

class base(object):
	"""docstring for base"""
	def __init__(self, koa, testnet = False):
		self.addr = self.pubkey = None
		self.judge(koa)
		self.testnet = testnet

	def judge(self, koa):
		# key or address
		if isinstance(koa, bytes):
			koa = hexlify(koa)

		if 34 <= len(koa) <= 62:
			# address 
			self.addr = koa
		elif len(koa) >= 66:
			# public key or MoNscript
			self.pubkey = koa if isinstance(koa, bytes) else bytes.fromhex(koa)
		else:
			raise AttributeError

	@property
	def address(self):
		return self.Address(self.pubkey, testnet = self.testnet)

	@property
	def scriptpubkey(self):
		_, scriptpubkey = self.ScriptPubKey(self.addr if self.addr else self.pubkey)
		return scriptpubkey

	@property
	def redeemscript(self):
		redeemscript, _ = self.ScriptPubKey(self.addrif if self.addr else self.pubkey) 
		return redeemscript

class P2PKH(base):
	"""docstring for P2PKH"""
	def __init__(self, *arg, **karg):
		super(P2PKH, self).__init__(*arg, **karg)
	
	@classmethod
	def Address(self, pubkey, testnet = False):

		addressversion = b'\x00' if not testnet else b'\x6f'
		Identifier =  ripemd160(sha256(pubkey).digest()).digest()
		vh160 = addressversion + Identifier
		return check_encode(vh160)

	@classmethod
	def ScriptPubKey(self, address):

		strx = lambda x: "76a914{}88ac".format(x)
		if address[0] in ["1", "m"]:
			return None, strx(hexlify(check_decode(address)))

		return None, strx(ripemd160(sha256(address).digest()).hexdigest())


class P2SH(base):
	"""docstring for P2SH"""
	def __init__(self, *arg, **karg):
		super(P2SH, self).__init__(*arg, **karg)

	@classmethod
	def Address(self, redeemScript ,testnet = False):
		prefix = b"\xc4" if testnet else b"\x05"
		hash_again = ripemd160(sha256(redeemScript).digest()).digest()
		return check_encode(prefix + hash_again) 
	
	@classmethod
	def ScriptPubKey(self, script, otherplaces = False):

		strx = lambda x: "a914{}87".format(x)

		if script[0] in ["2","3"] and otherplaces:
			return strx(hexlify(check_decode(script)))
			
		elif script[0] in ["2","3"] and not otherplaces:
			return script, strx(hexlify(check_decode(script)))

		if len(script) >= 66 and not otherplaces:
			return  script, strx(ripemd160(sha256(bytes.fromhex(script)).digest()).hexdigest())



class P2WPKHoP2SH(base):
	"""docstring for P2WPKHoP2SH"""

	def __init__(self, *arg, **karg):
		super(P2WPKHoP2SH, self).__init__(*arg, **karg)

	@classmethod
	def Address(self, pk, testnet = False):
		pk_hash = ripemd160(sha256(pk).digest()).digest()
		push_20 = bytes.fromhex('0014')
		script_sig = push_20 + pk_hash
		address_bytes = ripemd160(sha256(script_sig).digest()).digest()
		prefix = b"\xc4" if testnet else b"\x05"
		return check_encode(prefix + address_bytes)

	@classmethod
	def ScriptPubKey(self, pk):

		if (isinstance(pk, str) and len(pk) == 34) or \
			(isinstance(pk, bytes) and len(pk) == 17):
			check = P2SH.ScriptPubKey(pk, True)
			return "unknown", check

		pk_hash = ripemd160(sha256(pk).digest()).digest()
		push_20 = bytes.fromhex('0014')
		redeemscript = push_20 + pk_hash
		ScriptPubKey =  ripemd160(sha256(redeemscript).digest()).hexdigest()
		return hexlify(redeemscript), "a914" + ScriptPubKey + "87"


class P2WSHoP2SH(base):
	"""docstring for P2WSHoP2SH"""

	def __init__(self, *arg, **karg):
		super(P2WSHoP2SH, self).__init__(*arg, **karg)

	@classmethod
	def Address(self, witnessScript, testnet = False):
		prefix = b"\xc4" if testnet else b"\x05"
		redeemScript = bytes.fromhex("0020") + sha256(witnessScript).digest()
		ScriptPubKey = ripemd160(sha256(redeemScript).digest()).digest()
		return check_encode(prefix + ScriptPubKey) 

	@classmethod
	def ScriptPubKey(self, witnessScript):

		if (isinstance(witnessScript, str) and len(witnessScript) == 34) or \
			(isinstance(witnessScript, bytes) and len(witnessScript) == 17):
			check = P2SH.ScriptPubKey(witnessScript, True)
			return "unknown", check

		redeemScript = bytes.fromhex("0020") + sha256(witnessScript).digest()
		ScriptPubKey = ripemd160(sha256(redeemScript).digest()).hexdigest()
		return hexlify(redeemScript), "a914" + ScriptPubKey + "87"


class P2WPKH(base):
	"""docstring for P2WPKH"""

	def __init__(self, *arg, **karg):
		super(P2WPKH, self).__init__(*arg, **karg)

	@classmethod
	def Address(self, pk, testnet = False):
		pk_added_code = bytes.fromhex('0014') + ripemd160(sha256(pk).digest()).digest()
		l = list(bytearray(pk_added_code))
		l0 = l[0] - 0x50 if l[0] else 0
		hrp = "bc" if not testnet else "tb"
		result = bech32_encode(hrp, l0, l[2:])
		return result 

	@classmethod
	def ScriptPubKey(self, value):
		dec = None

		if len(value) == 42:

			if value.startswith("bc"):
				dec = bech32_decode("bc", value)

			elif value.startswith("tb"):
				dec = bech32_decode("tb", value)

		if dec:
			return None ,hexlify(bytes.fromhex('0014') + bytes(dec[1]))

		pk_added_code = bytes.fromhex('0014') + ripemd160(sha256(value).digest()).digest()
		return None, hexlify(pk_added_code)


class P2WSH(base):
	"""docstring for P2WSH"""

	def __init__(self, *arg, **karg):
		super(P2WSH, self).__init__(*arg, **karg)

	@classmethod
	def Address(self, witnessScript, testnet = False):
		# witnessScript for P2WSH is special, be careful.
		witnessScript = b"\x21" + witnessScript + b"\xac" if witnessScript[0] in [2, 3] else witnessScript # single key
		pk_added_code = bytes.fromhex('0020') + sha256(witnessScript).digest()
		hrp = "bc" if not testnet else "tb"
		l = list(bytearray(pk_added_code))
		l0 = l[0] - 0x50 if l[0] else 0
		address = bech32_encode(hrp, l0, l[2:])
		return address 

	@classmethod
	def ScriptPubKey(self, witnessScript):
		# witnessScript for P2WSH is special, be careful.
		dec = None
		
		if len(witnessScript) == 62:
			# this is address!
			if witnessScript.startswith("bc"):
				dec = bech32_decode("bc", witnessScript)

			elif witnessScript.startswith("tb"):
				dec = bech32_decode("tb", witnessScript)

		if dec:
			return None, hexlify(bytes.fromhex('0020') + bytes(dec[1]))

		pk_added_code = bytes.fromhex('0020') + sha256(witnessScript).digest()
		return None, hexlify(pk_added_code)

