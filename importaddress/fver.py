import codecs
from .cointype import cointypes, coin

# cointype is used to check coin number, coin is to find version bytes

def query_ver(cointype="bitcoin", testnet=False, private=False, bip=44):
	cointype = cointype.lower() if not testnet else "testnet"
	coin_number = cointypes.get(cointype)
	if not coin_number:
		return None
	pri, pub = [codecs.decode(key, "hex") for key in coin.get(coin_number)]
	return pri if private else pub

def query_path(cointype="bitcoin", testnet=False, bip=44):
	cointype = cointype.lower() if not testnet else "testnet"
	coin_number = cointypes.get(cointype)
	path = "m/{}'/{}".format(bip, coin_number)
	return path if coin_number else None

def query_coin_num(cointype="bitcoin", testnet=False, **ab):
	cointype = cointype.lower() if not testnet else "testnet"
	coin_number = cointypes.get(cointype)
	return coin_number