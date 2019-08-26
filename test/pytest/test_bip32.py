import pytest
from importaddress.bip32 import BIP32Key
from importaddress.func import hexlify
@pytest.fixture
def BIP32(request, seed):
	return BIP32Key.fromEntropy(seed)

def test_child_key(BIP32):
	assert BIP32.CKDpub(0).PublicKey() == b"\x03\xa1I\x98\xd0\xc3\xa1A\x8b~F\xb6\x14t\xd4\xdf\xedq'\xbe\x9eh\xee\xc6\xb7\xdbK\xf2\xc3\x03\x0c\x16\xcb"

def test_wif_error():
	with pytest.raises(Exception):
		assert BIP32.CKDpub(0).WalletImportFormat() != None

def test_ChainCode(BIP32):
	assert BIP32.ChainCode() == b'b\x98\xa2,\xa1\xc5$Ca?d\xb5\xc09\xb3\xbc\xa1\xc1\x89\xae$\x14 |\xc7\xfe.p\x03\xa8w\xda'
