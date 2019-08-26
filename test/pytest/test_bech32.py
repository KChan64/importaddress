from importaddress.segwit_addr import encode, decode
import pytest

valid = [
["BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"],
["tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"],
["bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"],
["BC1SW50QA3JX3S", "6002751e"],
["bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "5210751e76e8199196d454941c45d1b3a323"],
["tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"]
]


invalid = [
"tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty" # Invalid human-readable part
"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5" # Invalid checksum
"BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2" # Invalid witness version
"bc1rw5uspcuh" # Invalid program length
"bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90" # Invalid program length
"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P" # Invalid program length for witness version 0 (per BIP141)
"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7" # Mixed case
"bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du" # zero padding of more than 4 bits
"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv" # Non-zero padding in 8-to-5 conversion
"bc1gmk9yu" # Empty data section
]

def test_encode():
	for c,p in valid:
		p = bytes.fromhex(p)
		l0 = p[0] - 0x50 if p[0] else 0
		assert c.lower() == encode(c[:2].lower(), l0, p[2:])

def test_decode():
	for c,p in valid:
		c = c.lower()
		p = bytes.fromhex(p)[2:]
		assert bytes(decode(c[:2], c)[1]) == p

def test_decode_invalid():
	for c in invalid:
		c = c.lower()
		with pytest.raises(Exception):
			bytes(decode(c[:2], c)[1])

