from importaddress.Base58 import encode,decode,check_encode,check_decode 

test_data = [
["", ""],
["61", "2g"],
["626262", "a3gV"],
["636363", "aPEr"],
["73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"],
["00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"],
["516b6fcd0f", "ABnLTmg"],
["bf4f89001e670274dd", "3SEo3LWLoPntC"],
["572e4794", "3EFU7m"],
["ecac89cad93923c02321", "EJDM8drfXA6uyA"],
["10c8511e", "Rt5zm"],
["00000000000000000000", "1111111111"],
["000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"],
["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "1cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5NsBgNiFpWgAnEx6VQi8csexkgYw3mdYrMHr8x9i7aEwP8kZ7vccXWqKDvGv3u1GxFKPuAkn8JCPPGDMf3vMMnbzm6Nh9zh1gcNsMvH3ZNLmP5fSG6DGbbi2tuwMWPthr4boWwCxf7ewSgNQeacyozhKDDQQ1qL5fQFUW52QKUZDZ5fw3KXNQJMcNTcaB723LchjeKun7MuGW5qyCBZYzA1KjofN1gYBV3NqyhQJ3Ns746GNuf9N2pQPmHz4xpnSrrfCvy6TVVz5d4PdrjeshsWQwpZsZGzvbdAdN8MKV5QsBDY"]
]

test_data2 = [
["62e907b15cbf27d5425399ebf6f0fb50ebb88f18", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
["4733f37cf4db86fbc2efed2500b4f4e49f312023", "38BW8nqpHSWpkf5sXrQd2xYwvnPJwP59ic"],
["5a7b51041e3f0959db7783c097f278dd139ce436", "39wSTzCS9BiwF3Vci1tGXwyDXa1LReG9Jc"],
["b8a9a8ba8cf965b7df6b05afd948e53c351b2c0d", "3JXRVxhrk2o9f4w3cQchBLwUeegJBj6BEp"]
]

def test_encode():
	for p,c in test_data:
		assert c == encode(bytes.fromhex(p))

def test_decode():
	for p,c in test_data:
		assert bytes.fromhex(p) == decode(c)

def test_check_encode():
	for p,c in test_data2:
		if c.startswith("3"):
			prefix = b"\x05"
		else:
			prefix = b"\x00"
		assert c == check_encode(prefix + bytes.fromhex(p))

def test_check_decode():
	for p,c in test_data2:
		assert bytes.fromhex(p) == check_decode(c)
