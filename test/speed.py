import six
import timeit

def do(setup_statements, statement, times):
	# extracted from timeit.py
	t = timeit.Timer(stmt=statement,
					 setup="\n".join(setup_statements))
	return t.timeit(times) / times

def test_importaddress():
	entropy = "b3d45565178cbc13b91a52db39ff5ef6b2d9b464ee6c250c84bb1b63459970a4"
	for path in ["m/44'", "m/44'/0'", "m/44'/0'/0'", "m/44'/0'/0'/0"]:
		S1 = "from importaddress.hdprotocol import serialize" 
		S2 = """bip = serialize(path="{path}", entropy="{entropy}")""".format(path=path, entropy=entropy)
		# default poolsize is 8.
		S3 = "key = bip.generate(20)"
		S4 = "key = bip.generate(20, poolsize=1)"
		init = do([S1], S2, 4)
		genkey = do([S1,S2], S3, 7)
		print("{:<13s}: init:{:7f}s, generate 20 keys:{:7f}s.".format(path, init, genkey))

if __name__ == '__main__':
	test_importaddress()