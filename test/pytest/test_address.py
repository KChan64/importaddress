from importaddress.address import P2PKH, P2SH, P2WPKHoP2SH, P2WSHoP2SH, P2WPKH, P2WSH
from importaddress.func import MoNscript
from binascii import unhexlify

"""
key -> scriptpubkey, address, redeemscript(option)
address -> scriptpubkey, redeemscript(option)
scriptpubkey -> address :TODO
"""


def test_MoNscript():
	publickeylist = ["021e6617e06bb90f621c3800e8c37ab081a445ae5527f6c5f68a022e7133f9b5fe", "03bea1a8ce6369435bb74ff1584a136a7efeebfe4bc320b4d59113c92acd869f38", "0280631b27700baf7d472483fadfe1c4a7340a458f28bf6bae5d3234312d684c65"]
	assert MoNscript(2,3,publickeylist) == "5221021e6617e06bb90f621c3800e8c37ab081a445ae5527f6c5f68a022e7133f9b5fe2103bea1a8ce6369435bb74ff1584a136a7efeebfe4bc320b4d59113c92acd869f38210280631b27700baf7d472483fadfe1c4a7340a458f28bf6bae5d3234312d684c6553ae"

def test_witness_address_bip173():
	# Ignoring redeemscript as this is not a P2SH script. Means only P2SH need redeemscript
	pk = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	p2wsh = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
	p2wpkh = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	assert P2WPKH(pk).address == p2wpkh
	assert P2WSH(pk).address == p2wsh

def test_P2WSHoP2SH():
	P2WSHoP2SHAddress_witnessScript = "5221021e6617e06bb90f621c3800e8c37ab081a445ae5527f6c5f68a022e7133f9b5fe2103bea1a8ce6369435bb74ff1584a136a7efeebfe4bc320b4d59113c92acd869f38210280631b27700baf7d472483fadfe1c4a7340a458f28bf6bae5d3234312d684c6553ae"
	P2WSHoP2SHAddress_ = "3CYkk3x1XUvdXCdHtRFdjMjp17PuJ8eR8z"
	assert P2WSHoP2SH(P2WSHoP2SHAddress_witnessScript).address == P2WSHoP2SHAddress_
	# lack of redeemscript and scriptpubkey

def test_P2SH():
	# need a standard data, 51..51ae might be changed now, i think
	redeemScript_single = "5141042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf51ae"
	single_P2SH_address = "3P14159f73E4gFr7JterCCQh9QjiTjiZrG"
	redeemScript_mon = "522102194e1b5671daff4edc82ce01589e7179a874f63d6e5157fa0def116acd2c3a522103a043861e123bc67ddcfcd887b167e7ff9d00702d1466524157cf3b28c7aca71b2102a49a62a9470a31ee51824f0ee859b0534a4f555c0e2d7a9d9915d6986bfc200453ae"
	mon_P2SH_address = "3JUJgXbB1WpDEJprE8wP8vEXtba36dAYbk"
	assert P2SH(redeemScript_single).address == single_P2SH_address
	assert P2SH(redeemScript_mon).address == mon_P2SH_address
	# lack of redeemscript and scriptpubkey

def test_P2PKH():
	pk = "02fa84946ba062ea6cadf77561ca8859ef1de8edf6dd0bf91f516b770c84135b60"
	assert P2PKH(pk).address == "1DksSA9vNRbpG6etkDoWkqVHBfj8HmtyL9"
	# lack of scriptpubkey

def test_P2WPKH():	
	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Native_P2WPKH
	key = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
	assert P2WPKH(key).scriptpubkey == "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1" # ScriptPubKey 
	assert P2WPKH("tb1qm3e067l5aadlmr07qg05rudd05m3vmw2606rzj").scriptpubkey == "0014dc72fd7bf4ef5bfd8dfe021f41f1ad7d37166dca"
	# lack of address

def test_P2WPKHoP2SH():
	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
	key = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
	clss = P2WPKHoP2SH(key)
	redeemscript, ScriptPubKey = clss.redeemscript, clss.scriptpubkey
	assert redeemscript == "001479091972186c449eb1ded22b78e40d009bdf0089"
	assert ScriptPubKey == "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"
	assert P2WPKHoP2SH(key).address == "38BW8nqpHSWpkf5sXrQd2xYwvnPJwP59ic"
	assert P2WPKHoP2SH("39wSTzCS9BiwF3Vci1tGXwyDXa1LReG9Jc").scriptpubkey == "a9145a7b51041e3f0959db7783c097f278dd139ce43687"


def test_P2WSHoP2SH():
	key = "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"
	clss = P2WSHoP2SH(key)
	redeemScript, ScriptPubKey = clss.redeemscript, clss.scriptpubkey
	assert redeemScript == "0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54"
	assert ScriptPubKey == "a9149993a429037b5d912407a71c252019287b8d27a587"
	assert P2WSHoP2SH("3JXRVxhrk2o9f4w3cQchBLwUeegJBj6BEp").scriptpubkey  == "a914b8a9a8ba8cf965b7df6b05afd948e53c351b2c0d87"

def test_P2WSH():
	key = "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
	assert P2WSH(key).scriptpubkey == "00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"
		
	# Data from 9988eaabbcf5976d13f91c28604f921239ed3fadf4592d1a0a0e288b419a78a4
	key = "5221035c8e83fa4ca1d74d10f122daaac69b006e5c02a1594b78907881190500b1f22a2102c1235301c06e94bdd44c248e6c824b58fafea3ceee4db2857402e322486046842103e46359fd20b25a7be466984f156084be0dead32e4e99cec2e0f7c9ad4863daaa53ae"
	assert P2WSH(key).scriptpubkey , "0020d3124de88d90949cf90ed655bfd306f00d9473387eedc59d819d51bc6880f29d"
	assert P2WSH("bc1qm2pz5342a0n3ctv9hm6s568zeye8cw7j90j0nmjdwkrcy78qs2nsfyp945").scriptpubkey == "0020da822a46aaebe71c2d85bef50a68e2c9327c3bd22be4f9ee4d75878278e082a7"
	assert P2WSH("tb1q0zwle25cyned4ywwdnhxufqrtazy26vcat7353jj3raez002w49qdez7dz").scriptpubkey == "0020789dfcaa9824f2da91ce6cee6e24035f44456998eafd1a465288fb913dea754a"
	

def test_P2PKH():
	key = "039e84846f40570adc5cef6904e10d9f5a5dadb9f2afd07cc9aad188d769c50b46"
	assert P2PKH(key).scriptpubkey == "76a914d259038d23c4a8f9dd4eaaf92316d191f18d963788ac"
	assert P2PKH("1LBDY5Sugh4i2XS6StMKA1ZZiyN4a59Sdf").scriptpubkey == "76a914d259038d23c4a8f9dd4eaaf92316d191f18d963788ac"
	# hex-bytes input
	key = "039e84846f40570adc5cef6904e10d9f5a5dadb9f2afd07cc9aad188d769c50b46"
	assert P2PKH(unhexlify(key)).scriptpubkey == "76a914d259038d23c4a8f9dd4eaaf92316d191f18d963788ac"
	