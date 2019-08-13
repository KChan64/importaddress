import unittest
from importaddress.func import MoNscript
from importaddress.hdprotocol import serialize
from importaddress.address import P2PKH, P2SH, P2WPKHoP2SH, P2WSHoP2SH, P2WPKH, P2WSH
from collections import OrderedDict

words = "record pencil flock congress slim antenna tongue engage swamp soup stumble uniform collect surface neck snow celery goddess conduct cycle crowd smile secret panel"
entropy = "b3d45565178cbc13b91a52db39ff5ef6b2d9b464ee6c250c84bb1b63459970a4"
seed = "b0c32baffae7dc92b61706424ca70077f0b5252f1c75d37eeb3f783caec3bcb45a61f42cd2262398ea97bdf58be668d00266492ac4dddece59112928205970b6"

class test(unittest.TestCase):
	"""docstring for test"""

	def test_using_bip44_49_84(self):
		'''
		Default cointype is `bitcoin`, cointype only influence version bytes of `extended key`.
		If you want to see `extended key` you have to set parameter `extend_key = True` and 
			use `to_json` or `raw` to show it
		'''
		bip44 = serialize(path="m/44'/0'/0'/0", entropy=entropy).generate(5)
		test_data = [
					["m/44'/0'/0'/0/0","1C8ms58sg9a1dQKrTKwt2wP6eHGBJmnnEN","0201192c11fdba5f77dbee8af32f2fe038981ae4ac93a360fd698cd9f5a0def3e1","L291freeUv6GGXDD23UkvuviTTiKsdgHZ5ViNVYMFTHQZoSiykYt"],
					["m/44'/0'/0'/0/1","1PU2yxbUuxs2Va8jcnE2jhu2N6pvZXHuEU","03fff7a05dda6e6b688dab2d534cc1f46cad271331dc67827cb0bf12007a64dd6e","L41ihSongCBiD9YCeKXWUidSmKPqGHEdhaHktsWHG6j1SFn46kWr"],
					["m/44'/0'/0'/0/2","15Qry7hqCjqpaJ3pEoSnmFmhP3KhHwbthR","0219b78a84b266c70e8dcd060db655f36f3ea4f442b59158ee09bc7847e41a2135","Kxef5HZq9TUxW3PmHtHRe5XB7khqeTN4MC9NWsCMUNeZ7wCB1AmR"],
					["m/44'/0'/0'/0/3","1MBgfJ2YHcaTk1WbuMgJzBYfJHDiK7grP3","038ef95d20f507d083b00bec9aa0f595046f1019dd0c1fa5e3e69b5b2eda78657d","KzdEGEWcWQkLb5RSsAMiopdKgcSTBP1bzp2Fdr9kERjryNxcGWxZ"],
					["m/44'/0'/0'/0/4","139KkfwHytbBEQVW1GBCqJsJXud9P1dsHm","027bd4373aa42fdee6e064f7f8363cef796017ac79b27c72028dd349b50d36c3b9","L1SVV5jGhKbX4aZ5bejZVCXS51zK6b4TUGRneUewSjQ6ZHUQSoKt"]
					]
		self.assertEqual(bip44, test_data)
		
		bip49 = serialize(path="m/49'/0'/0'/0", entropy=entropy).generate(5)
		test_data = [["m/49'/0'/0'/0/0","34TcDG5AHzjouvzSYJPrJeGC2joeBjz3PW","02341f91a84af51fd7a4a519294dea4484b5c093102f9ba0ad0c4f6ae923af0ff6","L3bnBv6MH4CroAvsQfJMhjXm4yVNRHCRmJn596TwtNNjax7k5mqr"],
					["m/49'/0'/0'/0/1","3LK9ZUpNXYXvd2GBa5CRz5cUNGybD2j9gh","03ffc10361d68e04e058a23c569ac768c8112070466119a32bca096304da91b0ac","KwK5DK8BxpUP8EjWxTHvLDRV8croVy7ELtMEnGQBTvLSyarxUZvq"],
					["m/49'/0'/0'/0/2","333anCiKHDJ2R4KPe2Da7KUgrjWtcCJqpf","03462d8822d5e2a7323c9d6dc0e7655ca9dd1e00611f18667bc200fba3e7fc5951","L2HbaSAKmBqvFGSHnop1ZWiSpYs2CeTq4mNKHgBJTxBFnnmZXL5q"],
					["m/49'/0'/0'/0/3","38V69bjz8xcABFW2FmRor7i5v8TTQbLX98","02868e329f8b6fbad94bfca58432d73fa82ef9a329dd940a42398fa0b8400586d6","KzFCgxNQQvB5mkVFVxmg9ZDsN9L9MYxzeJsr96yCXMoLWjQqraRV"],
					["m/49'/0'/0'/0/4","3CmcVpMcWWyjYHdPHwhgfJGfbXYA9MzahS","02cfcc7a964e0a7e549bdbaeaf3dcef2d7c0f1dbd8c0645fcce30537c66d62865a","KzHaPS7iApCPfEc6LJxtVeUN1wB8sXieK97DC1reURW7hsSQS6pM"]]
		self.assertEqual(bip49, test_data)
		
		bip84 = serialize(path="m/84'/0'/0'/0", entropy=entropy).generate(5)
		test_data = [["m/84'/0'/0'/0/0","bc1qh0m35vfdzvle56rk86j3pstfgwlhlvv47dp3kg","0208adb0e2f515f4831ae1e7d737e006b6a9e03893d7d70bed06ee735a004861c7","KwzvYh3pt5Xkju4LHMWPkLSJoGHRCpCDjDmcsMTLKHEtpb5w9A31"],
					["m/84'/0'/0'/0/1","bc1qcz90q3j0g62esgfzc3jak0ltfk2hrhnvzq7lv9","03860650443cfb396f2b75e2ab6c4cf87b5b93c4c94e369ee88d1a6f1697a6e6ab","KyinKksJv72Q3iomKqQiYPTbjLmt5SYnFqLCHkxPJtE9mswQucVm"],
					["m/84'/0'/0'/0/2","bc1qj33dse7mf2eqnf8t02aylkhfgpur44p7dvy43r","025e9aa01551839188ff84b0644c6f94208c41dde3f4325b4c8d1e4e4ddcc81864","Kz65McGX1h58hF8wkDRuEaF4aThEiVokEuRdWuZrhuqshDAYwQLk"],
					["m/84'/0'/0'/0/3","bc1qu6d7mrn9sqh83eek224wwagmzqlzglpx36ze2e","03e36c1c54bf6581d2ef6263e675247c6bc0979b547f742ad8cb5d5609ee66251e","L2yzCjTZwi61vLcaNDLjSfgVCt7EudgfgQ9ZvTrTM6wCy61koGPD"],
					["m/84'/0'/0'/0/4","bc1qt58rqh7cg9vgtsvl2teamkrxxw9hf03ytjum6t","034cb0779bf451bf39adf0ba50fc91539d733f654bbadcba15ab2777a0554637ee","KwGqRptvCRF95T1V4Gq7ejy47HWPRg3T367pTpJdZt25tydrnbSz"]]
		self.assertEqual(bip84, test_data)

	def test_using_bip__with_wrong_cointype(self):
		# It doesn't matter, because only `extended key` is associated with cointype
		# When `extend_key` turn off, so `ExtendedKey` function will not be triggered. 
		# That means cointype will not be used
		# default `extend_key = False`
		bip44 = serialize(path="m/44'/0'/0'/0", entropy=entropy, 
							cointype = "bitcoins")
		addresses = bip44.generate(2)
		test_data = [["m/44'/0'/0'/0/0","1C8ms58sg9a1dQKrTKwt2wP6eHGBJmnnEN","0201192c11fdba5f77dbee8af32f2fe038981ae4ac93a360fd698cd9f5a0def3e1","L291freeUv6GGXDD23UkvuviTTiKsdgHZ5ViNVYMFTHQZoSiykYt"],
					["m/44'/0'/0'/0/1","1PU2yxbUuxs2Va8jcnE2jhu2N6pvZXHuEU","03fff7a05dda6e6b688dab2d534cc1f46cad271331dc67827cb0bf12007a64dd6e","L41ihSongCBiD9YCeKXWUidSmKPqGHEdhaHktsWHG6j1SFn46kWr"]]
		self.assertEqual(addresses, test_data)

		# But when you turn on it, 
		#	library will warn you that database could not find a relative version bytes
		bip49 = serialize(path="m/49'/0'/0'/0", entropy=entropy,
							cointype = "bitcoins", extend_key = True)
		addresses_49 = bip49.generate(2).raw # or bip44.generate(4).to_json
		test_data = OrderedDict([
			('Entropy', 'b3d45565178cbc13b91a52db39ff5ef6b2d9b464ee6c250c84bb1b63459970a4'),
			('Mnemonic', 'record pencil flock congress slim antenna tongue engage swamp soup stumble uniform collect surface neck snow celery goddess conduct cycle crowd smile secret panel'),
			('Seed', 'b0c32baffae7dc92b61706424ca70077f0b5252f1c75d37eeb3f783caec3bcb45a61f42cd2262398ea97bdf58be668d00266492ac4dddece59112928205970b6'),
			('BIP32 Root Key',
				('Can not compute extended key because database lack of version bytes',
				'Can not compute extended key because database lack of version bytes')),
			('Cointype', 'bitcoins'),
			('Purpose', '49'),
			('Coin', '0'),
			('Account', '0'),
			('External/Internal', '0'),
			('Account Extended Private Key', 'Can not compute extended key because database lack of version bytes'),
			('Account Extended Public Key', 'Can not compute extended key because database lack of version bytes'), 
			('BIP32 Derivation Path', "m/49'/0'/0'/0"), 
			('BIP32 Extended Pri/Pub Key', 
				('Can not compute extended key because database lack of version bytes', 
				 'Can not compute extended key because database lack of version bytes')), 
			('Derived Addresses', 
				[["m/49'/0'/0'/0/0", '34TcDG5AHzjouvzSYJPrJeGC2joeBjz3PW', '02341f91a84af51fd7a4a519294dea4484b5c093102f9ba0ad0c4f6ae923af0ff6', 'L3bnBv6MH4CroAvsQfJMhjXm4yVNRHCRmJn596TwtNNjax7k5mqr'], 
				["m/49'/0'/0'/0/1", '3LK9ZUpNXYXvd2GBa5CRz5cUNGybD2j9gh', '03ffc10361d68e04e058a23c569ac768c8112070466119a32bca096304da91b0ac', 'KwK5DK8BxpUP8EjWxTHvLDRV8croVy7ELtMEnGQBTvLSyarxUZvq']])])

		self.assertEqual(addresses_49, test_data)
	
	def test_using_bip__with_custom_version_bytes(self):

		bip44 = serialize(path="m/44'/0'/0'/0", entropy=entropy,
							cointype = ("0488b21e", "0488ade4"), extend_key = True).generate(4)

		self.assertEqual(bip44.raw, OrderedDict([
			('Entropy', 'b3d45565178cbc13b91a52db39ff5ef6b2d9b464ee6c250c84bb1b63459970a4'), 
			('Mnemonic', 'record pencil flock congress slim antenna tongue engage swamp soup stumble uniform collect surface neck snow celery goddess conduct cycle crowd smile secret panel'), 
			('Seed', 'b0c32baffae7dc92b61706424ca70077f0b5252f1c75d37eeb3f783caec3bcb45a61f42cd2262398ea97bdf58be668d00266492ac4dddece59112928205970b6'), 
			('BIP32 Root Key', 
				('xpub661MyMwAqRbcFXNLA4axKQTRBG4oBxsLKVCKM7bNc2fgvFMjYTEknFYQtwrDiGMB5gvHdCuvrqBEGcQ3Zuvd6eYx3cFgbnUw3HmPZzAyvRk', 
				 'xprv9s21ZrQH143K33Hs433wxGWgdEEJnW9UxGGiYjBm3h8i3T2azuvWETDw3pVmfaYvp34oJxZ6zT73iFJUwMsRkyGSaC3fUBs4tmCfa1cW62g')), 
			('Cointype', 'Custom cointype'), 
			('Purpose', '44'), 
			('Coin', '0'), 
			('Account', '0'), 
			('External/Internal', '0'), 
			('Account Extended Private Key', 
				'xpub6CUZvce9CMPYuhuDd4HFbDeEYQZSq72WcKMpQFc8tEobD9Zv93Mh1QzwvfZ6YRvVuav6B27VfyT4Sj4Q1G1Zbn8dtmNYGtAdngKYWG9TE9S'), 
			('Account Extended Public Key', 
				'xprv9yVDX77FMyqFhDpkX2kFE5hVzNixReJfF6SDbsCXKuGcLMEmbW3STcgU5ZZsUz4oxKXFmCFeVDFgaZ1zqgXAkaW37KivAFyXR4azWn6QKDY'), 
			('BIP32 Derivation Path', "m/44'/0'/0'/0"), 
			('BIP32 Extended Pri/Pub Key', 
				('xpub6FEobGTSLvSZoHiCUrd2oBPD8Q29e7fdjTDSa1UPstZRv9cbupSR8aQk1XuKcQtst9gQHZUTBqvkBTqrAqzg4Eg7v8X4iUWwm69GNuccJv2', 
				 'xprvA2FTBkvYWYtGaodjNq62S3SUaNBfEewnNEHqmd4nKZ2T3MHTNH8Aan6GARAgABoGD46kd8yvxrWRyekRumNGsreRVVctezMKouRBmaBoCSb')), 
			('Derived Addresses', [
				["m/44'/0'/0'/0/0", '1C8ms58sg9a1dQKrTKwt2wP6eHGBJmnnEN', '0201192c11fdba5f77dbee8af32f2fe038981ae4ac93a360fd698cd9f5a0def3e1', 'L291freeUv6GGXDD23UkvuviTTiKsdgHZ5ViNVYMFTHQZoSiykYt'], 
				["m/44'/0'/0'/0/1", '1PU2yxbUuxs2Va8jcnE2jhu2N6pvZXHuEU', '03fff7a05dda6e6b688dab2d534cc1f46cad271331dc67827cb0bf12007a64dd6e', 'L41ihSongCBiD9YCeKXWUidSmKPqGHEdhaHktsWHG6j1SFn46kWr'], 
				["m/44'/0'/0'/0/2", '15Qry7hqCjqpaJ3pEoSnmFmhP3KhHwbthR', '0219b78a84b266c70e8dcd060db655f36f3ea4f442b59158ee09bc7847e41a2135', 'Kxef5HZq9TUxW3PmHtHRe5XB7khqeTN4MC9NWsCMUNeZ7wCB1AmR'], 
				["m/44'/0'/0'/0/3", '1MBgfJ2YHcaTk1WbuMgJzBYfJHDiK7grP3', '038ef95d20f507d083b00bec9aa0f595046f1019dd0c1fa5e3e69b5b2eda78657d', 'KzdEGEWcWQkLb5RSsAMiopdKgcSTBP1bzp2Fdr9kERjryNxcGWxZ']])]))

	
	def test_custom_address_type(self):
		# In custom module, extended key never show
		# Besides, library will not check if you are using correct address type.
		# So you will not see any warnings, even you are using P2SH, P2WSH to single public key.
		custom = serialize(path="m/2'/0", entropy=entropy,
							custom_addr_type = P2WPKH).generate(4)
		test_data = [["m/2'/0/0", 'bc1qfpul4zxrc7z35ztxmkycr3298qspsqcg5zddls', '0294e050ca9ad7cee27b87729d2a85336c72782164385b2e03a5d82925328679c2', 'KzP7tCafv8xM1RFbnVAjAf14mGj9jBspYFqZ7Bp8Q7JbZyEnG7mG'], 
		["m/2'/0/1", 'bc1qcdfwngf7fczfty67dgsx4c2ghl8uqg74ss5xg3', '033588fa3711f45835c778d46f8b09f6875ecfa64b42d619eb1eeb77e7901da004', 'L44zErFTKZZRCpqPEBYF9XiMzLNXGKeazFd987tEBtbETjmagjVu'], 
		["m/2'/0/2", 'bc1q2v6jakyjzjgtsgdy5rgvyzm4qv0megczrl3nzp', '02099e466251b155cd0533c16ac088c157f61305af8188969a419d125509250cdb', 'KxzmGnjeJYVp4T2XKJTGVcpnN1yCvhUmoZEjWKdm8f41f1KKTaaN'], 
		["m/2'/0/3", 'bc1qp7wqm426kl459va84nkh4hu9hterdnf6s0fpgp', '02cd2a29e800284cdd7140dca08a43d836a389258a5f9f0afc44cb1c2281051f25', 'KyiNkDDErcpm13pQTQAXwmJdwsFxkNPEVWLjjcuJCTFwKPsg3A5q']]
		self.assertEqual(custom, test_data)

		custom2 = serialize(path="m/2/0", entropy=entropy,
							custom_addr_type = P2WSH).generate(4)
		test_data = [['m/2/0/0', 'bc1qc7f4w39cy6t4fugc9rycjp5y79cshz3c6rqjt88682tszg0jjs2semzrdg', '0243492671025defce6365634a19bc65cc58a029d39d3a381b4fb5126c4472383e', 'L1xqHqoeNSTcWH5Xt4X4kJoU7TzkWb1Le6AqRTP9ndfLKZng3sph'], 
		['m/2/0/1', 'bc1qcgxurvph5srfu399lym553k5kvyqryfz38g3snd8r6grrlm5j8dq4jkyje', '024c68e33d65ffe72e25a3a83c9894b92a48292f109104fc9dad65dde9ee61d9f5', 'Kwzf6gLgWw39cSoAchnkurac58nWxFKDNPhEKsciuriwkB8gef6d'], 
		['m/2/0/2', 'bc1q6q80unxc76qnatvredfkjhxksx97lvrnte0ucc4wf6zhz8q4pnvs04g209', '036d361cb15b33df41c7dd40abb411144aff8fb5b993e23dec7fbf2a00437b5b11', 'L2nNDuL2eva55yHJRxLLzVBdppRUxzbAqh6adUDBotqhgLeAJ8qB'], 
		['m/2/0/3', 'bc1q5x5guh0zag23xm2cpgd8jms3x6hv6sk6sfk5tcyyjnar4j2vnz4qr2jcvy', '02499d21cbf997a044449f8ddb9d0cf08070227c23ecdbd0381ab57b00540b19ae', 'L5duPoCc1AVv51rbbn6Pjh4Xf3Won5E5aByzj34QFV7egaodyiTT']]
		self.assertEqual(custom2, test_data)

		custom3 = serialize(path="m/2/0", entropy=entropy,
							custom_addr_type = P2WSH).generate(4, raw = False)

		custom3 = custom3.raw.get("Derived Addresses") # custom3.Derived_Addresses
		test_data = [['m/2/0/0', 'bc1qc7f4w39cy6t4fugc9rycjp5y79cshz3c6rqjt88682tszg0jjs2semzrdg', '0243492671025defce6365634a19bc65cc58a029d39d3a381b4fb5126c4472383e', 'L1xqHqoeNSTcWH5Xt4X4kJoU7TzkWb1Le6AqRTP9ndfLKZng3sph'], 
		['m/2/0/1', 'bc1qcgxurvph5srfu399lym553k5kvyqryfz38g3snd8r6grrlm5j8dq4jkyje', '024c68e33d65ffe72e25a3a83c9894b92a48292f109104fc9dad65dde9ee61d9f5', 'Kwzf6gLgWw39cSoAchnkurac58nWxFKDNPhEKsciuriwkB8gef6d'], 
		['m/2/0/2', 'bc1q6q80unxc76qnatvredfkjhxksx97lvrnte0ucc4wf6zhz8q4pnvs04g209', '036d361cb15b33df41c7dd40abb411144aff8fb5b993e23dec7fbf2a00437b5b11', 'L2nNDuL2eva55yHJRxLLzVBdppRUxzbAqh6adUDBotqhgLeAJ8qB'], 
		['m/2/0/3', 'bc1q5x5guh0zag23xm2cpgd8jms3x6hv6sk6sfk5tcyyjnar4j2vnz4qr2jcvy', '02499d21cbf997a044449f8ddb9d0cf08070227c23ecdbd0381ab57b00540b19ae', 'L5duPoCc1AVv51rbbn6Pjh4Xf3Won5E5aByzj34QFV7egaodyiTT']]
		self.assertEqual(custom3, test_data)
	
	def test_multisig(self):
		# Only one address each times.
		custom3 = serialize(path="m/9'/0", entropy=entropy, 
							custom_addr_type = P2WSH, testnet = True)
		result = custom3.generate_multisig(mon = (15,15))
		# path, public key list, private key list, address, MoNscript(witnessscript/redeemscript), redemscript(P2SH only)
		test_data = [	"m/9'/0/0~15", 
						('034f54bb7182f4339380a98726eb216c44400f2793385020e709338926e923dcfd', 
						'023121fda1389ba760687b4a92843b00d504e1156da725bcdd79be838e430c7d96', 
						'03e450a808be7ff4bd9e795ed6c89ed1146dc4cd6a52806d3e1bde45e7d0506a96', 
						'02989fb56d429d39ccd692544c2abd32c2c5748385cf3db6f5815c9e03bfb40273', 
						'03062a90d4e1ee03da48dea59e3373f36afb5ad55ccb16fdce986ba8ca3aca6a39', 
						'03659e98a6d4f5570176371298302b3ecc01c3c8b1661cb61599cba9d7ab54d31a', 
						'02a7aceda8b6a6bc062de73562d14fd088808c7e344fe7567eb199665e379cff28', 
						'031a3b5105aa2b811eba7e7af6f1ea3bfec7a7b3993eed23fdaf629b23924f2d2b', 
						'023c8ae2d317357af16e068c1a427bccdc192eea190086c339a3d18d7b21b264de', 
						'030018f07f0c48307cf14aee0b1453a2ee12dc7045eedc91ca1540fc76ee3d0d3a', 
						'0257a658d25f9c56793236a5bafca44876fc3344823d3f08c1838dc5107c45c41d', 
						'02fe00702080abf52d02cc8d3b33354b42e3181e341d5fd26c4c195a743a11b03d', 
						'02f11aa7a0487314d1b938ea11adea4edf5097c071d32378af1f3467b3fc07fa88', 
						'0363fc5750bc67eadc8052ef55035e137af672e8a8805f88b936da552f9815862a', 
						'0343641bbb6789be70b6ad3d9f34f11090588e965134f97ece5a4dfbcc812da7c2'),
						('cSmHgUzYceu2V8ixvWKVGApDZD4QMYx56E8fuNKzpuEE8d66QGsD', 
						'cPgAnEnbFF6zxkRBTrNYRWFoRsqxusb6xDMGsMdtKniCr4rPTAL5', 
						'cTQrkHLdHmKnba9uw3iuYhx25GFYvi9f9QBa15EBfiscRmx4ZySh', 
						'cQrxy6mrkKDoGZLeMM8eH4NDmWbdQnz1AtELXB8JRxR4Wec58ADM', 
						'cPDebgod4WbzbpmfMgFXSv6eEgLiW2RC1YwDAT6RueBU7oSbPqH2', 
						'cPyHVSNvZADswxgUUcp69eLzPWn9RVfon2ZFG9CmuB4m8NHTk9R3', 
						'cUPens9VAWMEU6YxBenVNVKo767JcrHyt95NMSrswYEZQYgad142', 
						'cV62f11pznSLoHepSNqu5ZcSWPrG8SV57TuwYJAH5H6h5AxMuZNb', 
						'cQ7CjFeYHp5VTSUExae4iNKFo9BdBY6GGEEPA2RkdfWqG6oRuYJy', 
						'cUUoBh5b1ay4yF9rKxutTz2QugNCxiNiMXZFLdGpe1NeRq2fjc1i', 
						'cTBBWEKYbqwyFmtWVKw3MvScthAsHPam26YX9S4ueBZYW8r6df6V', 
						'cUCy6F3wbPLNQVZTroVmGELw5KxC9BpGhgyj6ZWtKCvrLKK4Hc2B', 
						'cQxeJcAn7TUCuJo3Nji2NFbmDtiQUoht8vGvB9RBZz7RikeThpL5', 
						'cNgxYrP3yjBXwr4pnEEfap2BRL6dV4yKsC1oS8FV7nYqrEqBA8nT', 
						'cPvx9SmDCyMqKA42buPniuvWUecfgRWpnH5sqRk9pqp8PuYxzmyY'), 
						'tb1q0zwle25cyned4ywwdnhxufqrtazy26vcat7353jj3raez002w49qdez7dz', 
						'5f21034f54bb7182f4339380a98726eb216c44400f2793385020e709338926e923dcfd21023121fda1389ba760687b4a92843b00d504e1156da725bcdd79be838e430c7d962103e450a808be7ff4bd9e795ed6c89ed1146dc4cd6a52806d3e1bde45e7d0506a962102989fb56d429d39ccd692544c2abd32c2c5748385cf3db6f5815c9e03bfb402732103062a90d4e1ee03da48dea59e3373f36afb5ad55ccb16fdce986ba8ca3aca6a392103659e98a6d4f5570176371298302b3ecc01c3c8b1661cb61599cba9d7ab54d31a2102a7aceda8b6a6bc062de73562d14fd088808c7e344fe7567eb199665e379cff2821031a3b5105aa2b811eba7e7af6f1ea3bfec7a7b3993eed23fdaf629b23924f2d2b21023c8ae2d317357af16e068c1a427bccdc192eea190086c339a3d18d7b21b264de21030018f07f0c48307cf14aee0b1453a2ee12dc7045eedc91ca1540fc76ee3d0d3a210257a658d25f9c56793236a5bafca44876fc3344823d3f08c1838dc5107c45c41d2102fe00702080abf52d02cc8d3b33354b42e3181e341d5fd26c4c195a743a11b03d2102f11aa7a0487314d1b938ea11adea4edf5097c071d32378af1f3467b3fc07fa88210363fc5750bc67eadc8052ef55035e137af672e8a8805f88b936da552f9815862a210343641bbb6789be70b6ad3d9f34f11090588e965134f97ece5a4dfbcc812da7c25fae', 
						None]
		self.assertEqual(result, test_data)

		result = custom3.generate_multisig(mon = (15,15), sf = 4)
		test_data = ["m/9'/0/4~19", 
		('03062a90d4e1ee03da48dea59e3373f36afb5ad55ccb16fdce986ba8ca3aca6a39', 
		'03659e98a6d4f5570176371298302b3ecc01c3c8b1661cb61599cba9d7ab54d31a', 
		'02a7aceda8b6a6bc062de73562d14fd088808c7e344fe7567eb199665e379cff28', 
		'031a3b5105aa2b811eba7e7af6f1ea3bfec7a7b3993eed23fdaf629b23924f2d2b', 
		'023c8ae2d317357af16e068c1a427bccdc192eea190086c339a3d18d7b21b264de', 
		'030018f07f0c48307cf14aee0b1453a2ee12dc7045eedc91ca1540fc76ee3d0d3a', 
		'0257a658d25f9c56793236a5bafca44876fc3344823d3f08c1838dc5107c45c41d', 
		'02fe00702080abf52d02cc8d3b33354b42e3181e341d5fd26c4c195a743a11b03d', 
		'02f11aa7a0487314d1b938ea11adea4edf5097c071d32378af1f3467b3fc07fa88', 
		'0363fc5750bc67eadc8052ef55035e137af672e8a8805f88b936da552f9815862a', 
		'0343641bbb6789be70b6ad3d9f34f11090588e965134f97ece5a4dfbcc812da7c2', 
		'03e7f371197cd81f044b513ac6f9df15cface526ed13a92d70b3c1a2e9e8660db7', 
		'02c2bf71e0c663fb6ad3948c138da0f2ac2441e602ac0bb7ff05411c4e89460707', 
		'03800187b7cc26213fe071492cd05aa46a4fbf76e55a0b8f8606f05ecf5a9e3ab2', 
		'02fcf379714d8e5c05ff62d82dd8fa93a174374e5ad703c5ec5ca3f4734b210db1'), 
		('cPDebgod4WbzbpmfMgFXSv6eEgLiW2RC1YwDAT6RueBU7oSbPqH2', 
		'cPyHVSNvZADswxgUUcp69eLzPWn9RVfon2ZFG9CmuB4m8NHTk9R3', 
		'cUPens9VAWMEU6YxBenVNVKo767JcrHyt95NMSrswYEZQYgad142', 
		'cV62f11pznSLoHepSNqu5ZcSWPrG8SV57TuwYJAH5H6h5AxMuZNb', 
		'cQ7CjFeYHp5VTSUExae4iNKFo9BdBY6GGEEPA2RkdfWqG6oRuYJy', 
		'cUUoBh5b1ay4yF9rKxutTz2QugNCxiNiMXZFLdGpe1NeRq2fjc1i', 
		'cTBBWEKYbqwyFmtWVKw3MvScthAsHPam26YX9S4ueBZYW8r6df6V', 
		'cUCy6F3wbPLNQVZTroVmGELw5KxC9BpGhgyj6ZWtKCvrLKK4Hc2B', 
		'cQxeJcAn7TUCuJo3Nji2NFbmDtiQUoht8vGvB9RBZz7RikeThpL5', 
		'cNgxYrP3yjBXwr4pnEEfap2BRL6dV4yKsC1oS8FV7nYqrEqBA8nT', 
		'cPvx9SmDCyMqKA42buPniuvWUecfgRWpnH5sqRk9pqp8PuYxzmyY', 
		'cNMET3AefACRWSCwutNEuzVCmqNDd3Afzbhu78kVzsFVzymTyMEe', 
		'cRR6dDEJc8PZ55iauisbYyT1L8u4HStRDjZyHpmj1nNRtRyububP', 
		'cNzeBc6iE2Pku1SB2229NQY7q8BkMMV4Sniu6UjRTKt5g3L3sjrT', 
		'cRW7HvyLLWeFjCMrxoEJPzMT3CNNFQr5vMQTqXsuMQZYaUeZ7jAh'), 
		'tb1qq7ca79qmepuha3fa7rrrjereygamxypmx0fpghmzwgup5y3a5gpqsw2wxd', 
		'5f2103062a90d4e1ee03da48dea59e3373f36afb5ad55ccb16fdce986ba8ca3aca6a392103659e98a6d4f5570176371298302b3ecc01c3c8b1661cb61599cba9d7ab54d31a2102a7aceda8b6a6bc062de73562d14fd088808c7e344fe7567eb199665e379cff2821031a3b5105aa2b811eba7e7af6f1ea3bfec7a7b3993eed23fdaf629b23924f2d2b21023c8ae2d317357af16e068c1a427bccdc192eea190086c339a3d18d7b21b264de21030018f07f0c48307cf14aee0b1453a2ee12dc7045eedc91ca1540fc76ee3d0d3a210257a658d25f9c56793236a5bafca44876fc3344823d3f08c1838dc5107c45c41d2102fe00702080abf52d02cc8d3b33354b42e3181e341d5fd26c4c195a743a11b03d2102f11aa7a0487314d1b938ea11adea4edf5097c071d32378af1f3467b3fc07fa88210363fc5750bc67eadc8052ef55035e137af672e8a8805f88b936da552f9815862a210343641bbb6789be70b6ad3d9f34f11090588e965134f97ece5a4dfbcc812da7c22103e7f371197cd81f044b513ac6f9df15cface526ed13a92d70b3c1a2e9e8660db72102c2bf71e0c663fb6ad3948c138da0f2ac2441e602ac0bb7ff05411c4e894607072103800187b7cc26213fe071492cd05aa46a4fbf76e55a0b8f8606f05ecf5a9e3ab22102fcf379714d8e5c05ff62d82dd8fa93a174374e5ad703c5ec5ca3f4734b210db163ae', 
		None]
		self.assertEqual(result, test_data)
	
	def test_to_importmulti(self):
		# sf -> start from
		bip = serialize(path="m/44'/0'/0'/0", entropy=entropy, testnet = True)
		_, importmulti = bip.to_importmulti(n = 7, sf = 2)
		test_data = '[{"scriptPubKey": {"address": "mqNaQbjGTrjNs8e1k8Cit7iZSrbYHsCfxX"}, "label": "m/44h/0h/0h/0/8", "timestamp": "now", "pubkeys": ["03ddd9f8b6a0a0179fa0affe2d7dadaafcbe63dad25e36fc02e0016a0d32c60461"], "keys": ["cUSyCyf4Kdb8JgmAP7hLyYffbkC3AY5dvNkykYbiYRRTLazHbzba"], "watchonly": false}, {"scriptPubKey": {"address": "mqNaQbjGTrjNs8e1k8Cit7iZSrbYHsCfxX"}, "label": "m/44h/0h/0h/0/8", "timestamp": "now", "pubkeys": ["03ddd9f8b6a0a0179fa0affe2d7dadaafcbe63dad25e36fc02e0016a0d32c60461"], "keys": ["cUSyCyf4Kdb8JgmAP7hLyYffbkC3AY5dvNkykYbiYRRTLazHbzba"], "watchonly": false}, {"scriptPubKey": {"address": "mqNaQbjGTrjNs8e1k8Cit7iZSrbYHsCfxX"}, "label": "m/44h/0h/0h/0/8", "timestamp": "now", "pubkeys": ["03ddd9f8b6a0a0179fa0affe2d7dadaafcbe63dad25e36fc02e0016a0d32c60461"], "keys": ["cUSyCyf4Kdb8JgmAP7hLyYffbkC3AY5dvNkykYbiYRRTLazHbzba"], "watchonly": false}, {"scriptPubKey": {"address": "mqNaQbjGTrjNs8e1k8Cit7iZSrbYHsCfxX"}, "label": "m/44h/0h/0h/0/8", "timestamp": "now", "pubkeys": ["03ddd9f8b6a0a0179fa0affe2d7dadaafcbe63dad25e36fc02e0016a0d32c60461"], "keys": ["cUSyCyf4Kdb8JgmAP7hLyYffbkC3AY5dvNkykYbiYRRTLazHbzba"], "watchonly": false}, {"scriptPubKey": {"address": "mqNaQbjGTrjNs8e1k8Cit7iZSrbYHsCfxX"}, "label": "m/44h/0h/0h/0/8", "timestamp": "now", "pubkeys": ["03ddd9f8b6a0a0179fa0affe2d7dadaafcbe63dad25e36fc02e0016a0d32c60461"], "keys": ["cUSyCyf4Kdb8JgmAP7hLyYffbkC3AY5dvNkykYbiYRRTLazHbzba"], "watchonly": false}, {"scriptPubKey": {"address": "mqNaQbjGTrjNs8e1k8Cit7iZSrbYHsCfxX"}, "label": "m/44h/0h/0h/0/8", "timestamp": "now", "pubkeys": ["03ddd9f8b6a0a0179fa0affe2d7dadaafcbe63dad25e36fc02e0016a0d32c60461"], "keys": ["cUSyCyf4Kdb8JgmAP7hLyYffbkC3AY5dvNkykYbiYRRTLazHbzba"], "watchonly": false}, {"scriptPubKey": {"address": "mqNaQbjGTrjNs8e1k8Cit7iZSrbYHsCfxX"}, "label": "m/44h/0h/0h/0/8", "timestamp": "now", "pubkeys": ["03ddd9f8b6a0a0179fa0affe2d7dadaafcbe63dad25e36fc02e0016a0d32c60461"], "keys": ["cUSyCyf4Kdb8JgmAP7hLyYffbkC3AY5dvNkykYbiYRRTLazHbzba"], "watchonly": false}]'
		self.assertEqual(importmulti, test_data)

		custom = serialize(path="m/21'/0", entropy=entropy, 
							custom_addr_type = P2WPKH, testnet = True)
		_, importmulti = custom.to_importmulti(n = 7, sf = 7)
		test_data = '[{"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}]'
		self.assertEqual(importmulti, test_data)

	def test_to_importmulti_multisig(self):
		custom = serialize(path="m/16'/0", entropy=entropy, 
							custom_addr_type = P2WSH, testnet = True)
		_, importmulti = custom.to_importmulti(mon = (15,15), sf = 4)
		test_data = '[{"scriptPubKey": {"address": "tb1qmqp8ukkem2txsy7hyd5p097ppy7nfmpe2y36acwc4sajad4gnqjqpx0e7z"}, "label": "m/16h/0/4~19", "timestamp": "now", "pubkeys": ["027b994ac9642b0346d02a17c33b74c7b378a7ebc83c0e499cfa2ad634f2223359", "039a83d1ab7351312c7e31724aac3a971d69fe3b7b7ac91ef17d13adbc91de2873", "033fba7405668e571ff2c658c56094e950992375b6cce0ab830943cd0d3ccf3d03", "02bfe22c4c496df6fc03843c93470adb86482414e458f99fae9996212987a5e055", "03d364bfc238b8ede28d19c5287e2386b0eee0e220ca26847a1a68bf4e62f611a6", "032c9a12d01f59b45176cf9e7cf373824ee36056929c2507df8f4697e155ab6da5", "0251b61395b0c75a045904634b2b991a6cc7ffbff06ba61bac141b02df4a9fda4d", "032babd5a9af5f087de74392aa1477b6b555103423e32c16a45dd5ddc7d6b0e07b", "029020549066058a50e224b1ca9d9b0f5b765298ec90d239b8f905aacbb9506086", "02b12cc28e4914dcd8ead1068c9f1c590dc9914b5bdc7ff73d9c38a50b49e7bc7f", "025a003920dd62044bd606a64ac10a1ece88dd8bef58ebd68b04f8b53b43d46f7f", "02518cc2f63c19654f9f4c8ee1274fcb8d953f1393266587fa18e4d2f3e9641cd7", "0389185061c9e9e823ead64140284425225125a8d229038903e621dd7130fd8a07", "02cb059098018c74b9073592672c7ffd90550dded7c59d0c9826e829e8157da1b8", "036d87ed88af552d050d420a1fd39c6bc44b777798ef50c92b569d29d2985ac0d2"], "keys": ["cPC2z7rJ9w2fzycECTcNvc699QNhm54XSFFu3ZtWx2x1bnF5MaBC", "cRaa9pthv1QUzBFQGYVYBBDxc73Skgvj5q4KYEcMjL7mXkFZRCsQ", "cNhMY1vL8dJCZf5aHp4wNjxpiZ5AKDYBXdYrtcvQdp6v6UojndBe", "cVyS45EKMKniHQ2bUUJ1Ay4hXURK2JUkYKWPYnmem3CnyGnK79K8", "cPv27fCNw1fKnAApx6Vm6mhNDodAg7b1oMyvweooefcfABd2jN5v", "cUs1kgaYWYxmDdFFB1itp5dEpQFSyi9pBY1FjdrbCsTf3ta9xnfd", "cPMrXuD985iPVHaJXrdMh66FFAWrmMHqNBzUxnejjNwVwNYJpMDw", "cTurem6czLQLMT6xKngUwqHUiVBAki5PRtmpDx7UT9s1N35JwPoe", "cSjNVHLEyhdNSoSS3iYrKRCN8tBvJrp6pd9Ch5T6jY2jTe1pfazw", "cSy25WpFDaFaZYRpWgjzRDCy7hErf5z1K2edWSurKGx81zgRGifG", "cUxMr4iSzGcXKr9CYz5szBACuEAp675sXPU5A5my4f3bRut8VvdD", "cNFDtEyRuSGzUQk1rMyuHU7CCgKtASoGhD1dSRVawFC5ESv4AHsp", "cV9U2ReeL7orSFm3PFr3fm4Zksp6Q3fQqqhBvrnabWFSCeAypChX", "cTTormMthffJRiPGKRizXEpLQ5yAA7yEVvaZ2LWVCW8XcVy7XQrs", "cQmXicjiUoZHU7FbQtoueSq8G9bvafpcdVTVNzQaVtDZqH9HePPu"], "watchonly": false, "witnessscript": "5f21027b994ac9642b0346d02a17c33b74c7b378a7ebc83c0e499cfa2ad634f222335921039a83d1ab7351312c7e31724aac3a971d69fe3b7b7ac91ef17d13adbc91de287321033fba7405668e571ff2c658c56094e950992375b6cce0ab830943cd0d3ccf3d032102bfe22c4c496df6fc03843c93470adb86482414e458f99fae9996212987a5e0552103d364bfc238b8ede28d19c5287e2386b0eee0e220ca26847a1a68bf4e62f611a621032c9a12d01f59b45176cf9e7cf373824ee36056929c2507df8f4697e155ab6da5210251b61395b0c75a045904634b2b991a6cc7ffbff06ba61bac141b02df4a9fda4d21032babd5a9af5f087de74392aa1477b6b555103423e32c16a45dd5ddc7d6b0e07b21029020549066058a50e224b1ca9d9b0f5b765298ec90d239b8f905aacbb95060862102b12cc28e4914dcd8ead1068c9f1c590dc9914b5bdc7ff73d9c38a50b49e7bc7f21025a003920dd62044bd606a64ac10a1ece88dd8bef58ebd68b04f8b53b43d46f7f2102518cc2f63c19654f9f4c8ee1274fcb8d953f1393266587fa18e4d2f3e9641cd7210389185061c9e9e823ead64140284425225125a8d229038903e621dd7130fd8a072102cb059098018c74b9073592672c7ffd90550dded7c59d0c9826e829e8157da1b821036d87ed88af552d050d420a1fd39c6bc44b777798ef50c92b569d29d2985ac0d263ae"}]'
		self.assertEqual(importmulti, test_data)

	def test_to_json(self):
		custom = serialize(path="m/2'/0", entropy=entropy,
							custom_addr_type = P2WPKH).generate(40, raw = False).to_json

	def test_to_csv(self):
		custom = serialize(path="m/2'/0", entropy=entropy,
							custom_addr_type = P2WPKH).generate(40, raw = False).to_csv

	def test_address(self):
		# Ignoring redeemscript as this is not a P2SH script. Means only P2SH need redeemscript
		pk = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
		p2wsh = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
		p2wpkh = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
		self.assertEqual(P2WPKH(pk).address , p2wpkh)
		self.assertEqual(P2WSH(pk).address , p2wsh)

		
		P2WSHoP2SHAddress_witnessScript = "5221021e6617e06bb90f621c3800e8c37ab081a445ae5527f6c5f68a022e7133f9b5fe2103bea1a8ce6369435bb74ff1584a136a7efeebfe4bc320b4d59113c92acd869f38210280631b27700baf7d472483fadfe1c4a7340a458f28bf6bae5d3234312d684c6553ae"
		P2WSHoP2SHAddress_ = "3CYkk3x1XUvdXCdHtRFdjMjp17PuJ8eR8z"
		self.assertEqual(P2WSHoP2SH(P2WSHoP2SHAddress_witnessScript).address , P2WSHoP2SHAddress_)
		
		# need a standard data, 51..51ae might be changed now, i think
		redeemScript_single = "5141042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf51ae"
		single_P2SH_address = "3P14159f73E4gFr7JterCCQh9QjiTjiZrG"

		redeemScript_mon = "522102194e1b5671daff4edc82ce01589e7179a874f63d6e5157fa0def116acd2c3a522103a043861e123bc67ddcfcd887b167e7ff9d00702d1466524157cf3b28c7aca71b2102a49a62a9470a31ee51824f0ee859b0534a4f555c0e2d7a9d9915d6986bfc200453ae"
		mon_P2SH_address = "3JUJgXbB1WpDEJprE8wP8vEXtba36dAYbk"
		self.assertEqual(P2SH(redeemScript_single).address , single_P2SH_address)
		self.assertEqual(P2SH(redeemScript_mon).address , mon_P2SH_address)
		
		publickeylist = ["021e6617e06bb90f621c3800e8c37ab081a445ae5527f6c5f68a022e7133f9b5fe", "03bea1a8ce6369435bb74ff1584a136a7efeebfe4bc320b4d59113c92acd869f38", "0280631b27700baf7d472483fadfe1c4a7340a458f28bf6bae5d3234312d684c65"]
		self.assertEqual(MoNscript(2,3,publickeylist) , "5221021e6617e06bb90f621c3800e8c37ab081a445ae5527f6c5f68a022e7133f9b5fe2103bea1a8ce6369435bb74ff1584a136a7efeebfe4bc320b4d59113c92acd869f38210280631b27700baf7d472483fadfe1c4a7340a458f28bf6bae5d3234312d684c6553ae")

		pk = "02fa84946ba062ea6cadf77561ca8859ef1de8edf6dd0bf91f516b770c84135b60"
		self.assertEqual(P2PKH(pk).address , "1DksSA9vNRbpG6etkDoWkqVHBfj8HmtyL9")

		
		# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Native_P2WPKH
		key = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
		self.assertEqual(P2WPKH(key).scriptpubkey , "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1") # ScriptPubKey 

		# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
		key = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
		clss = P2WPKHoP2SH(key)
		redeemscript, ScriptPubKey = clss.redeemscript, clss.scriptpubkey
		self.assertEqual(redeemscript , "001479091972186c449eb1ded22b78e40d009bdf0089")
		self.assertEqual(ScriptPubKey , "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387")
		
		key = "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
		self.assertEqual(P2WSH(key).scriptpubkey , "00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0")
		
		key = "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"
		clss = P2WSHoP2SH(key)
		redeemScript, ScriptPubKey = clss.redeemscript, clss.scriptpubkey
		self.assertEqual(redeemScript , "0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54")
		self.assertEqual(ScriptPubKey , "a9149993a429037b5d912407a71c252019287b8d27a587")

		key = "039e84846f40570adc5cef6904e10d9f5a5dadb9f2afd07cc9aad188d769c50b46"
		self.assertEqual(P2PKH(key).scriptpubkey , "76a914d259038d23c4a8f9dd4eaaf92316d191f18d963788ac")

		
		self.assertEqual(P2WPKHoP2SH("39wSTzCS9BiwF3Vci1tGXwyDXa1LReG9Jc").scriptpubkey , "a9145a7b51041e3f0959db7783c097f278dd139ce43687")
		self.assertEqual(P2WSHoP2SH("3JXRVxhrk2o9f4w3cQchBLwUeegJBj6BEp").scriptpubkey  , "a914b8a9a8ba8cf965b7df6b05afd948e53c351b2c0d87")
		# self.assertEqual(P2SH() They base on P2SH function, so pass
		self.assertEqual(P2PKH("1LBDY5Sugh4i2XS6StMKA1ZZiyN4a59Sdf").scriptpubkey , "76a914d259038d23c4a8f9dd4eaaf92316d191f18d963788ac")
		
		
		self.assertEqual(P2WPKH("tb1qm3e067l5aadlmr07qg05rudd05m3vmw2606rzj").scriptpubkey , "0014dc72fd7bf4ef5bfd8dfe021f41f1ad7d37166dca")
		
		# Data from 9988eaabbcf5976d13f91c28604f921239ed3fadf4592d1a0a0e288b419a78a4
		key = "5221035c8e83fa4ca1d74d10f122daaac69b006e5c02a1594b78907881190500b1f22a2102c1235301c06e94bdd44c248e6c824b58fafea3ceee4db2857402e322486046842103e46359fd20b25a7be466984f156084be0dead32e4e99cec2e0f7c9ad4863daaa53ae"
		self.assertEqual(P2WSH(key).scriptpubkey , "0020d3124de88d90949cf90ed655bfd306f00d9473387eedc59d819d51bc6880f29d")
		self.assertEqual(P2WSH("bc1qm2pz5342a0n3ctv9hm6s568zeye8cw7j90j0nmjdwkrcy78qs2nsfyp945").scriptpubkey , "0020da822a46aaebe71c2d85bef50a68e2c9327c3bd22be4f9ee4d75878278e082a7")


if __name__ == '__main__':

	unittest.main()