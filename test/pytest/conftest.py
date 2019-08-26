import pytest
import time
import os.path
from importaddress.hdprotocol import bip39

_words = "record pencil flock congress slim antenna tongue engage swamp soup stumble uniform collect surface neck snow celery goddess conduct cycle crowd smile secret panel"
_entropy = "b3d45565178cbc13b91a52db39ff5ef6b2d9b464ee6c250c84bb1b63459970a4"
_seed = "b0c32baffae7dc92b61706424ca70077f0b5252f1c75d37eeb3f783caec3bcb45a61f42cd2262398ea97bdf58be668d00266492ac4dddece59112928205970b6"
_extendedkey = "xprv9s21ZrQH143K33Hs433wxGWgdEEJnW9UxGGiYjBm3h8i3T2azuvWETDw3khwd6CafxUHiko1C5RmfArFgFS5LnxnXbwJkTft7Rt9ozKMJoX"
_extendedkey_publickey = "xpub661MyMwAqRbcFXNLA4axKQTRBG4oBxsLKVCKM7bNc2fgvFMjYTEknFYQu1e3kkhXDmWoDQg2fCrWKgrGq2MyWprc6CN3KWg7pd5uL2i4JHv"
_extendedkey_testnet = "tprv8ZgxMBicQKsPdrXPibuT7v8fwMeX22BVHpBqR9cDXfdBq3mfzHGFkCbNxvsbdTau3Q14irQmMS1a82PzoTn29rEP4F9cQpPw2XdaFe8TVxZ"

def pytest_addoption(parser):
	parser.addoption(
		"--words", action="store", default=_words, help="Mnemonic for BIP39"
	)
	parser.addoption(
		"--entropy", action="store", default=_entropy, help="Entropy for BIP39"
	)
	parser.addoption(
		"--seed", action="store", default=_seed, help="Seed for BIP32"
	)
	parser.addoption(
		"--extendedkey", action="store", default=_extendedkey, help="ExtendedKey for BIP32"
	)
	parser.addoption(
		"--extendedkey_publickey", action="store", default=_extendedkey_publickey, help="ExtendedKey-Public key for BIP32"
	)

def pytest_report_header(config):
	if config.getoption("verbose") > 0:
		return ["project deps: importaddress", "project author: kcorlidy Chan"]

@pytest.fixture(scope="module")
def words(request):
	return request.config.getoption("--words")

@pytest.fixture(scope="module")
def entropy(request):
	return request.config.getoption("--entropy")

@pytest.fixture(autouse=True)
def seed(request):
	return bytes.fromhex(request.config.getoption("--seed"))

@pytest.fixture(scope="module")
def extendedkey(request):
	return request.config.getoption("--extendedkey")

@pytest.fixture(scope="module")
def extendedkey_publickey(request):
	return request.config.getoption("--extendedkey_publickey")

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
	# execute all other hooks to obtain the report object
	outcome = yield
	rep = outcome.get_result()

	# we only look at actual failing test calls, not setup/teardown
	if rep.failed:
		mode = "a" if os.path.exists("failures") else "w"
		with open("failures", mode) as f:
			# let's also access a fixture for the fun of it
			if "tmpdir" in item.fixturenames:
				extra = " ({})".format(item.funcargs["tmpdir"])
			else:
				extra = ""
			
			f.write(time.ctime() + " " + ":".join([str(data) for data in rep.location]) + extra + "\n")