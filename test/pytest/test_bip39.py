import pytest
from importaddress.hdprotocol import bip39
from importaddress.func import hexlify, hybridmethod

lang = "english"
passphrase = ""


def test_entropy2Mnemonic_onfunc(entropy, words):
	_words = bip39.to_mnemonic(entropy=entropy, lang=lang)
	assert _words == words

def test_entropy2seed_onfunc(entropy, seed):
	words = bip39.to_mnemonic(entropy=entropy, lang=lang)
	_seed = bip39.to_seed(words, passphrase)
	assert _seed == seed

def test_Mnemonic2seed_onfunc(words, seed):
	_seed = bip39.to_seed(words=words, passphrase=passphrase)
	assert _seed == seed

def test_entropy2Mnemonic_onclass(entropy, words):
	_words = bip39(entropy=entropy).to_mnemonic(lang=lang)
	assert _words == words

def test_entropy2seed_onclass(entropy, seed):
	words = bip39(entropy=entropy).to_mnemonic(lang=lang)
	_seed = bip39(words=words).to_seed(passphrase=passphrase)
	assert _seed == seed

def test_Mnemonic2seed_onclass(words, seed):
	_seed = bip39(words=words).to_seed(passphrase=passphrase)
	assert _seed == seed
