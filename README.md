# Importaddress

[![Build Status](https://travis-ci.org/kcorlidy/importaddress.svg?branch=master)](https://travis-ci.org/kcorlidy/importaddress) [![codecov](https://codecov.io/gh/kcorlidy/importaddress/branch/master/graph/badge.svg)](https://codecov.io/gh/kcorlidy/importaddress)

## Key Features

- we
- can
- create

## Getting started

The data we use

```python
words = "record pencil flock congress slim antenna tongue engage swamp soup stumble uniform collect surface neck snow celery goddess conduct cycle crowd smile secret panel"
entropy = "b3d45565178cbc13b91a52db39ff5ef6b2d9b464ee6c250c84bb1b63459970a4"
seed = "b0c32baffae7dc92b61706424ca70077f0b5252f1c75d37eeb3f783caec3bcb45a61f42cd2262398ea97bdf58be668d00266492ac4dddece59112928205970b6"
```

### Using bip44, bip49, bip84

```python
from importaddress.hdprotocol import serialize

bip44 = serialize(path="m/44'/0'/0'/0", entropy=entropy).generate(5)
bip49 = serialize(path="m/49'/0'/0'/0", entropy=entropy).generate(5)
bip84 = serialize(path="m/84'/0'/0'/0", entropy=entropy).generate(5)
'''
[["m/44'/0'/0'/0/0","1C8ms58sg9a1dQKrTKwt2wP6eHGBJmnnEN","0201192c11fdba5f77dbee8af32f2fe038981ae4ac93a360fd698cd9f5a0def3e1","L291freeUv6GGXDD23UkvuviTTiKsdgHZ5ViNVYMFTHQZoSiykYt"],...]
[["m/49'/0'/0'/0/0","34TcDG5AHzjouvzSYJPrJeGC2joeBjz3PW","02341f91a84af51fd7a4a519294dea4484b5c093102f9ba0ad0c4f6ae923af0ff6","L3bnBv6MH4CroAvsQfJMhjXm4yVNRHCRmJn596TwtNNjax7k5mqr"],...]
[["m/84'/0'/0'/0/0","bc1qh0m35vfdzvle56rk86j3pstfgwlhlvv47dp3kg","0208adb0e2f515f4831ae1e7d737e006b6a9e03893d7d70bed06ee735a004861c7","KwzvYh3pt5Xkju4LHMWPkLSJoGHRCpCDjDmcsMTLKHEtpb5w9A31"],...]
'''
```

### Using bip44, bip49, bip84 with other cointype

```python
from importaddress.hdprotocol import serialize
# bitcoin-testnet
bip44 = serialize(path="m/44'/1'/0'/0", entropy=entropy, testnet = True).generate(5)
bip49 = serialize(path="m/49'/1'/0'/0", entropy=entropy, testnet = True).generate(5)
bip84 = serialize(path="m/84'/1'/0'/0", entropy=entropy, testnet = True).generate(5)

# litecoin 
bip44 = serialize(path="m/44'/2'/0'/0", entropy=entropy).generate(5)
bip49 = serialize(path="m/49'/2'/0'/0", entropy=entropy).generate(5)
bip84 = serialize(path="m/84'/2'/0'/0", entropy=entropy).generate(5)
```



### Generate address with custom path and address type

```python
# P2WPKH, Notice dont use m/44', m/49', m/84' as main path
from importaddress.address import P2WPKH
from importaddress.hdprotocol import serialize

custom = serialize(path="m/2'/0", entropy=entropy, custom_addr_type = P2WPKH).generate(4)
'''
[["m/2'/0/0", 'bc1qfpul4zxrc7z35ztxmkycr3298qspsqcg5zddls', '0294e050ca9ad7cee27b87729d2a85336c72782164385b2e03a5d82925328679c2', 'KzP7tCafv8xM1RFbnVAjAf14mGj9jBspYFqZ7Bp8Q7JbZyEnG7mG'],...]
'''
```



### Generate multisig address

```python
from importaddress.address import P2WSH
from importaddress.hdprotocol import serialize

custom3 = serialize(path="m/9'/0", entropy=entropy, custom_addr_type = P2WSH, testnet = True)
result = custom3.generate_multisig(mon = (15,15))
# path, public key list, private key list, address, MoNscript, redemscript(P2SH only)
'''
test_data = [
"m/9'/0/0~15", 
('034f54bb7182f4339380a98726eb216c44400f2793385020e709338926e923dcfd', ...),
('cSmHgUzYceu2V8ixvWKVGApDZD4QMYx56E8fuNKzpuEE8d66QGsD',...)
'tb1q0zwle25cyned4ywwdnhxufqrtazy26vcat7353jj3raez002w49qdez7dz', 			'5f21034f54bb7182f4339380a98726eb216c44400f2793385020e709338926e923dcfd21023121fda1389ba760687b4a92843b00d504e1156da725bcdd79be838e430c7d962103e450a808be7ff4bd9e795ed6c89ed1146dc4cd6a52806d3e1bde45e7d0506a962102989fb56d429d39ccd692544c2abd32c2c5748385cf3db6f5815c9e03bfb402732103062a90d4e1ee03da48dea59e3373f36afb5ad55ccb16fdce986ba8ca3aca6a392103659e98a6d4f5570176371298302b3ecc01c3c8b1661cb61599cba9d7ab54d31a2102a7aceda8b6a6bc062de73562d14fd088808c7e344fe7567eb199665e379cff2821031a3b5105aa2b811eba7e7af6f1ea3bfec7a7b3993eed23fdaf629b23924f2d2b21023c8ae2d317357af16e068c1a427bccdc192eea190086c339a3d18d7b21b264de21030018f07f0c48307cf14aee0b1453a2ee12dc7045eedc91ca1540fc76ee3d0d3a210257a658d25f9c56793236a5bafca44876fc3344823d3f08c1838dc5107c45c41d2102fe00702080abf52d02cc8d3b33354b42e3181e341d5fd26c4c195a743a11b03d2102f11aa7a0487314d1b938ea11adea4edf5097c071d32378af1f3467b3fc07fa88210363fc5750bc67eadc8052ef55035e137af672e8a8805f88b936da552f9815862a210343641bbb6789be70b6ad3d9f34f11090588e965134f97ece5a4dfbcc812da7c25fae', 
None] 
'''
```



### Generate address with specified start position

```python
from importaddress.address import P2WSH
from importaddress.hdprotocol import serialize

bip = serialize(path="m/44'/0'/0'/0", entropy=entropy, testnet = True).generate(5, sf=2) # sf means `start from`
multisig = serialize(path="m/9'/0", entropy=entropy, custom_addr_type = P2WSH, testnet = True).generate_multisig(mon = (15,15), sf = 4)
```

## Save to file

### Json

```

```



### CSV

```

```



## Special usage

### Create `importmulti`'s parameter - useful to bitcoin-core

```

```

## Use them to create something new!

### `importaddress.func`

### `importaddress.address` 

## Requirements

- python-mnemonic
- ecdsa