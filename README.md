# Importaddress

[![Build Status](https://travis-ci.org/kcorlidy/importaddress.svg?branch=master)](https://travis-ci.org/kcorlidy/importaddress) [![codecov](https://codecov.io/gh/kcorlidy/importaddress/branch/master/graph/badge.svg)](https://codecov.io/gh/kcorlidy/importaddress)[![codebeat badge](https://codebeat.co/badges/8295fb11-479e-4d5f-9ed4-e0999dd531a6)](https://codebeat.co/projects/github-com-kcorlidy-importaddress-master)

[TOC]

## Key Features

- Supported all type of addresses
- Supported all type of ScriptPubKey
- Supported bip44, bip49, bip84
- Create `importmulti` parameter
- Save data to `Json` or `CSV`

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
'tb1q0zwle25cyned4ywwdnhxufqrtazy26vcat7353jj3raez002w49qdez7dz',
'5f21034f54bb7182f4339380a98726eb216c44400f2793385020e709338926e923dcfd21023121fda1389ba760687b4a92843b00d504e1156da725bcdd79be838e430c7d962103e450a808be7ff4bd9e795ed6c89ed1146dc4cd6a52806d3e1bde45e7d0506a962102989fb56d429d39ccd692544c2abd32c2c5748385cf3db6f5815c9e03bfb402732103062a90d4e1ee03da48dea59e3373f36afb5ad55ccb16fdce986ba8ca3aca6a392103659e98a6d4f5570176371298302b3ecc01c3c8b1661cb61599cba9d7ab54d31a2102a7aceda8b6a6bc062de73562d14fd088808c7e344fe7567eb199665e379cff2821031a3b5105aa2b811eba7e7af6f1ea3bfec7a7b3993eed23fdaf629b23924f2d2b21023c8ae2d317357af16e068c1a427bccdc192eea190086c339a3d18d7b21b264de21030018f07f0c48307cf14aee0b1453a2ee12dc7045eedc91ca1540fc76ee3d0d3a210257a658d25f9c56793236a5bafca44876fc3344823d3f08c1838dc5107c45c41d2102fe00702080abf52d02cc8d3b33354b42e3181e341d5fd26c4c195a743a11b03d2102f11aa7a0487314d1b938ea11adea4edf5097c071d32378af1f3467b3fc07fa88210363fc5750bc67eadc8052ef55035e137af672e8a8805f88b936da552f9815862a210343641bbb6789be70b6ad3d9f34f11090588e965134f97ece5a4dfbcc812da7c25fae', 
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

Default filename is the entropy. You can apply a new filename through parameter `filename`.
`to_json(filename = "abc")`

### Json

```python
from importaddress.address import P2WPKH
from importaddress.hdprotocol import serialize

custom = serialize(path="m/2'/0", entropy=entropy, custom_addr_type = P2WPKH).generate(40, raw = False).to_json()
```



### CSV

```python
from importaddress.address import P2WPKH
from importaddress.hdprotocol import serialize

custom = serialize(path="m/2'/0", entropy=entropy, custom_addr_type = P2WPKH).generate(40, raw = False).to_csv()
```



## Special usage

### Create `importmulti`'s parameter - useful to bitcoin-core

```python
from importaddress.address import P2WPKH, P2WSH
from importaddress.hdprotocol import serialize

# `to_importmulti` wil return raw data and serialize data
custom = serialize(path="m/16'/0", entropy=entropy, custom_addr_type = P2WSH, testnet = True)
_, importmulti = custom.to_importmulti(mon = (15,15), sf = 4)
'''
'[{"scriptPubKey": {"address": "tb1qmqp8ukkem2txsy7hyd5p097ppy7nfmpe2y36acwc4sajad4gnqjqpx0e7z"}, "label": "m/16h/0/4~19", "timestamp": "now", "pubkeys": ["027b994ac9642b0346d02a17c33b74c7b378a7ebc83c0e499cfa2ad634f2223359", "039a83d1ab7351312c7e31724aac3a971d69fe3b7b7ac91ef17d13adbc91de2873", "033fba7405668e571ff2c658c56094e950992375b6cce0ab830943cd0d3ccf3d03", "02bfe22c4c496df6fc03843c93470adb86482414e458f99fae9996212987a5e055", "03d364bfc238b8ede28d19c5287e2386b0eee0e220ca26847a1a68bf4e62f611a6", "032c9a12d01f59b45176cf9e7cf373824ee36056929c2507df8f4697e155ab6da5", "0251b61395b0c75a045904634b2b991a6cc7ffbff06ba61bac141b02df4a9fda4d", "032babd5a9af5f087de74392aa1477b6b555103423e32c16a45dd5ddc7d6b0e07b", "029020549066058a50e224b1ca9d9b0f5b765298ec90d239b8f905aacbb9506086", "02b12cc28e4914dcd8ead1068c9f1c590dc9914b5bdc7ff73d9c38a50b49e7bc7f", "025a003920dd62044bd606a64ac10a1ece88dd8bef58ebd68b04f8b53b43d46f7f", "02518cc2f63c19654f9f4c8ee1274fcb8d953f1393266587fa18e4d2f3e9641cd7", "0389185061c9e9e823ead64140284425225125a8d229038903e621dd7130fd8a07", "02cb059098018c74b9073592672c7ffd90550dded7c59d0c9826e829e8157da1b8", "036d87ed88af552d050d420a1fd39c6bc44b777798ef50c92b569d29d2985ac0d2"], "keys": ["cPC2z7rJ9w2fzycECTcNvc699QNhm54XSFFu3ZtWx2x1bnF5MaBC", "cRaa9pthv1QUzBFQGYVYBBDxc73Skgvj5q4KYEcMjL7mXkFZRCsQ", "cNhMY1vL8dJCZf5aHp4wNjxpiZ5AKDYBXdYrtcvQdp6v6UojndBe", "cVyS45EKMKniHQ2bUUJ1Ay4hXURK2JUkYKWPYnmem3CnyGnK79K8", "cPv27fCNw1fKnAApx6Vm6mhNDodAg7b1oMyvweooefcfABd2jN5v", "cUs1kgaYWYxmDdFFB1itp5dEpQFSyi9pBY1FjdrbCsTf3ta9xnfd", "cPMrXuD985iPVHaJXrdMh66FFAWrmMHqNBzUxnejjNwVwNYJpMDw", "cTurem6czLQLMT6xKngUwqHUiVBAki5PRtmpDx7UT9s1N35JwPoe", "cSjNVHLEyhdNSoSS3iYrKRCN8tBvJrp6pd9Ch5T6jY2jTe1pfazw", "cSy25WpFDaFaZYRpWgjzRDCy7hErf5z1K2edWSurKGx81zgRGifG", "cUxMr4iSzGcXKr9CYz5szBACuEAp675sXPU5A5my4f3bRut8VvdD", "cNFDtEyRuSGzUQk1rMyuHU7CCgKtASoGhD1dSRVawFC5ESv4AHsp", "cV9U2ReeL7orSFm3PFr3fm4Zksp6Q3fQqqhBvrnabWFSCeAypChX", "cTTormMthffJRiPGKRizXEpLQ5yAA7yEVvaZ2LWVCW8XcVy7XQrs", "cQmXicjiUoZHU7FbQtoueSq8G9bvafpcdVTVNzQaVtDZqH9HePPu"], "watchonly": false, "witnessscript": "5f21027b994ac9642b0346d02a17c33b74c7b378a7ebc83c0e499cfa2ad634f222335921039a83d1ab7351312c7e31724aac3a971d69fe3b7b7ac91ef17d13adbc91de287321033fba7405668e571ff2c658c56094e950992375b6cce0ab830943cd0d3ccf3d032102bfe22c4c496df6fc03843c93470adb86482414e458f99fae9996212987a5e0552103d364bfc238b8ede28d19c5287e2386b0eee0e220ca26847a1a68bf4e62f611a621032c9a12d01f59b45176cf9e7cf373824ee36056929c2507df8f4697e155ab6da5210251b61395b0c75a045904634b2b991a6cc7ffbff06ba61bac141b02df4a9fda4d21032babd5a9af5f087de74392aa1477b6b555103423e32c16a45dd5ddc7d6b0e07b21029020549066058a50e224b1ca9d9b0f5b765298ec90d239b8f905aacbb95060862102b12cc28e4914dcd8ead1068c9f1c590dc9914b5bdc7ff73d9c38a50b49e7bc7f21025a003920dd62044bd606a64ac10a1ece88dd8bef58ebd68b04f8b53b43d46f7f2102518cc2f63c19654f9f4c8ee1274fcb8d953f1393266587fa18e4d2f3e9641cd7210389185061c9e9e823ead64140284425225125a8d229038903e621dd7130fd8a072102cb059098018c74b9073592672c7ffd90550dded7c59d0c9826e829e8157da1b821036d87ed88af552d050d420a1fd39c6bc44b777798ef50c92b569d29d2985ac0d263ae"}]'
'''

# Be careful, all of data will pack in one list
custom = serialize(path="m/21'/0", entropy=entropy, custom_addr_type = P2WPKH, testnet = True)
_, importmulti = custom.to_importmulti(n = 7, sf = 7)
'''
[{"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}, {"scriptPubKey": {"address": "tb1qck6tpllsvfj8hlrma7hj9mv3lpqu5h3e5n60pe"}, "label": "m/21h/0/13", "timestamp": "now", "pubkeys": ["02549bf4d0d609fab694a761adb287a987b93f6663ac3bbbbc376413d38bc1fbdd"], "keys": ["cVJsr7ays1w87Yus7PTZwXE5pgjdAY85UtmTRhCsrBLJPH1g7HFp"], "watchonly": false}]'
'''
```

## Use them to create something new!

### `importaddress.func`

### `importaddress.address` 

## Requirements

- python-mnemonic
- ecdsa