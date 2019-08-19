from binascii import hexlify as _hexlify
from hashlib import sha256, new
from . import segwit_addr
from . import Base58
import sys


check_decode = Base58.check_decode
check_encode = Base58.check_encode
bech32_decode = segwit_addr.decode
bech32_encode = segwit_addr.encode
ripemd160 = lambda x: new('ripemd160', x)
_hex = lambda x: hex(int(x))[2:]
hexlify = lambda x: _hexlify(x).decode() if sys.version > "3" else _hexlify(x)
dsha256 = lambda x: sha256(sha256().digest(x)).digest()


def MoNscript(m, n, publickeylist):
    # Be careful the order of publickeylist, which will change your address. Then redeem unsuccessfully
    if isinstance(publickeylist, list) or isinstance(publickeylist, tuple)\
            and (isinstance(m, int) and isinstance(n) and m <= n and m >= 1):
        m += 80
        n += 80
        start = [bytes.fromhex(_hex(m))]
        for pk in publickeylist:
            pk = pk if isinstance(pk, bytes) else bytes.fromhex(pk)
            start += [bytes.fromhex(hex(len(pk))[2:]), pk]
        start += [bytes.fromhex(_hex(n)), bytes.fromhex("ae")]
    else:
        raise NotImplementedError("Can not handle your input")

    return hexlify(b"".join(start))
