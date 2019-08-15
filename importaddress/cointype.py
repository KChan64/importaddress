'''
network	script type		pub/priv	version bytes	human-readable prefix
mainnet	p2pkh or p2sh	public		0488b21e		xpub
mainnet	p2pkh or p2sh	private		0488ade4		xprv
mainnet	p2wpkh-p2sh		public		049d7cb2		ypub
mainnet	p2wpkh-p2sh		private		049d7878		yprv
mainnet	p2wsh-p2sh		public		0295b43f		Ypub
mainnet	p2wsh-p2sh		private		0295b005		Yprv
mainnet	p2wpkh			public		04b24746		zpub
mainnet	p2wpkh			private		04b2430c		zprv
mainnet	p2wsh			public		02aa7ed3		Zpub
mainnet	p2wsh			private		02aa7a99		Zprv

testnet	p2pkh or p2sh	public		043587cf		tpub
testnet	p2pkh or p2sh	private		04358394		tprv
testnet	p2wpkh-p2sh		public		044a5262		upub
testnet	p2wpkh-p2sh		private		044a4e28		uprv
testnet	p2wsh-p2sh		public		024289ef		Upub
testnet	p2wsh-p2sh		private		024285b5		Uprv
testnet	p2wpkh			public		045f1cf6		vpub
testnet	p2wpkh			private		045f18bc		vprv
testnet	p2wsh			public		02575483		Vpub
testnet	p2wsh			private		02575048		Vprv		
'''
from collections import defaultdict
import re

x 		= {"xpub":"0488b21e", "xprv":"0488ade4"}

y 		= {"ypub":"049d7cb2", "yprv":"049d7878"}

y_up 	= {"Ypub":"0295b43f", "Yprv":"0295b005"}

z 		= {"zpub":"04b24746", "zprv":"04b2430c"}

z_up 	= {"Zpub":"02aa7ed3", "Zprv":"02aa7a99"}

t 		= {"tpub":"043587cf", "tprv":"04358394"}

u 		= {"upub":"044a5262", "uprv":"044a4e28"}

u_up 	= {"Upub":"024289ef", "Uprv":"024285b5"}

v 		= {"vpub":"045f1cf6", "vprv":"045f18bc"}

v_up 	= {"Vpub":"02575483", "Vprv":"02575048"}

# https://github.com/satoshilabs/slips/blob/master/slip-0044.md
to_path = re.findall(r"(.+?)cointype.py",__file__)[0]
with open(to_path + "data/slip-0044.md", "r+") as fd:
	content = fd.read()

cointypes = {tup[-1].strip().lower(): tup[0] for tup in re.findall(r"(\d{1,8})\W{0,7}(\dx\w{8}).{12}\[{0,1}([^\]\n(]+)", content)}


btc = {"main":{44:x, 49:y, 84:z}, "test":{44:t,49:u,84:v}}
coin = {
	1: btc.get("test"),
}
coin = defaultdict(lambda : btc.get("main"), coin)

'''
cointype -number-> coin -dict-> bip -pri/pub-> end
'''