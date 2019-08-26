default_position = None

def details(msg, inp, winp):
	return msg + "Your input is {}, but functions need something like {}".format(inp, winp)

class ParameterError(Exception):
	
	def __init__(self, message, inp, winp, position=default_position):
	
		self.position = position
		self._details = details(message, inp, winp)
		super().__init__(self._details)

class EmptyParamError(Exception):
	
	def __init__(self, message, inp, winp, position=default_position):
	
		self.position = position
		self._details = details(message, inp, winp)
		super().__init__(self._details)

class AddressTypeError(Exception):
	
	def __init__(self, message, inp, winp, position=default_position):
	
		self.position = position
		self._details = details(message, inp, winp)
		super().__init__(self._details)
		