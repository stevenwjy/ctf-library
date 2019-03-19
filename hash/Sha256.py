from HashAlgo import HashAlgo

class Sha256(HashAlgo):
	# Sha-256 constants:
	# the first thirty-two bits of the fractional parts of the cube roots of the first sixty- four prime numbers
	__CONSTANTS__ = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	]

	# Sha-256 initial hash value
	__INIT_VALUE__ = [
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	]

	__BLOCK_SIZE__	= 32
	__N_BLOCKS__	= 8
	__MSG_BLOCKS__  = 16

	__OFFSET__ 		= 64
	__MSG_BITS__ 	= 512
	
	def __init__(self, init_digest=None):
		HashAlgo.__init__(self, Sha256.__BLOCK_SIZE__, Sha256.__N_BLOCKS__)

		if init_digest and len(init_digest) == self.__N_BLOCKS__:
			self.digest = [ (x & self.mask) for x in init_digest ]
		else:
			self.digest = Sha256.__INIT_VALUE__

	def __ch(self, x, y, z):
		return (x & y) ^ ((~x) & z)

	def __maj(self, x, y, z):
		return (x & y) ^ (x & z) ^ (y & z)

	def __s0(self, x):
		return self.rotr(x,  2) ^ self.rotr(x, 13) ^ self.rotr(x, 22)

	def __s1(self, x):
		return self.rotr(x,  6) ^ self.rotr(x, 11) ^ self.rotr(x, 25)

	def __o0(self, x):
		return self.rotr(x,  7) ^ self.rotr(x, 18) ^ self.shr(x, 3)

	def __o1(self, x):
		return self.rotr(x, 17) ^ self.rotr(x, 19) ^ self.shr(x, 10)

	def __update_digest(self, msg):
		a, b, c, d, e, f, g, h = self.digest

		w = msg.copy()
		for k in range(16, 64):
			w.append((self.__o1(w[k - 2]) + w[k - 7] + self.__o0(w[k - 15]) + w[k - 16]) & self.mask)

		for k in range(64):
			t1 = (h + self.__s1(e) + self.__ch(e, f, g) + Sha256.__CONSTANTS__[k] + w[k]) & self.mask
			t2 = (self.__s0(a) + self.__maj(a, b, c)) & self.mask

			h = g
			g = f
			f = e
			e = (d + t1) & self.mask
			d = c
			c = b
			b = a
			a = (t1 + t2) & self.mask

		res = [a, b, c, d, e, f, g, h]
		for i in range(len(self.digest)):
			self.digest[i] = (self.digest[i] + res[i]) & self.mask

	def __str_to_bin(s):
		if not s:
			return ''

		hx, i = '', 0
		expected_length = 0

		while i < len(s):
			expected_length += 8
			if s[i] == '%':
				hx += s[i+1:i+3]
				i += 3	
			else:
				hx += s[i].encode().hex()
				i += 1

		return bin(int(hx, 16))[2:].zfill(expected_length)

	def __add_padding(msg):
		l = len(msg)
		ext = Sha256.__MSG_BITS__ - ((len(msg) + Sha256.__OFFSET__) % Sha256.__MSG_BITS__)

		msg += '1'
		for i in range(1, ext):
			msg += '0'
		msg += bin(l)[2:].zfill(64)

		return msg

	def get_nbit_padding(msg):
		msg = Sha256.__str_to_bin(msg)
		return Sha256.__MSG_BITS__ - ((len(msg) + Sha256.__OFFSET__) % Sha256.__MSG_BITS__)

	def update(self, s):
		msg = Sha256.__str_to_bin(s)
		msg = Sha256.__add_padding(msg)

		while msg:
			msg_block = []
			for i in range(Sha256.__MSG_BLOCKS__):
				msg_block.append(int(msg[i * Sha256.__BLOCK_SIZE__ : (i + 1) * Sha256.__BLOCK_SIZE__], 2))

			msg = msg[Sha256.__MSG_BLOCKS__ * Sha256.__BLOCK_SIZE__ :]
			self.__update_digest(msg_block)

	def hexdigest(self):
		ret = ''
		for i in range(Sha256.__N_BLOCKS__):
			ret += hex(self.digest[i])[2:].zfill(8)
		return ret