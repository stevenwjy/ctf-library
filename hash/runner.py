def length_extension_attack(hash_algo):
	if hash_algo == 'sha-256':
		
		from Sha256 import Sha256

		c = input()
		sign = input()
		ext = input()

		l, lop = Sha256.get_nbit(c)

		ln  = hex(l + 256)[2:].zfill(16)
		lop = (lop + 1 - 256 + 512) % 512

		if lop == 0:
			lop = 512
		lop = lop // 8

		print("extra padding: " + str(lop) + " bytes")

		out = c + '%80'
		for i in range(1, lop):
			out += '%00'
		for i in range(0, 16, 2):
			out += '%' + ln[i:i+2]
		out += ext

		print("final cookie:")
		print(out)

		init_digest = []
		for i in range(8):
			init_digest.append(int(sign[i * 8 : (i + 1) * 8], 16))

		sha = Sha256(init_digest)
		sha.update(ext, 3)

		print("final signature:")
		print(sha.hexdigest())

length_extension_attack('sha-256')