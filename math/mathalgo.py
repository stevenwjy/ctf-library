def extended_euclid(a, b):
	if a == 0:
		return (0, 1, b)

	x1, y1, gcd = extended_euclid(b % a, a)

	x = y1 - (b // a) * x1
	y = x1

	return (x, y, gcd)

def fast_pow(a, b, mod=None):
	ret = 1 % mod if mod else 1
	val, lop = a, b

	while lop:
		if lop & 1:
			ret = (ret * val) % mod if mod else ret * val
		lop = lop // 2
		val = (val * val) % mod if mod else val * val

	return ret