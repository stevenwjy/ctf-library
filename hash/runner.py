from Sha256 import Sha256

c = input()
sign = input()
ext = input()

lop = Sha256.get_nbit_padding(c) // 8
print("extra padding: " + str(lop) + " bytes")

out = c
if lop:
	out += '%80'
	for i in range(1, lop):
		out += '%00'
out += ext

print("final cookie:")
print(out)

init_digest = []
for i in range(8):
	init_digest.append(int(sign[i * 8 : (i + 1) * 8], 16))

sha = Sha256(init_digest)
sha.update(ext)

print("final signature:")
print(sha.hexdigest())