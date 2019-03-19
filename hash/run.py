from Sha256 import Sha256

test = Sha256()
test.update('')

print(test.hexdigest())
