def length_extension_attack(hash_algo):
    if hash_algo == 'sha-256':
        from Sha256 import Sha256
        
        secret_length   = int(input('Enter unknown initial message length (in bits): '))
        msg             = input('Enter known initial message: ')
        hash_val        = input('Enter initial hash value: ')

        ext             = input('Enter additional message: ')

        msg_ln, pad_ln = Sha256.get_nbit(msg)

        msg_ln  = hex(msg_ln + secret_length)[2:].zfill(16)
        pad_ln = (pad_ln + 1 - secret_length + Sha256.__MSG_BITS__) % Sha256.__MSG_BITS__

        pad_ln = Sha256.__MSG_BITS__ if pad_ln == 0 else pad_ln
        pad_ln = pad_ln // 8

        print("extra padding: " + str(pad_ln) + " bytes")

        out = msg + '%80'
        for i in range(1, pad_ln):
            out += '%00'
        for i in range(0, 16, 2):
            out += '%' + msg_ln[i:i+2]
        out += ext

        print("final msg:")
        print(out)

        init_digest = []
        for i in range(8):
            init_digest.append(int(hash_val[i * 8 : (i + 1) * 8], 16))

        sha = Sha256(init_digest)
        sha.update(ext, (secret_length + int(msg_ln, 16) + (pad_ln * 8)) // Sha256.__MSG_BITS__)

        print("final hash value:")
        print(sha.hexdigest())

length_extension_attack('sha-256')
