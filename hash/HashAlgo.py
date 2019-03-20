class HashAlgo:
    def __init__(self, block_size, n_blocks):
        self.block_size = block_size
        self.mask       = (1 << block_size) - 1

    # Right shift operation
    def shr(self, value, shift_amount=1):
        return (value >> shift_amount) & self.mask
    
    # Left shift operation
    def shl(self, value, shift_amount=1):
        return (value << shift_amount) & self.mask

    # Circular right shift operation
    def rotr(self, value, shift_amount=1):
        return ((value >> shift_amount) | (value << (self.block_size - shift_amount))) & \
               self.mask

    # Circular left shift operation
    def rotl(self, value, shift_amount=1):
        return ((value >> (self.block_size - shift_amount)) | (value << shift_amount)) & \
               self.mask
