def pad(block, block_size):
    padding_length = block_size - (len(block) % block_size)
    return block + padding_length * chr(padding_length)


def unpad(block, block_size):
    padding_length = ord(block[-1])
    if 0 < padding_length < block_size:
        return block[:-padding_length]
    return block


def byte_xor(byte1, byte2):
    parts = []
    for b1, b2 in zip(byte1, byte2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)
