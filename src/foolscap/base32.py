
# copied from the waterken.org Web-Calculus python implementation

def encode(input):
    output = []
    buffer = 0
    n = 0

    for b in input:
        buffer = buffer << 8
        buffer = buffer | b
        n = n + 8
        while n >= 5:
            output.append(_encode((buffer >> (n - 5)) & 0x1F))
            n = n - 5
        buffer = buffer & 0x1F  # To quiet any warning from << operator

    if n > 0:
        buffer = buffer << (5 - n)
        output.append(_encode(buffer & 0x1F))

    return bytes(output)

ord_a,   = b'a'
ord_two, = b'2'

def _encode(v):
    if v < 26:
        return ord_a + v
    return ord_two + v - 26

# we use the rfc4648 base32 alphabet, in lowercase
BASE32_ALPHABET = bytes(_encode(i) for i in range(0x20))
# 'abcdefghijklmnopqrstuvwxyz234567'

def is_base32(s):
    for c in s.lower():
        if c not in BASE32_ALPHABET:
            return False
    return True
