import os


S_BOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]

def gf_mult(a, b):
    res = 0
    for _ in range(4):
        if b & 1: res ^= a
        hi = a & 0x8
        a = (a << 1) & 0xF
        if hi: a ^= 0x3
        b >>= 1
    return res

def key_expansion(key):
    def sub_nib(byte):
        return (S_BOX[(byte >> 4) & 0xF] << 4) | S_BOX[byte & 0xF]
    w = [0] * 6
    w[0], w[1] = (key >> 8) & 0xFF, key & 0xFF
    w[2] = w[0] ^ 0x80 ^ sub_nib(((w[1] << 4) | (w[1] >> 4)) & 0xFF)
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ 0x30 ^ sub_nib(((w[3] << 4) | (w[3] >> 4)) & 0xFF)
    w[5] = w[4] ^ w[3]
    return (w[0]<<8|w[1]), (w[2]<<8|w[3]), (w[4]<<8|w[5])

def encrypt_block(block, key):
    k0, k1, k2 = key_expansion(key)
    def add_k(s, k):
        return [s[i] ^ ((k >> (12-4*i)) & 0xF) for i in range(4)]
    s = [(block >> 12) & 0xF, (block >> 8) & 0xF, (block >> 4) & 0xF, block & 0xF]
    # Round 0
    s = add_k(s, k0)
    # Round 1
    s = [S_BOX[x] for x in s]
    s[1], s[3] = s[3], s[1]
    n0, n1 = s[0] ^ gf_mult(4, s[1]), gf_mult(4, s[0]) ^ s[1]
    n2, n3 = s[2] ^ gf_mult(4, s[3]), gf_mult(4, s[2]) ^ s[3]
    s = add_k([n0, n1, n2, n3], k1)
    # Round 2
    s = [S_BOX[x] for x in s]
    s[1], s[3] = s[3], s[1]
    s = add_k(s, k2)
    return (s[0] << 12) | (s[1] << 8) | (s[2] << 4) | s[3]


def cfb_encrypt(plaintext: bytes, key: int, iv: int) -> bytes:
    output = bytearray()
    prev_block = iv
    # Ensure data is even for 16-bit processing
    data = plaintext + (b'\x00' if len(plaintext) % 2 != 0 else b'')
    for i in range(0, len(data), 2):
        p_block = (data[i] << 8) | data[i+1]
        keystream = encrypt_block(prev_block, key)
        c_block = p_block ^ keystream
        output.extend([(c_block >> 8) & 0xFF, c_block & 0xFF])
        prev_block = c_block # Feed back the ciphertext
    return bytes(output)

def cfb_decrypt(ciphertext: bytes, key: int, iv: int) -> bytes:
    output = bytearray()
    prev_block = iv
    for i in range(0, len(ciphertext), 2):
        c_block = (ciphertext[i] << 8) | ciphertext[i+1]
       
        keystream = encrypt_block(prev_block, key)
        p_block = c_block ^ keystream
        output.extend([(p_block >> 8) & 0xFF, p_block & 0xFF])
        prev_block = c_block # Feed back the ciphertext (input), not the result
    return bytes(output).rstrip(b'\x00')

def encrypt_file(in_f, out_f, key, iv):
    with open(in_f, "rb") as f: data = f.read()
    with open(out_f, "wb") as f: f.write(cfb_encrypt(data, key, iv))

def decrypt_file(in_f, out_f, key, iv):
    with open(in_f, "rb") as f: data = f.read()
    with open(out_f, "wb") as f: f.write(cfb_decrypt(data, key, iv))