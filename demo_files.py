import os
from saes_cfb import cfb_encrypt, cfb_decrypt, encrypt_file, decrypt_file

os.makedirs("demo_output", exist_ok=True)
KEY, IV = 0xA73B, 0x1234

# 1. TEXT DEMO
print("Running Text Demo...")
msg = b"This is the confidential text for the cryptography assignment."
cipher_text = cfb_encrypt(msg, KEY, IV)
plain_text = cfb_decrypt(cipher_text, KEY, IV)
with open("demo_output/cipher_text.bin", "wb") as f: f.write(cipher_text)
print(f"Decrypted Text Match: {msg == plain_text}")

# 2. CHESSBOARD DEMO
print("Running Chessboard Demo...")
W, H = 128, 128
pixels = bytearray(W * H)
for y in range(H):
    for x in range(W):
        pixels[y * W + x] = 255 if ((x // 16) + (y // 16)) % 2 == 0 else 0

header = f"P5\n{W} {H}\n255\n".encode()
with open("demo_output/plain_chessboard.pgm", "wb") as f: f.write(header + pixels)

# Encrypt pixels
cipher_pix = cfb_encrypt(bytes(pixels), KEY, IV)
with open("demo_output/cipher_chessboard.pgm", "wb") as f: 
    f.write(header + cipher_pix[:len(pixels)])

# Decrypt pixels
dec_pix = cfb_decrypt(cipher_pix, KEY, IV)
with open("demo_output/decrypted_chessboard.pgm", "wb") as f: 
    f.write(header + dec_pix[:len(pixels)])

print("All demo files generated in 'demo_output'.")