import time
import string
from saes_cfb import cfb_decrypt

PRINTABLE = set(bytes(string.printable, "ascii"))

def english_score(text: bytes) -> float:
    if not text: return -1000
    # Heuristic: ratio of printable characters + bonus for spaces
    printable_count = sum(1 for b in text if b in PRINTABLE)
    score = (printable_count / len(text)) * 100
    score += text.count(b' ') * 5
    return score

def brute_force_text():
    # We intercepted this from the text demo
    from demo_files import cipher_text, IV, msg
    
    print(f"Brute forcing ciphertext ({len(cipher_text)} bytes)...")
    best_key = -1
    max_score = -1000
    start = time.time()

    for k in range(0x10000):
        try:
            p = cfb_decrypt(cipher_text, k, IV)
            score = english_score(p)
            if score > max_score:
                max_score = score
                best_key = k
        except: continue

    elapsed = time.time() - start
    print(f"Done in {elapsed:.2f}s.")
    print(f"Found Key: 0x{best_key:04X}")
    print(f"Decrypted: {cfb_decrypt(cipher_text, best_key, IV).decode()}")

if __name__ == "__main__":
    brute_force_text()