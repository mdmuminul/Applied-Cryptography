#!/usr/bin/env python3

import argparse, hashlib, sys, datetime # do not use any other imports/libraries

# took 1.2 hours

## Output of running `pow.py --difficulty 26`:

def meets_difficulty(digest: bytes, difficulty: int) -> bool:
    if difficulty <= 0:
        return True
    full_bytes = difficulty >> 3
    rem_bits = difficulty & 7
    for i in range(full_bytes):
        if digest[i] != 0:
            return False
    if rem_bits:
        mask = (0xFF << (8 - rem_bits)) & 0xFF
        return (digest[full_bytes] & mask) == 0
    return True

# parse arguments
parser = argparse.ArgumentParser(description='Proof-of-work solver')
parser.add_argument('--difficulty', default=0, type=int, help='Number of leading zero bits')
args = parser.parse_args()

if args.difficulty < 0 or args.difficulty > 256:
    sys.exit(2)

identity = b"Arnis"

start = datetime.datetime.now()
seed = hashlib.sha256()
seed.update(identity)

nonce = 0
tried = 0

while True:
    counter = nonce.to_bytes(8, 'big', signed=False)

    h1 = seed.copy()
    h1.update(counter)
    d1 = h1.digest()
    d2 = hashlib.sha256(d1).digest()

    tried += 1
    if meets_difficulty(d2, args.difficulty):
        elapsed = (datetime.datetime.now() - start).total_seconds()
        mhps = (tried / elapsed) / 1_000_000.0 if elapsed > 0 else 0.0
        inp = identity + counter
        print(f"[+] Solved in {elapsed:.6f} sec ({mhps:.4f} Mhash/sec)")
        print(f"[+] Input: {inp.hex()}")
        print(f"[+] Solution: {d2.hex()}")
        print(f"[+] Nonce: {nonce}")
        break

    nonce += 1

