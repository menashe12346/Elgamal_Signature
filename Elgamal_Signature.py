
import math
import hashlib
import random
from typing import Tuple

# Cryptographically secure RNG
_rand = random.SystemRandom()

def is_prime(n: int, k: int = 40) -> bool:
    """Miller–Rabin probabilistic primality test (k rounds)."""
    if n < 2:
        return False
    # small primes check
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23):
        if n == p:
            return True
        if n % p == 0:
            return False
    # write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    # witness loop
    for _ in range(k):
        a = _rand.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_candidate(bits: int) -> int:
    """Generate a random odd integer of specified bit-length."""
    candidate = _rand.getrandbits(bits)
    # ensure highest and lowest bits are set to 1
    candidate |= (1 << (bits - 1)) | 1
    return candidate

def generate_prime(bits: int) -> int:
    """Generate a prime of specified bit-length."""
    while True:
        q = generate_prime_candidate(bits)
        if is_prime(q):
            return q

def generate_p_q(q_bits: int) -> Tuple[int,int]:
    """
    Generate a Sophie-Germain prime pair:
      q = prime of q_bits
      p = 2*q + 1, also prime
    """
    while True:
        q = generate_prime(q_bits)
        p = 2 * q + 1
        if is_prime(p):
            return p, q

def find_generator(p: int, q: int) -> int:
    """
    Find a generator g of the subgroup of order q in Z_p^*:
      pick random h in [2, p-2]
      set g = h^((p-1)//q) mod p, require g > 1
    """
    while True:
        h = _rand.randrange(2, p - 1)
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            return g

def hash_message(msg: bytes) -> int:
    """Compute SHA-256 hash of msg and return as integer."""
    h = hashlib.sha256(msg).digest()
    return int.from_bytes(h, byteorder='big')

def generate_keys(p: int, g: int) -> Tuple[int,int]:
    """
    Generate ElGamal keypair:
      x = private key in [2, p-2]
      y = g^x mod p (public key)
    """
    x = _rand.randrange(2, p - 2)
    y = pow(g, x, p)
    return x, y

def sign(msg: bytes, p: int, g: int, x: int, q: int) -> Tuple[int,int]:
    """
    ElGamal signature on msg; returns (r, s):
      r = g^k mod p
      s = k^{-1} * (H(msg) - x*r mod q) mod q
    """
    h = hash_message(msg) % q
    while True:
        k = _rand.randrange(2, q - 1)
        if math.gcd(k, q) != 1:
            continue
        r = pow(g, k, p)             # full group element
        if r == 0:
            continue
        k_inv = pow(k, -1, q)
        s = (k_inv * (h - x * (r % q))) % q
        if s != 0:
            return r, s

def verify(msg: bytes, sig: Tuple[int,int], p: int, g: int, y: int, q: int) -> bool:
    """
    Verify ElGamal signature:
      check 0 < r < p, 0 < s < q
      let H = H(msg) mod q
      check (y^r * r^s mod p) == (g^H mod p)
    """
    r, s = sig
    if not (0 < r < p and 0 < s < q):
        return False
    h = hash_message(msg) % q
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

if __name__ == "__main__":
    # 1. Choose bit-length for q (e.g., 256 bits)
    while True:
        try:
            q_bits = int(input("Enter bit-length for subgroup order q (e.g., 256): "))
            if q_bits < 128:
                print("Warning: bit-length too small for secure use.")
            elif q_bits > 1024:
                print("Bit-length very large; generation may take a while.")
            break
        except ValueError:
            print("Please enter a valid integer.")

    # 2–5. Generate p and q
    p, q = generate_p_q(q_bits)
    print(f"p = {p}\nq = {q}")

    # 6–8. Find subgroup generator g
    g = find_generator(p, q)
    print(f"g = {g}")

    # Generate keypair
    x, y = generate_keys(p, g)
    print(f"private x = {x}\npublic y = {y}")

    # Sign a message
    message = b"HELLO WORLD"
    sig = sign(message, p, g, x, q)
    print(f"signature = {sig}")

    # Verify signature
    valid = verify(message, sig, p, g, y, q)
    print("Signature valid?", valid)