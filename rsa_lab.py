# rsa_lab_spyder.py — single-file RSA lab implementation (Python big integers)
# What this file contains (high-level roadmap):
# 1) Helpers: extended gcd + modular inverse + parsing + timing stats
# 2) Primes: Miller–Rabin probable prime test + random prime generator
# 3) Side-channel mitigations: fixed-structure exponentiation + RSA blinding
# 4) RSA core: keygen, encrypt, decrypt/sign with and without CRT
# 5) CRT fault countermeasure: public re-check (prevents Bellcore-style attacks)
# 6) Validation: self-tests + benchmarks + lab vector computation

import secrets   # cryptographically secure random numbers (for primes + blinding)
import time      # benchmarking timers
import math      # gcd
from dataclasses import dataclass
from statistics import mean, pvariance


# ====== CONFIG: choose what runs when you execute the script ======
RUN_SELF_TESTS = True
RUN_LAB_VECTOR = True
RUN_BENCHMARKS = True   # set False if you only want correctness (no timings)

# benchmark sample sizes (more runs = more stable mean/variance)
BENCH_RUNS_1024 = 20
BENCH_RUNS_2048 = 15
BENCH_RUNS_4096 = 10


# ================================================================
# 1) SMALL UTILITIES (math + parsing + benchmarking)
# ================================================================

def egcd(a: int, b: int):
    """
    Extended Euclidean Algorithm.
    Returns (g, x, y) such that:
        a*x + b*y = g
    where g = gcd(a, b).

    Why we need it:
    - to compute modular inverses (RSA needs d = e^{-1} mod phi).
    """
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inv_mod(a: int, m: int) -> int:
    """
    Modular inverse:
        return a^{-1} mod m  (only exists if gcd(a,m)=1)
    Used for:
    - d = e^{-1} mod phi(n)
    - qinv = q^{-1} mod p (CRT recombination)
    - r_inv for blinding unmasking
    """
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("inverse does not exist (gcd != 1)")
    return x % m


def join_int_lines(s: str) -> int:
    """
    Lab vectors often split p and q across multiple lines.
    This helper removes whitespace/newlines and parses as one big integer.
    """
    return int("".join(s.split()))


def timeit(fn, runs: int, warmup: int = 2):
    """
    Benchmark helper:
    - warmup runs to reduce first-run effects
    - collects samples
    - returns (mean, variance, samples)

    Lab requirement: show mean + variance for different key sizes.
    """
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        samples.append(t1 - t0)
    return mean(samples), pvariance(samples), samples


# ================================================================
# 2) PRIMALITY TESTING + PRIME GENERATION
# ================================================================

# quick trial-division primes to reject obvious composites fast
_SMALL_PRIMES = (3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97)

def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """
    Miller–Rabin probable prime test.

    What it guarantees:
    - if returns False => n is definitely composite
    - if returns True => n is "very likely prime" (probability of error negligible for enough rounds)

    Why this is used:
    - deterministic primality testing is slower; Miller–Rabin is standard for RSA key generation.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Small prime trial division first (cheap speed-up)
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n-1 as d * 2^s with d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # repeat Miller–Rabin rounds with random bases
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # random witness a in [2, n-2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue

        witness = True
        for __ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                witness = False
                break

        if witness:
            return False

    return True


def random_prime(bits: int) -> int:
    """
    Generates a random probable prime of exactly 'bits' bits.

    Key details:
    - set top bit => ensures correct bit-length
    - set lowest bit => ensures odd
    """
    if bits < 32:
        raise ValueError("prime size too small")
    while True:
        x = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(x):
            return x


# ================================================================
# 3) SIDE-CHANNEL COUNTERMEASURES
# ================================================================

def sametime(base: int, exponent: int, mod: int) -> int:
    """
    Fixed-structure modular exponentiation ("square-and-always-multiply").

    Goal:
    - reduce timing leakage from secret exponent bits.
    - unlike classic square-and-multiply, we do multiply every bit (by base or by 1).

    Note:
    - In Python this is not a formal constant-time guarantee (big-int ops may vary),
      but it removes the biggest branch-based leakage pattern.
    """
    if mod == 1:
        return 0

    base %= mod
    acc = 1 % mod

    # Iterate from MSB to LSB of exponent
    for i in range(exponent.bit_length() - 1, -1, -1):
        # always square
        acc = (acc * acc) % mod

        # get current bit of exponent
        bit = (exponent >> i) & 1

        # always multiply (by base if bit=1 else by 1 if bit=0)
        mul = base if bit else 1
        acc = (acc * mul) % mod

    return acc


def blind_value(x: int, e: int, n: int):
    """
    RSA blinding.

    We randomize the input x before private exponentiation:
        x_blinded = x * r^e mod n
    where gcd(r,n)=1 so that r has an inverse mod n.
    After private op we can unblind by multiplying with r^{-1}.

    Why this matters:
    - breaks correlation between attacker-chosen inputs and side-channel leakage.
    """
    while True:
        r = secrets.randbelow(n - 2) + 2
        if math.gcd(r, n) == 1:
            break

    r_e = pow(r, e, n)            # public exponentiation (safe: e is public)
    x_blinded = (x * r_e) % n
    r_inv = inv_mod(r, n)
    return x_blinded, r_inv


# ================================================================
# 4) RSA CORE (key structure + key generation + operations)
# ================================================================

@dataclass(frozen=True)
class RSAKey:
    """
    RSA key container.

    n, e = public key
    d    = private exponent
    p, q = secret primes
    dp, dq, qinv = CRT parameters for fast private ops
    """
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int  # q^{-1} mod p


def rsa_keygen(bits: int, e: int = 65537) -> RSAKey:
    """
    RSA key generation for lab-required sizes only.

    Steps:
    1) pick random primes p and q of bits/2 bits
    2) compute n = p*q
    3) compute phi = (p-1)(q-1)
    4) ensure gcd(e,phi)=1
    5) compute d = e^{-1} mod phi
    6) compute CRT params dp, dq, qinv
    """
    if bits not in (1024, 2048, 4096):
        raise ValueError("required sizes: 1024/2048/4096")

    h = bits // 2
    while True:
        p = random_prime(h)
        q = random_prime(h)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if math.gcd(e, phi) != 1:
            continue

        d = inv_mod(e, phi)

        # CRT parameters (speed-up)
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = inv_mod(q, p)

        return RSAKey(n=n, e=e, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)


def rsa_encrypt(m: int, e: int, n: int) -> int:
    """
    RSA encryption (textbook):
        c = m^e mod n

    Note:
    - textbook RSA is deterministic and not semantically secure without OAEP.
    - OK for lab demonstration.
    """
    if not (0 <= m < n):
        raise ValueError("m must be in [0, n)")
    return pow(m, e, n)


def rsa_private_no_crt(c: int, key: RSAKey) -> int:
    """
    RSA private operation without CRT:
        m = c^d mod n

    With side-channel countermeasures:
    - blinding: operate on randomized input
    - fixed-structure exp: reduce bit-dependent timing patterns
    """
    # 1) blind ciphertext
    c_b, r_inv = blind_value(c % key.n, key.e, key.n)

    # 2) private exponentiation using fixed-structure exp
    m_b = sametime(c_b, key.d, key.n)

    # 3) unblind result
    return (m_b * r_inv) % key.n


def rsa_private_crt(c: int, key: RSAKey) -> int:
    """
    RSA private operation with CRT (fast path) + security hardening.

    Steps:
    1) x = c mod n
    2) blind x -> x_b
    3) compute:
       m1 = x_b^dp mod p
       m2 = x_b^dq mod q
    4) CRT recombination to get out_b mod n
    5) unblind
    6) FAULT DEFENSE: verify pow(out, e, n) == x
       (prevents Bellcore-style CRT fault attacks)
    """
    x = c % key.n

    # 1) blind input
    x_b, r_inv = blind_value(x, key.e, key.n)

    # 2) compute two half-size exponentiations
    m1 = sametime(x_b % key.p, key.dp, key.p)
    m2 = sametime(x_b % key.q, key.dq, key.q)

    # 3) recombine using Garner-style CRT
    h = (key.qinv * (m1 - m2)) % key.p
    out_b = (m2 + h * key.q) % key.n

    # 4) unblind
    out = (out_b * r_inv) % key.n

    # 5) fault countermeasure: public re-check
    if pow(out, key.e, key.n) != x:
        raise RuntimeError("fault detected in CRT private operation")

    return out


def rsa_decrypt(c: int, key: RSAKey, use_crt: bool) -> int:
    """
    Decrypt chooses either CRT or non-CRT private operation.
    Lab requires both implementations.
    """
    if not (0 <= c < key.n):
        raise ValueError("c must be in [0, n)")
    return rsa_private_crt(c, key) if use_crt else rsa_private_no_crt(c, key)


def rsa_sign(m: int, key: RSAKey, use_crt: bool) -> int:
    """
    RSA signing in textbook form:
        s = m^d mod n

    Note:
    - In real schemes we sign a padded hash (e.g., PSS).
    - Here m must already be a valid representative < n.
    """
    if not (0 <= m < key.n):
        raise ValueError("message representative must be < n (hash/padding not implemented)")
    return rsa_private_crt(m, key) if use_crt else rsa_private_no_crt(m, key)


def rsa_verify(m: int, sig: int, e: int, n: int) -> bool:
    """
    RSA verify:
        check sig^e mod n == m
    """
    return (0 <= m < n) and (0 <= sig < n) and (pow(sig, e, n) == m)


# ================================================================
# 5) TESTS (correctness proof by checks)
# ================================================================

def self_tests() -> None:
    """
    Two-stage test strategy:

    Stage A: Known tiny RSA example (easy sanity check)
    Stage B: Random tests on a generated 1024-bit key (realistic big-int check)
    """
    # --- Stage A: classic small RSA example ---
    p, q = 61, 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = inv_mod(e, phi)

    key = RSAKey(
        n=n, e=e, d=d, p=p, q=q,
        dp=d % (p - 1),
        dq=d % (q - 1),
        qinv=inv_mod(q, p)
    )

    # test multiple edge-case messages
    for m in (0, 1, 2, 42, 123, n - 1):
        c = rsa_encrypt(m, e, n)
        assert rsa_decrypt(c, key, use_crt=False) == m
        assert rsa_decrypt(c, key, use_crt=True) == m
        s = rsa_sign(m, key, use_crt=True)
        assert rsa_verify(m, s, e, n)

    # --- Stage B: random tests on actual 1024-bit key ---
    key2 = rsa_keygen(1024)
    for _ in range(10):
        m = secrets.randbelow(key2.n - 1) + 1
        c = rsa_encrypt(m, key2.e, key2.n)
        assert rsa_decrypt(c, key2, use_crt=False) == m
        assert rsa_decrypt(c, key2, use_crt=True) == m
        s = rsa_sign(m, key2, use_crt=True)
        assert rsa_verify(m, s, key2.e, key2.n)

    print("Self-tests: OK")


# ================================================================
# 6) BENCHMARKS (mean + variance as required)
# ================================================================

def benchmark(bits: int, runs: int = 15) -> None:
    """
    Measures performance for:
    - Key generation (mean/variance)
    - Encryption
    - Decryption without CRT
    - Decryption with CRT + fault-check
    """
    print(f"\n=== Benchmark {bits}-bit ===")

    kg_mean, kg_var, _ = timeit(lambda: rsa_keygen(bits), runs=max(5, runs // 2), warmup=1)
    key = rsa_keygen(bits)

    # pick one random message and encrypt once
    m = secrets.randbelow(key.n - 1) + 1
    c = rsa_encrypt(m, key.e, key.n)

    enc_mean, enc_var, _ = timeit(lambda: rsa_encrypt(m, key.e, key.n), runs=runs)
    dec_mean, dec_var, _ = timeit(lambda: rsa_decrypt(c, key, use_crt=False), runs=runs)
    crt_mean, crt_var, _ = timeit(lambda: rsa_decrypt(c, key, use_crt=True), runs=runs)

    # sanity check after benchmarking
    assert rsa_decrypt(c, key, use_crt=False) == m
    assert rsa_decrypt(c, key, use_crt=True) == m

    print(f"KeyGen   mean={kg_mean:.2f}s var={kg_var:.3e}")
    print(f"Encrypt  mean={enc_mean:.2f}s var={enc_var:.3e}")
    print(f"Decrypt  mean={dec_mean:.2f}s var={dec_var:.3e}   (no CRT)")
    print(f"Decrypt  mean={crt_mean:.2f}s var={crt_var:.3e}   (CRT + verify)")


# ================================================================
# 7) REQUIRED LAB VECTOR COMPUTATION
# ================================================================

def lab_vector() -> None:
    """
    Computes required values for the lab:
    - n, phi(n), e, d
    - encryption of a given message m
    - CRT signature of a given representative message

    IMPORTANT:
    - Replace p_text and q_text with the provided large test vector primes
      for the real lab submission.
    """
    # TODO for real lab: paste p and q from the provided test vector file here
    p_text = """
    61
    """
    q_text = """
    53
    """

    p = join_int_lines(p_text)
    q = join_int_lines(q_text)

    e = 65537
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inv_mod(e, phi)

    key = RSAKey(
        n=n, e=e, d=d,
        p=p, q=q,
        dp=d % (p - 1),
        dq=d % (q - 1),
        qinv=inv_mod(q, p),
    )

    # --- Encryption example required by lab ---
    m_enc = 65
    c = rsa_encrypt(m_enc, e, n)

    # --- Signature example required by lab ---
    # Example message: 78 digits of '1' (big number). We must reduce it mod n if needed.
    m_sig = int("1" * 78)
    m_sig_rep = m_sig if m_sig < n else (m_sig % n)

    sig = rsa_sign(m_sig_rep, key, use_crt=True)
    ok = rsa_verify(m_sig_rep, sig, e, n)

    m_dec = rsa_decrypt(c, key, use_crt=True)


    print("=== LAB VECTOR RESULTS ===")
    print("n =", n)
    print("phi(n) =", phi)
    print("e =", e)
    print("d =", d)
    print("m =", m_enc)
    print("c =", c)
    print("m(sign) representative =", m_sig_rep)
    print("signature =", sig)
    print("signature verifies? ", ok)
    print("decrypted =", m_dec)


# ================================================================
# 8) MAIN ENTRY POINT
# ================================================================

def main():
    # Run correctness tests first (fast feedback)
    if RUN_SELF_TESTS:
        self_tests()

    # Then compute and print the lab vector outputs
    if RUN_LAB_VECTOR:
        lab_vector()

    # Finally benchmark (slowest)
    if RUN_BENCHMARKS:
        benchmark(1024, runs=BENCH_RUNS_1024)
        benchmark(2048, runs=BENCH_RUNS_2048)
        benchmark(4096, runs=BENCH_RUNS_4096)


if __name__ == "__main__":
    main()
