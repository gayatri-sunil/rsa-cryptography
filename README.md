# RSA Cryptography Lab (Python)

Single-file RSA lab implementation using Python big integers.  
Implements RSA key generation, encryption/decryption, and signing, with CRT optimization and basic side-channel hardening. Includes self-tests and performance benchmarks.

## Features
- Miller–Rabin probabilistic prime testing
- RSA key generation (1024 / 2048 / 4096 bits)
- RSA encryption and decryption (with and without CRT)
- RSA signing and verification
- CRT optimization with public re-check (fault attack countermeasure)
- Side-channel mitigations:
  - RSA blinding
  - Fixed-structure exponentiation
- Built-in self-tests and benchmarks (mean and variance)

## How to run
```bash
python rsa_lab.py

## Notes
- This implementation is intended for educational and lab use.
- Textbook RSA is used (no OAEP/PSS padding).
- Benchmarks measure relative performance, not constant-time guarantees.

## What I learned
- Practical RSA implementation details beyond theory
- Performance impact of CRT vs non-CRT private operations
- Common RSA side-channel risks and mitigation techniques
- Writing correctness tests and reproducible benchmarks
