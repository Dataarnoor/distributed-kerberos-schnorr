"""
crypto_utils.py
Core cryptographic primitives for Kerberos multi-signature system.

Manually implemented:
  - Modular exponentiation (square-and-multiply)
  - Modular arithmetic over Z_q
  - Schnorr signature generation and verification
  - Multi-signature threshold verification
  - AES-256-CBC encryption/decryption (from scratch, no external libs)
  - Manual PKCS#7 padding/unpadding
  - SHA-256 (via hashlib standard library)
  - OS-level secure RNG (via os.urandom)

No asymmetric cryptographic libraries are used.
"""

import hashlib
import os
import json

# ============================================================
# Schnorr Group Parameters (RFC 5114, Section 2.1)
# 1024-bit MODP Group with 160-bit Prime Order Subgroup
# p: 1024-bit prime
# q: 160-bit prime such that q | (p - 1)
# g: generator of order q in Z_p*
# ============================================================

P = int(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA"
    "52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324"
    "975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE564"
    "4738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFD"
    "A76D4DA708DF1FB2BC2E4A4371", 16
)

Q = int("F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16)

G = int(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF142"
    "66D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E9154"
    "7F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F53"
    "1DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97"
    "C2A24855E6EEB22B3B2E5", 16
)

# ============================================================
# Manual Modular Arithmetic
# ============================================================

def mod_pow(base: int, exp: int, mod: int) -> int:
    """
    Manual modular exponentiation using square-and-multiply algorithm.
    Computes base^exp mod mod in O(log exp) multiplications.
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:                        # if bit is set
            result = (result * base) % mod
        exp >>= 1                          # shift right (divide by 2)
        base = (base * base) % mod        # square the base
    return result


def mod_inverse(a: int, m: int) -> int:
    """Extended Euclidean Algorithm for modular inverse: a^{-1} mod m."""
    if m == 1:
        return 0
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0


# ============================================================
# OS-Level Secure RNG
# ============================================================

def secure_random_bytes(n: int) -> bytes:
    """Generate n cryptographically secure random bytes using OS RNG."""
    return os.urandom(n)


def secure_random_int(max_val: int) -> int:
    """
    Generate a cryptographically secure random integer in [1, max_val - 1].
    Uses rejection sampling to avoid bias.
    """
    byte_len = (max_val.bit_length() + 7) // 8
    while True:
        r = int.from_bytes(os.urandom(byte_len), 'big')
        if 1 <= r < max_val:
            return r


# ============================================================
# SHA-256 (Standard Library)
# ============================================================

def sha256_bytes(data: bytes) -> bytes:
    """Return SHA-256 digest as bytes."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 digest as hex string."""
    return hashlib.sha256(data).hexdigest()


def sha256_int(data: bytes) -> int:
    """Return SHA-256 digest as integer."""
    return int.from_bytes(hashlib.sha256(data).digest(), 'big')


# ============================================================
# Schnorr Key Generation
# ============================================================

def schnorr_keygen():
    """
    Generate a Schnorr key pair.
    Private key: x in Z_q (random)
    Public key:  y = g^x mod p
    Returns (x, y) as integers.
    """
    x = secure_random_int(Q)
    y = mod_pow(G, x, P)
    return x, y


# ============================================================
# Schnorr Signature Generation
# ============================================================

def schnorr_sign(message: bytes, private_key: int, authority_id: str):
    """
    Generate a Schnorr signature (R, s) for message m.

    Protocol:
      1. Generate fresh nonce k in Z_q  (MUST be fresh each time)
      2. Commitment R = g^k mod p
      3. Challenge  e = H(m || R || authority_id) mod q
      4. Response   s = (k + e * x) mod q

    Returns (R, s) as integers.
    """
    # Fresh random nonce -- reusing leaks the private key!
    k = secure_random_int(Q)

    # Commitment
    R = mod_pow(G, k, P)

    # Challenge: bind to message, commitment, and authority identity
    R_bytes = R.to_bytes((R.bit_length() + 7) // 8, 'big')
    h_input = message + R_bytes + authority_id.encode('utf-8')
    e = sha256_int(h_input) % Q

    # Signature
    s = (k + e * private_key) % Q

    return R, s


# ============================================================
# Schnorr Signature Verification
# ============================================================

def schnorr_verify(message: bytes, R: int, s: int,
                   public_key: int, authority_id: str) -> bool:
    """
    Verify a Schnorr signature.

    Checks: g^s ≡ R * y^e  (mod p)
    where   e = H(m || R || authority_id) mod q

    Returns True iff valid.
    """
    # Recompute challenge the same way as signing
    R_bytes = R.to_bytes((R.bit_length() + 7) // 8, 'big')
    h_input = message + R_bytes + authority_id.encode('utf-8')
    e = sha256_int(h_input) % Q

    # Verify equation: g^s == R * y^e  (mod p)
    lhs = mod_pow(G, s, P)
    rhs = (R * mod_pow(public_key, e, P)) % P

    return lhs == rhs


# ============================================================
# Multi-Signature Threshold Verification
# ============================================================

def verify_multi_signatures(message: bytes, signatures: list,
                             public_keys: dict, threshold: int = 2) -> bool:
    """
    Verify that at least `threshold` independent signatures are valid.

    signatures: list of dicts {"authority_id": str, "R": int, "s": int}
    public_keys: dict {authority_id: public_key_int}
    threshold:   minimum number of valid signatures required (default 2)

    Returns True iff at least `threshold` distinct authorities have valid signatures.
    """
    valid_count = 0
    seen_authorities = set()

    for sig in signatures:
        auth_id = sig.get("authority_id")
        R = sig.get("R")
        s = sig.get("s")

        if auth_id is None or R is None or s is None:
            continue
        if auth_id not in public_keys:
            continue
        # Prevent double-counting: each authority counts at most once
        if auth_id in seen_authorities:
            continue

        pub_key = public_keys[auth_id]
        if schnorr_verify(message, R, s, pub_key, auth_id):
            valid_count += 1
            seen_authorities.add(auth_id)

    return valid_count >= threshold


# ============================================================
# Manual PKCS#7 Padding / Unpadding
# ============================================================

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Manual PKCS#7 padding.
    Appends N bytes of value N to make len(data) a multiple of block_size.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Manual PKCS#7 unpadding with strict validation.
    Raises ValueError on invalid padding.
    """
    if not data:
        raise ValueError("Empty data cannot be unpadded")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Invalid PKCS#7 pad length: {pad_len}")
    for byte in data[-pad_len:]:
        if byte != pad_len:
            raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-pad_len]


# ============================================================
# AES-256 Implementation (from scratch, no external libraries)
# ============================================================

# AES S-box (forward substitution)
_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
])

# AES inverse S-box (for decryption)
_INV_SBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
])

# Round constants for AES key expansion
_RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
]


def _gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with AES irreducible polynomial x^8+x^4+x^3+x+1."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B  # AES reduction polynomial (x^4 + x^3 + x + 1 -> 0x1b)
        b >>= 1
    return p


def _sub_bytes(state: list) -> list:
    return [[_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _inv_sub_bytes(state: list) -> list:
    return [[_INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state: list) -> list:
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][1], state[1][2], state[1][3], state[1][0]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][3], state[3][0], state[3][1], state[3][2]],
    ]


def _inv_shift_rows(state: list) -> list:
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][3], state[1][0], state[1][1], state[1][2]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][1], state[3][2], state[3][3], state[3][0]],
    ]


def _mix_columns(state: list) -> list:
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        s0 = state[0][c]; s1 = state[1][c]
        s2 = state[2][c]; s3 = state[3][c]
        result[0][c] = _gmul(0x02, s0) ^ _gmul(0x03, s1) ^ s2 ^ s3
        result[1][c] = s0 ^ _gmul(0x02, s1) ^ _gmul(0x03, s2) ^ s3
        result[2][c] = s0 ^ s1 ^ _gmul(0x02, s2) ^ _gmul(0x03, s3)
        result[3][c] = _gmul(0x03, s0) ^ s1 ^ s2 ^ _gmul(0x02, s3)
    return result


def _inv_mix_columns(state: list) -> list:
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        s0 = state[0][c]; s1 = state[1][c]
        s2 = state[2][c]; s3 = state[3][c]
        result[0][c] = (_gmul(0x0e, s0) ^ _gmul(0x0b, s1) ^
                        _gmul(0x0d, s2) ^ _gmul(0x09, s3))
        result[1][c] = (_gmul(0x09, s0) ^ _gmul(0x0e, s1) ^
                        _gmul(0x0b, s2) ^ _gmul(0x0d, s3))
        result[2][c] = (_gmul(0x0d, s0) ^ _gmul(0x09, s1) ^
                        _gmul(0x0e, s2) ^ _gmul(0x0b, s3))
        result[3][c] = (_gmul(0x0b, s0) ^ _gmul(0x0d, s1) ^
                        _gmul(0x09, s2) ^ _gmul(0x0e, s3))
    return result


def _add_round_key(state: list, round_key: list) -> list:
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


def _bytes_to_state(block: bytes) -> list:
    """Convert 16-byte block to 4x4 state matrix (column-major)."""
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = block[i]
    return state


def _state_to_bytes(state: list) -> bytes:
    """Convert 4x4 state matrix back to 16-byte block."""
    result = []
    for c in range(4):
        for r in range(4):
            result.append(state[r][c])
    return bytes(result)


def _key_expansion_256(key: bytes) -> list:
    """
    AES-256 key expansion.
    key: 32 bytes (256 bits)
    Returns list of 15 round keys, each as a 4x4 state matrix.
    """
    assert len(key) == 32
    Nk = 8   # key words (32-bit each)
    Nr = 14  # rounds for AES-256
    Nb = 4   # block words

    # W[i] = 4-byte word
    W = []
    for i in range(Nk):
        W.append(list(key[4*i : 4*i+4]))

    for i in range(Nk, Nb * (Nr + 1)):
        temp = W[i-1][:]
        if i % Nk == 0:
            # SubWord(RotWord(temp)) XOR Rcon
            temp = [_SBOX[temp[1]], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
            temp[0] ^= _RCON[i // Nk - 1]
        elif i % Nk == 4:
            temp = [_SBOX[b] for b in temp]
        W.append([W[i-Nk][j] ^ temp[j] for j in range(4)])

    # Convert words to round key state matrices
    round_keys = []
    for rnd in range(Nr + 1):
        state = [[0]*4 for _ in range(4)]
        for c in range(4):
            word = W[rnd * 4 + c]
            for r in range(4):
                state[r][c] = word[r]
        round_keys.append(state)

    return round_keys


def _aes256_encrypt_block(block: bytes, round_keys: list) -> bytes:
    """Encrypt a single 16-byte block with AES-256."""
    state = _bytes_to_state(block)
    Nr = 14

    state = _add_round_key(state, round_keys[0])
    for rnd in range(1, Nr):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])

    # Final round (no MixColumns)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[Nr])

    return _state_to_bytes(state)


def _aes256_decrypt_block(block: bytes, round_keys: list) -> bytes:
    """Decrypt a single 16-byte block with AES-256."""
    state = _bytes_to_state(block)
    Nr = 14

    state = _add_round_key(state, round_keys[Nr])
    for rnd in range(Nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)

    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-CBC encryption with manual PKCS#7 padding.
    key:       32-byte AES key
    plaintext: arbitrary-length bytes
    Returns:   16-byte IV  ||  ciphertext
    """
    assert len(key) == 32, "AES-256 requires exactly 32-byte key"
    round_keys = _key_expansion_256(key)
    iv = secure_random_bytes(16)
    padded = pkcs7_pad(plaintext, 16)

    ciphertext = b''
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc = _aes256_encrypt_block(block, round_keys)
        ciphertext += enc
        prev = enc

    return iv + ciphertext


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """
    AES-256-CBC decryption with PKCS#7 unpadding.
    key:  32-byte AES key
    data: IV (16 bytes) || ciphertext
    Returns: plaintext bytes
    """
    assert len(key) == 32, "AES-256 requires exactly 32-byte key"
    assert len(data) >= 32, "Data too short (must include IV + at least one block)"
    round_keys = _key_expansion_256(key)
    iv = data[:16]
    ciphertext = data[16:]
    assert len(ciphertext) % 16 == 0, "Ciphertext length must be multiple of 16"

    plaintext = b''
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = _aes256_decrypt_block(block, round_keys)
        plaintext += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block

    return pkcs7_unpad(plaintext)


# ============================================================
# Password-Based Key Derivation
# ============================================================

def derive_key_from_password(password: str, salt: bytes = None):
    """
    Derive a 32-byte AES key from a password using iterated SHA-256.
    Returns (key_bytes, salt_bytes).
    """
    if salt is None:
        salt = secure_random_bytes(16)
    key_material = password.encode('utf-8') + salt
    for _ in range(100_000):
        key_material = sha256_bytes(key_material)
    return key_material[:32], salt


# ============================================================
# Canonical Message Encoding (for signing)
# ============================================================

def canonical_message(payload: dict) -> bytes:
    """
    Produce a deterministic, canonical byte encoding of a dict for signing.
    Uses sorted keys and compact JSON.
    """
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')


# ============================================================
# Integer / Hex / Bytes Conversion Utilities
# ============================================================

def int_to_hex(n: int) -> str:
    return format(n, 'x')


def hex_to_int(h: str) -> int:
    return int(h, 16)


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)


# ============================================================
# Message Framing (length-prefixed TCP protocol)
# ============================================================

def send_message(sock, payload: dict):
    """Send a JSON-encoded dict over a socket with 4-byte length prefix."""
    data = json.dumps(payload).encode('utf-8')
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)


def recv_message(sock) -> dict:
    """Receive a length-prefixed JSON message from a socket."""
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, 'big')
    data = _recv_exact(sock, msg_len)
    if not data:
        return None
    return json.loads(data.decode('utf-8'))


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ============================================================
# Ticket Helper Functions
# ============================================================

def create_tgt_payload(client_id: str, issue_timestamp: float,
                       lifetime: int, session_key_hex: str,
                       key_version: int = 1) -> dict:
    """Build a TGT payload dict."""
    return {
        "client_id": client_id,
        "service": "TGS",
        "issue_timestamp": int(issue_timestamp),
        "lifetime": lifetime,
        "session_key": session_key_hex,
        "key_version": key_version,
        "authority_metadata": {"cluster_size": 3, "threshold": 2},
    }


def create_service_ticket_payload(client_id: str, service_id: str,
                                   issue_timestamp: float, lifetime: int,
                                   service_session_key_hex: str,
                                   key_version: int = 1) -> dict:
    """Build a service ticket payload dict."""
    return {
        "client_id": client_id,
        "service_id": service_id,
        "issue_timestamp": int(issue_timestamp),
        "lifetime": lifetime,
        "service_session_key": service_session_key_hex,
        "key_version": key_version,
        "authority_metadata": {"cluster_size": 3, "threshold": 2},
    }
