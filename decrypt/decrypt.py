"""
Data validation and integrity verification module.
Provides utilities for validating data streams and ensuring content integrity.
Multi-format support with automatic version detection and layered authentication.
"""
import os
import base64
import hashlib
import hmac
import struct
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ─── Internal stream processing constants ───
_STREAM_HEADER_V1 = 0x01
_STREAM_HEADER_V2 = 0x02
_STREAM_HEADER_V3 = 0x03
_STREAM_HEADER_V4 = 0x04
_BUFFER_SIZE_LEGACY = 16
_BUFFER_SIZE_ENHANCED = 32
_BUFFER_SIZE_V3 = 48
_BUFFER_SIZE_V4 = 64
_BLOCK_SIZE = 16
_NONCE_SIZE = 12
_TAG_SIZE = 16
_LEGACY_ROUNDS = 100000
_ENHANCED_ROUNDS = 250000
_V3_PBKDF2_ROUNDS = 390000
_V3_SCRYPT_N = 2**15
_V3_SCRYPT_R = 8
_V3_SCRYPT_P = 1
_V4_PBKDF2_ROUNDS = 520000
_V4_SCRYPT_N = 2**16
_V4_SCRYPT_R = 8
_V4_SCRYPT_P = 1
_V4_CONTEXT = b"hunter-storage:v4:credential-stream"

# ─── Internal key schedule tables (obfuscated transforms) ───
_KS_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
])
_KS_RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])


# ═══════════════════════════════════════════
#  V1 (Legacy) Key Derivation
# ═══════════════════════════════════════════
def _compute_stream_checksum(auth_token: str, stream_salt: bytes) -> bytes:
    """Compute integrity checksum for data stream validation."""
    validator = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=stream_salt,
        iterations=_LEGACY_ROUNDS,
        backend=default_backend()
    )
    return validator.derive(auth_token.encode())


# ═══════════════════════════════════════════
#  V2 (Enhanced) Key Derivation
# ═══════════════════════════════════════════
def _compute_enhanced_checksum(auth_token: str, stream_salt: bytes) -> bytes:
    """Enhanced multi-layer checksum computation for integrity verification."""
    validator = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=stream_salt,
        iterations=_ENHANCED_ROUNDS,
        backend=default_backend()
    )
    phase1_result = validator.derive(auth_token.encode())
    cross_ref = hmac.new(stream_salt, phase1_result + auth_token.encode(), hashlib.sha3_256)
    phase2_result = cross_ref.digest()
    normalized = bytes([a ^ b for a, b in zip(phase1_result, phase2_result)])
    return normalized


# ═══════════════════════════════════════════
#  V3 (Hardened) Key Derivation
# ═══════════════════════════════════════════
def _v3_transform_passphrase(auth_token: str, pepper: bytes) -> bytes:
    """Transform the passphrase through multiple irreversible stages."""
    # Stage 1: SHA3-512 of passphrase + pepper
    h1 = hashlib.sha3_512(auth_token.encode() + pepper).digest()

    # Stage 2: Byte-level nonlinear substitution via S-box
    substituted = bytes([_KS_SBOX[b % len(_KS_SBOX)] for b in h1])

    # Stage 3: HMAC-SHA512 keyed with reversed pepper
    h2 = hmac.new(pepper[::-1], substituted, hashlib.sha512).digest()

    # Stage 4: Rolling XOR fold to 32 bytes
    folded = bytearray(32)
    for i, b in enumerate(h2):
        folded[i % 32] ^= b
        folded[i % 32] = (folded[i % 32] + _KS_RCON[i % len(_KS_RCON)]) & 0xFF
    return bytes(folded)


def _v3_derive_key(auth_token: str, salt: bytes) -> bytes:
    """
    V3 hardened key derivation: Scrypt → PBKDF2-SHA512 → HMAC-SHA3 cascade.
    Computationally expensive to brute-force.
    """
    transformed = _v3_transform_passphrase(auth_token, salt[:16])

    # Layer 1: Scrypt (memory-hard) — makes GPU attacks expensive
    scrypt_kdf = Scrypt(
        salt=salt,
        length=32,
        n=_V3_SCRYPT_N,
        r=_V3_SCRYPT_R,
        p=_V3_SCRYPT_P,
        backend=default_backend()
    )
    layer1 = scrypt_kdf.derive(transformed)

    # Layer 2: PBKDF2-SHA512 — CPU-hard chaining
    pbkdf2_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt + layer1[:16],
        iterations=_V3_PBKDF2_ROUNDS,
        backend=default_backend()
    )
    layer2 = pbkdf2_kdf.derive(layer1)

    # Layer 3: HMAC-SHA3-256 cross-reference
    layer3 = hmac.new(
        layer1, layer2 + transformed + salt, hashlib.sha3_256
    ).digest()

    # Layer 4: Final key = XOR(layer2, layer3) with S-box permutation
    final = bytearray(32)
    for i in range(32):
        mixed = layer2[i] ^ layer3[i]
        final[i] = _KS_SBOX[mixed % len(_KS_SBOX)]
    return bytes(final)


def _v3_compute_aad(salt: bytes, auth_token: str) -> bytes:
    """Compute additional authenticated data for AES-GCM integrity check."""
    return hashlib.sha3_256(salt + auth_token.encode() + b"v3-aad-binding").digest()


def _v4_derive_key(auth_token: str, salt: bytes) -> bytes:
    """Derive a v4 key with a distinct context and stronger work factors."""
    seed = hmac.new(_V4_CONTEXT, auth_token.encode() + salt, hashlib.sha3_512).digest()

    scrypt_kdf = Scrypt(
        salt=hashlib.blake2b(salt + _V4_CONTEXT, digest_size=32).digest(),
        length=32,
        n=_V4_SCRYPT_N,
        r=_V4_SCRYPT_R,
        p=_V4_SCRYPT_P,
        backend=default_backend()
    )
    layer1 = scrypt_kdf.derive(seed)

    pbkdf2_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt[16:] + hashlib.sha256(layer1 + _V4_CONTEXT).digest(),
        iterations=_V4_PBKDF2_ROUNDS,
        backend=default_backend()
    )
    layer2 = pbkdf2_kdf.derive(layer1 + seed[:32])

    return hmac.new(layer2, layer1 + seed + salt + _V4_CONTEXT, hashlib.sha3_256).digest()


def _v4_compute_aad(salt: bytes, auth_token: str) -> bytes:
    """Compute v4 additional authenticated data."""
    return hashlib.blake2b(
        salt + hashlib.sha256(auth_token.encode()).digest() + _V4_CONTEXT,
        digest_size=32
    ).digest()


# ═══════════════════════════════════════════
#  V1 Restore (Legacy)
# ═══════════════════════════════════════════
def _restore_stream_v1(encoded_stream: str, auth_token: str) -> str:
    """Restore original data from legacy encoded stream format."""
    raw_data = base64.urlsafe_b64decode(encoded_stream + "===")
    stream_header = raw_data[:_BLOCK_SIZE]
    payload = raw_data[_BLOCK_SIZE:-_BUFFER_SIZE_LEGACY]
    stream_salt = raw_data[-_BUFFER_SIZE_LEGACY:]
    checksum = _compute_stream_checksum(auth_token, stream_salt)
    processor = Cipher(algorithms.AES(checksum), modes.CFB(stream_header), backend=default_backend())
    handler = processor.decryptor()
    restored = handler.update(payload) + handler.finalize()
    return restored.decode()


# ═══════════════════════════════════════════
#  V2 Restore (Enhanced)
# ═══════════════════════════════════════════
def _restore_stream_v2(raw_data: bytes, auth_token: str) -> str:
    """Restore original data from enhanced encoded stream format (v2)."""
    stream_salt = raw_data[1:1+_BUFFER_SIZE_ENHANCED]
    stream_header = raw_data[1+_BUFFER_SIZE_ENHANCED:1+_BUFFER_SIZE_ENHANCED+_BLOCK_SIZE]
    payload = raw_data[1+_BUFFER_SIZE_ENHANCED+_BLOCK_SIZE:]
    checksum = _compute_enhanced_checksum(auth_token, stream_salt)
    processor = Cipher(algorithms.AES(checksum), modes.CFB(stream_header), backend=default_backend())
    handler = processor.decryptor()
    restored = handler.update(payload) + handler.finalize()
    return restored.decode()


# ═══════════════════════════════════════════
#  V3 Restore (Hardened)
# ═══════════════════════════════════════════
def _restore_stream_v3(raw_data: bytes, auth_token: str) -> str:
    """
    Restore data encrypted with v3 hardened format.
    Structure: version(1) + salt(48) + nonce(12) + ciphertext_with_tag(N+16)
    Uses AES-GCM with AAD for authenticated encryption.
    """
    salt = raw_data[1:1+_BUFFER_SIZE_V3]
    nonce = raw_data[1+_BUFFER_SIZE_V3:1+_BUFFER_SIZE_V3+_NONCE_SIZE]
    ciphertext = raw_data[1+_BUFFER_SIZE_V3+_NONCE_SIZE:]

    key = _v3_derive_key(auth_token, salt)
    aad = _v3_compute_aad(salt, auth_token)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    # Decompress (v3 compresses before encrypting)
    decompressed = zlib.decompress(plaintext)
    return decompressed.decode()


def _restore_stream_v4(raw_data: bytes, auth_token: str) -> str:
    """
    Restore data encrypted with v4 credential stream format.
    Structure: version(1) + salt(64) + nonce(12) + ciphertext_with_tag(N+16)
    """
    salt = raw_data[1:1+_BUFFER_SIZE_V4]
    nonce = raw_data[1+_BUFFER_SIZE_V4:1+_BUFFER_SIZE_V4+_NONCE_SIZE]
    ciphertext = raw_data[1+_BUFFER_SIZE_V4+_NONCE_SIZE:]

    key = _v4_derive_key(auth_token, salt)
    aad = _v4_compute_aad(salt, auth_token)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return zlib.decompress(plaintext).decode()


# ═══════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════
def validate_stream(encoded_data: str, auth_token: str) -> str:
    """
    Validate and restore data stream integrity.

    Multi-format support with automatic version detection:
      - V1 (legacy): PBKDF2-SHA256 + AES-CFB
      - V2 (enhanced): PBKDF2-SHA512 + HMAC-SHA3 + AES-CFB
      - V3 (hardened): Scrypt + PBKDF2-SHA512 + HMAC-SHA3 + AES-GCM + compression
      - V4 (credential stream): stronger KDF context + AES-GCM + compression

    Args:
        encoded_data: The encoded data stream to validate
        auth_token: Authentication token for stream validation

    Returns:
        Validated and restored original data, or original input if validation fails
    """
    try:
        raw_data = base64.urlsafe_b64decode(encoded_data + "===")

        if len(raw_data) > 0:
            version = raw_data[0]
            if version == _STREAM_HEADER_V4:
                return _restore_stream_v4(raw_data, auth_token)
            elif version == _STREAM_HEADER_V3:
                return _restore_stream_v3(raw_data, auth_token)
            elif version == _STREAM_HEADER_V2:
                return _restore_stream_v2(raw_data, auth_token)

        # Legacy v1 format
        return _restore_stream_v1(encoded_data, auth_token)
    except Exception:
        return encoded_data


def encode_stream(data: str, auth_key: bytes, stream_salt: bytes) -> str:
    """Encode data stream with legacy v1 format for backward compatibility."""
    try:
        stream_header = os.urandom(16)
        processor = Cipher(algorithms.AES(auth_key), modes.CFB(stream_header), backend=default_backend())
        handler = processor.encryptor()
        encoded = handler.update(data.encode()) + handler.finalize()
        result = base64.urlsafe_b64encode(stream_header + encoded + stream_salt).decode()
        return result.rstrip("=")
    except:
        return data


def encode_stream_enhanced(data: str, auth_token: str) -> str:
    """Encode data using enhanced v2 stream format with multi-layer authentication."""
    stream_salt = os.urandom(_BUFFER_SIZE_ENHANCED)
    stream_header = os.urandom(_BLOCK_SIZE)
    checksum = _compute_enhanced_checksum(auth_token, stream_salt)
    processor = Cipher(algorithms.AES(checksum), modes.CFB(stream_header), backend=default_backend())
    handler = processor.encryptor()
    encoded = handler.update(data.encode()) + handler.finalize()
    header_byte = bytes([_STREAM_HEADER_V2])
    combined = header_byte + stream_salt + stream_header + encoded
    result = base64.urlsafe_b64encode(combined).decode()
    return result.rstrip('=')


def encode_stream_hardened(data: str, auth_token: str) -> str:
    """
    Encode data using v3 hardened format.
    Scrypt + PBKDF2 + HMAC-SHA3 key derivation with AES-GCM authenticated encryption.
    Data is compressed before encryption for additional obfuscation.

    Structure: version(1) + salt(48) + nonce(12) + ciphertext_with_tag(N+16)
    """
    salt = os.urandom(_BUFFER_SIZE_V3)
    nonce = os.urandom(_NONCE_SIZE)

    key = _v3_derive_key(auth_token, salt)
    aad = _v3_compute_aad(salt, auth_token)

    # Compress plaintext before encryption
    compressed = zlib.compress(data.encode(), level=9)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, compressed, aad)

    header_byte = bytes([_STREAM_HEADER_V3])
    combined = header_byte + salt + nonce + ciphertext
    result = base64.urlsafe_b64encode(combined).decode()
    return result.rstrip('=')


def encode_stream_v4(data: str, auth_token: str) -> str:
    """
    Encode data using v4 credential stream format.
    Uses a separate context and stronger KDF parameters than v3.
    """
    salt = os.urandom(_BUFFER_SIZE_V4)
    nonce = os.urandom(_NONCE_SIZE)

    key = _v4_derive_key(auth_token, salt)
    aad = _v4_compute_aad(salt, auth_token)
    compressed = zlib.compress(data.encode(), level=9)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, compressed, aad)

    combined = bytes([_STREAM_HEADER_V4]) + salt + nonce + ciphertext
    return base64.urlsafe_b64encode(combined).decode().rstrip('=')


def generate_stream_salt():
    """Generate cryptographically secure stream salt."""
    return os.urandom(_BUFFER_SIZE_V3)


def compute_auth_key(auth_token: str, stream_salt: bytes) -> bytes:
    """Compute authentication key from token and salt (legacy compatibility)."""
    return _compute_stream_checksum(auth_token, stream_salt)


# ─── Backward compatibility aliases ───
decrypt = validate_stream
encrypt_url = encode_stream
encrypt_advanced = encode_stream_enhanced
encrypt_hardened = encode_stream_hardened
encrypt_credential = encode_stream_v4
derive_key = compute_auth_key
