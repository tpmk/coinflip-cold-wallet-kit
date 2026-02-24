#!/usr/bin/env python3
"""Shared cryptographic and derivation core for offline wallet tools."""

import hashlib
import hmac
import struct
import unicodedata
from pathlib import Path

# secp256k1 curve parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)

VALID_ENTS = {128, 160, 192, 224, 256}
VALID_NIBBLES = {e // 4 for e in VALID_ENTS}
MAX_NON_HARDENED_INDEX = 0x7FFFFFFF
MAX_BIP32_INDEX = 0xFFFFFFFF
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
PROJECT_DIR = Path(__file__).resolve().parent
# Reference source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
# Verified on 2026-02-24; pinning hash protects against silent local tampering.
BIP39_ENGLISH_WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

# RIPEMD-160 backend detection
try:
    hashlib.new("ripemd160")
    _HASHLIB_HAS_RIPEMD160 = True
except (ValueError, TypeError):
    _HASHLIB_HAS_RIPEMD160 = False

if not _HASHLIB_HAS_RIPEMD160:
    try:
        from Crypto.Hash import RIPEMD160 as _RIPEMD160
    except ImportError:
        _RIPEMD160 = None
else:
    _RIPEMD160 = None

# Keccak-256 backend detection
try:
    import sha3
except ImportError:
    sha3 = None

if sha3 is None:
    try:
        from Crypto.Hash import keccak as _keccak
    except ImportError:
        _keccak = None
else:
    _keccak = None


def ripemd160(data: bytes) -> bytes:
    if _HASHLIB_HAS_RIPEMD160:
        h = hashlib.new("ripemd160")
        h.update(data)
        return h.digest()
    if _RIPEMD160 is not None:
        h = _RIPEMD160.new()
        h.update(data)
        return h.digest()
    raise RuntimeError(
        "RIPEMD-160 backend not available. Install pycryptodome: pip install pycryptodome"
    )


def keccak_256(data: bytes) -> bytes:
    if sha3 is not None:
        h = sha3.keccak_256()
        h.update(data)
        return h.digest()
    if _keccak is not None:
        return _keccak.new(digest_bits=256, data=data).digest()
    raise RuntimeError(
        "Keccak-256 backend not available. Install pysha3 or pycryptodome: pip install pycryptodome"
    )


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def pbkdf2_hmac_sha512(password: bytes, salt: bytes, iterations=2048) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=64)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


def int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, byteorder="big")


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def ser256(i: int) -> bytes:
    return int_to_bytes(i, 32)


def _require_index_range(name: str, value: int, upper: int = MAX_NON_HARDENED_INDEX) -> None:
    if value < 0 or value > upper:
        raise ValueError(f"{name} must be between 0 and {upper}, got {value}")


def point_add(pt, qt):
    if pt is None:
        return qt
    if qt is None:
        return pt

    x1, y1 = pt
    x2, y2 = qt

    if x1 == x2 and y1 != y2:
        return None
    if pt == qt:
        if y1 == 0:
            return None
        m = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        if x1 == x2:
            return None
        m = (y2 - y1) * pow(x2 - x1, P - 2, P) % P

    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k: int, pt):
    if k % N == 0 or pt is None:
        return None
    result = None
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def serP(pt, compressed=True) -> bytes:
    x, y = pt
    if not compressed:
        return b"\x04" + ser256(x) + ser256(y)
    return (b"\x02" if (y % 2 == 0) else b"\x03") + ser256(x)


def read_wordlist(wordlist_path="wordlist.txt"):
    path = Path(wordlist_path).expanduser()
    if not path.is_absolute() and not path.exists():
        path = PROJECT_DIR / path
    if not path.exists():
        raise FileNotFoundError(
            f"Wordlist file not found: {path}\n"
            "Please ensure wordlist.txt (2048 English words) exists."
        )
    raw = path.read_bytes()
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != BIP39_ENGLISH_WORDLIST_SHA256:
        raise ValueError(
            "Wordlist SHA256 mismatch. "
            f"expected={BIP39_ENGLISH_WORDLIST_SHA256}, got={actual_hash}"
        )
    words = [w.strip() for w in raw.decode("utf-8").splitlines() if w.strip()]
    if len(words) != 2048:
        raise ValueError(f"Wordlist must have exactly 2048 words, got {len(words)}")
    return words


def is_hex(s: str) -> bool:
    if not s:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in s)


def bits_from_hex(hex_str: str) -> str:
    hex_str = hex_str.lower().removeprefix("0x")
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    data = bytes.fromhex(hex_str)
    ent_bits_len = len(hex_str) * 4
    bit_str = "".join(bin(b)[2:].zfill(8) for b in data)
    return bit_str[-ent_bits_len:]


def add_checksum(ent_bits: str) -> str:
    ent_len = len(ent_bits)
    cs_len = ent_len // 32
    ent_bytes = int(ent_bits, 2).to_bytes((ent_len + 7) // 8, "big")
    hash_bytes = sha256(ent_bytes)
    cs_bits = bin(hash_bytes[0])[2:].zfill(8)[:cs_len]
    return ent_bits + cs_bits


def split_to_11(full_bits: str):
    return [int(full_bits[i : i + 11], 2) for i in range(0, len(full_bits), 11)]


def entropy_to_mnemonic(hex_entropy: str, wordlist_path="wordlist.txt") -> str:
    hex_entropy = hex_entropy.strip().lower().removeprefix("0x")
    if not is_hex(hex_entropy):
        raise ValueError("Invalid hex string")
    if len(hex_entropy) not in VALID_NIBBLES:
        raise ValueError(f"Hex entropy must be {sorted(VALID_NIBBLES)} characters, got {len(hex_entropy)}")

    wordlist = read_wordlist(wordlist_path)
    ent_bits = bits_from_hex(hex_entropy)
    full_bits = add_checksum(ent_bits)
    if len(full_bits) % 11 != 0:
        raise ValueError("Full bit string is not divisible by 11")
    indices = split_to_11(full_bits)
    return " ".join(wordlist[idx] for idx in indices)


def validate_mnemonic(mnemonic: str, wordlist_path="wordlist.txt") -> None:
    """Validate a BIP39 mnemonic: word count, wordlist membership, and checksum."""
    wordlist = read_wordlist(wordlist_path)
    word_map = {w: i for i, w in enumerate(wordlist)}
    words = unicodedata.normalize("NFKD", mnemonic.strip()).split()

    valid_word_counts = {12, 15, 18, 21, 24}
    if len(words) not in valid_word_counts:
        raise ValueError(
            f"Mnemonic must be {sorted(valid_word_counts)} words, got {len(words)}"
        )

    indices = []
    for i, w in enumerate(words):
        if w not in word_map:
            raise ValueError(f"Word #{i + 1} '{w}' is not in the BIP39 wordlist")
        indices.append(word_map[w])

    # Reconstruct bits and verify checksum
    bits = "".join(bin(idx)[2:].zfill(11) for idx in indices)
    total_bits = len(bits)
    cs_len = total_bits // 33  # CS = ENT / 32, total = ENT + CS = 33 * CS
    ent_len = total_bits - cs_len

    ent_bits = bits[:ent_len]
    cs_bits = bits[ent_len:]

    ent_bytes = int(ent_bits, 2).to_bytes(ent_len // 8, "big")
    expected_cs = bin(sha256(ent_bytes)[0])[2:].zfill(8)[:cs_len]

    if cs_bits != expected_cs:
        raise ValueError("Mnemonic checksum mismatch — possible typo")


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic_normalized = unicodedata.normalize("NFKD", mnemonic.strip())
    passphrase_normalized = unicodedata.normalize("NFKD", passphrase)
    salt = ("mnemonic" + passphrase_normalized).encode("utf-8")
    return pbkdf2_hmac_sha512(mnemonic_normalized.encode("utf-8"), salt, iterations=2048)


def bip32_master_key(seed: bytes):
    i = hmac_sha512(b"Bitcoin seed", seed)
    il, ir = i[:32], i[32:]
    il_int = bytes_to_int(il)
    if il_int >= N:
        raise ValueError("Invalid master key: parse256(IL) >= n (BIP32 spec)")
    if il_int == 0:
        raise ValueError("Invalid master key (zero)")
    pub = scalar_mult(il_int, G)
    return il_int, pub, ir


def ckd_priv(k_parent: int, c_parent: bytes, index: int):
    """BIP32 child key derivation (private).

    Spec deviation: BIP32 says if parse256(IL) >= n or ki == 0, proceed
    with the next index.  We raise ValueError instead because the
    probability is ~1/2^128 and silently skipping to a different index
    would change the derived path without the caller's knowledge.
    """
    hardened = index >= 0x80000000
    if hardened:
        data = b"\x00" + ser256(k_parent) + struct.pack(">L", index)
    else:
        p_parent = scalar_mult(k_parent, G)
        data = serP(p_parent, compressed=True) + struct.pack(">L", index)

    i = hmac_sha512(c_parent, data)
    il, ir = i[:32], i[32:]
    il_int = bytes_to_int(il)
    if il_int >= N:
        raise ValueError("Invalid child key: parse256(IL) >= n (BIP32 spec)")
    k_child = (il_int + k_parent) % N
    if k_child == 0:
        raise ValueError("Derived zero key")
    return k_child, ir


def derive_priv_path(k: int, c: bytes, path: str):
    if path in ("m", "M", ""):
        return k, c
    if not path.startswith("m/"):
        raise ValueError("Path must start with m/")

    segments = path[2:].split("/")
    k_current, c_current = k, c
    for seg in segments:
        if seg.endswith("'"):
            raw_idx = int(seg[:-1])
            _require_index_range("hardened index", raw_idx)
            idx = raw_idx | 0x80000000
        else:
            idx = int(seg)
            _require_index_range("non-hardened index", idx)
        _require_index_range("BIP32 index", idx, upper=MAX_BIP32_INDEX)
        k_current, c_current = ckd_priv(k_current, c_current, idx)
    return k_current, c_current


def bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xFF
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in combined)


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode_segwit_address(hrp, witver, witprog):
    ret = convertbits(witprog, 8, 5)
    if ret is None:
        raise ValueError("convertbits failed: invalid witness program")
    data = [witver] + ret
    return bech32_encode(hrp, data)


def btc_p2wpkh_address(pubkey_compressed: bytes, hrp="bc") -> str:
    h160 = hash160(pubkey_compressed)
    return encode_segwit_address(hrp, 0, h160)


def eip55_checksum(hex_addr: str) -> str:
    h = keccak_256(hex_addr.encode("ascii")).hex()
    out = ""
    for c, hv in zip(hex_addr, h):
        if c in "0123456789":
            out += c
        else:
            out += c.upper() if int(hv, 16) >= 8 else c.lower()
    return out


def eth_address(pubkey_uncompressed: bytes) -> str:
    if pubkey_uncompressed[0] != 0x04:
        raise ValueError("Must be uncompressed pubkey (0x04 prefix)")
    ke = keccak_256(pubkey_uncompressed[1:])
    addr_bytes = ke[-20:]
    return "0x" + eip55_checksum(addr_bytes.hex())


def derive_pubkey_at(mnemonic: str, passphrase: str, path: str):
    seed = mnemonic_to_seed(mnemonic, passphrase)
    k_master, _, c_master = bip32_master_key(seed)
    k, _ = derive_priv_path(k_master, c_master, path)
    return scalar_mult(k, G)


def derive_btc_addresses(
    mnemonic: str,
    passphrase: str = "",
    account: int = 0,
    change: int = 0,
    start: int = 0,
    count: int = 5,
    hrp: str = "bc",
    coin_type: int | None = None,
):
    if coin_type is None:
        if hrp == "bc":
            coin_type = 0
        elif hrp == "tb":
            coin_type = 1
        else:
            raise ValueError("Unsupported hrp for default coin type; use bc/tb or set coin_type")

    _require_index_range("coin_type", coin_type)
    _require_index_range("account", account)
    _require_index_range("change", change)
    _require_index_range("start", start)
    if count < 0:
        raise ValueError(f"count must be >= 0, got {count}")
    if count > 0:
        _require_index_range("last index", start + count - 1)

    results = []
    for i in range(start, start + count):
        path = f"m/84'/{coin_type}'/{account}'/{change}/{i}"
        point = derive_pubkey_at(mnemonic, passphrase, path)
        pubkey_compressed = serP(point, compressed=True)
        address = btc_p2wpkh_address(pubkey_compressed, hrp=hrp)
        results.append((path, address, pubkey_compressed.hex()))
    return results


def derive_eth_addresses(
    mnemonic: str,
    passphrase: str = "",
    account: int = 0,
    start: int = 0,
    count: int = 5,
):
    _require_index_range("account", account)
    _require_index_range("start", start)
    if count < 0:
        raise ValueError(f"count must be >= 0, got {count}")
    if count > 0:
        _require_index_range("last index", start + count - 1)

    results = []
    for i in range(start, start + count):
        path = f"m/44'/60'/{account}'/0/{i}"
        point = derive_pubkey_at(mnemonic, passphrase, path)
        pubkey_uncompressed = serP(point, compressed=False)
        address = eth_address(pubkey_uncompressed)
        results.append((path, address))
    return results


__all__ = [
    "entropy_to_mnemonic",
    "mnemonic_to_seed",
    "validate_mnemonic",
    "derive_btc_addresses",
    "derive_eth_addresses",
    "derive_pubkey_at",
    "is_hex",
    "ripemd160",
    "keccak_256",
]
