#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Offline tool: convert bits/hex entropy into a BIP39 mnemonic.

Core cryptographic logic is delegated to wallet_core for consistency.
"""

import argparse
import sys
from pathlib import Path

import wallet_core as core

# Re-export for layering tests and safe shared usage.
entropy_to_mnemonic = core.entropy_to_mnemonic
is_hex = core.is_hex
VALID_ENTS = core.VALID_ENTS
VALID_NIBBLES = core.VALID_NIBBLES


def load_bits(args):
    if args.bits is not None:
        bits = args.bits.strip()
    elif args.bits_file is not None:
        path = Path(args.bits_file)
        if not path.exists():
            sys.exit(f"bits file not found: {path}")
        bits = path.read_text(encoding="utf-8").strip()
    else:
        return None

    if any(ch not in "01" for ch in bits):
        sys.exit("Bits must be only '0' or '1'")
    if len(bits) not in VALID_ENTS:
        sys.exit(f"Bit length must be one of {sorted(VALID_ENTS)}; got {len(bits)}")
    return bits


def load_hex(args):
    if args.hex is not None:
        hex_s = args.hex.strip().lower().removeprefix("0x")
    elif args.hex_file is not None:
        path = Path(args.hex_file)
        if not path.exists():
            sys.exit(f"hex file not found: {path}")
        hex_s = path.read_text(encoding="utf-8").strip().lower().removeprefix("0x")
    else:
        return None

    if not is_hex(hex_s):
        sys.exit("Hex must contain only [0-9a-f] (optionally prefixed by 0x).")
    if len(hex_s) not in VALID_NIBBLES:
        sys.exit(f"Hex length must be one of {sorted(VALID_NIBBLES)} nibbles; got {len(hex_s)}")
    return hex_s


def bits_to_hex(bits: str) -> str:
    return hex(int(bits, 2))[2:].zfill(len(bits) // 4)


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hex", help="hex string of length 32/40/48/56/64 nibbles")
    group.add_argument("--hex-file", help="path to a file containing a single hex string")
    group.add_argument("--bits", help="bit string of length 128/160/192/224/256")
    group.add_argument("--bits-file", help="path to a file containing a single line of bits")
    parser.add_argument("--wordlist", default="wordlist.txt", help="BIP39 wordlist path (default: wordlist.txt)")
    args = parser.parse_args()

    hex_s = load_hex(args)
    bits_s = load_bits(args)
    if hex_s is None:
        hex_s = bits_to_hex(bits_s)

    mnemonic = entropy_to_mnemonic(hex_s, args.wordlist)

    # Derive display values arithmetically (no duplicate crypto ops)
    ent_bits_len = len(hex_s) * 4
    cs_len = ent_bits_len // 32
    total_bits = ent_bits_len + cs_len
    wordlist = core.read_wordlist(args.wordlist)
    word_map = {w: i for i, w in enumerate(wordlist)}
    idxs = [word_map[w] for w in mnemonic.split()]

    print("=== BIP39 Conversion ===")
    print(f"ENT = {ent_bits_len} bits, CS = {cs_len} bits, Total = {total_bits} bits")
    print("Indexes (11-bit):")
    print(",".join(map(str, idxs)))
    print("\nMnemonic:")
    print(mnemonic)
    print("\nNotes: Keep this mnemonic OFFLINE. Consider an optional BIP39 passphrase (backup separately).")


if __name__ == "__main__":
    main()
