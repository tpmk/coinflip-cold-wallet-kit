#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Offline watch-only derivation tool:
- Input: BIP39 mnemonic (+ optional passphrase)
- Output:
  * BTC bech32 (BIP84, mainnet m/84'/0'/..., testnet m/84'/1'/...) addresses
  * ETH (BIP44, m/44'/60'/0'/0/i) addresses

This script intentionally delegates derivation logic to `wallet_core.py`
to avoid duplicate cryptographic implementations across tools.
"""

import argparse
import getpass
import sys

from wallet_core import derive_btc_addresses, derive_eth_addresses, validate_mnemonic

UINT31_MAX = 0x7FFFFFFF


def uint31_arg(flag_name: str):
    def _parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{flag_name} must be an integer") from exc
        if parsed < 0 or parsed > UINT31_MAX:
            raise argparse.ArgumentTypeError(
                f"{flag_name} must be between 0 and {UINT31_MAX}"
            )
        return parsed

    return _parse


def non_negative_arg(flag_name: str):
    def _parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{flag_name} must be an integer") from exc
        if parsed < 0:
            raise argparse.ArgumentTypeError(f"{flag_name} must be >= 0")
        return parsed

    return _parse


def resolve_passphrase(args, parser: argparse.ArgumentParser) -> str:
    if args.passphrase_stdin:
        if sys.stdin.isatty():
            parser.error("--passphrase-stdin requires piped stdin input")
        return sys.stdin.readline().rstrip("\r\n")
    if args.passphrase_prompt:
        return getpass.getpass("Enter BIP39 passphrase (leave empty for none): ")
    if args.passphrase is not None:
        print(
            "WARNING: --passphrase is visible in process list and shell history. "
            "Prefer --passphrase-stdin or --passphrase-prompt.",
            file=sys.stderr,
        )
        return args.passphrase
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mnemonic", required=True, help="BIP39 mnemonic words")
    passphrase_group = parser.add_mutually_exclusive_group()
    passphrase_group.add_argument(
        "--passphrase",
        default=None,
        help=(
            "BIP39 passphrase (HIGH RISK: visible in process list and shell history; "
            "prefer --passphrase-stdin or --passphrase-prompt)"
        ),
    )
    passphrase_group.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="Read BIP39 passphrase from stdin (recommended for scripts)",
    )
    passphrase_group.add_argument(
        "--passphrase-prompt",
        action="store_true",
        help="Prompt passphrase with hidden input (recommended for interactive use)",
    )
    parser.add_argument(
        "--btc-hrp",
        default="bc",
        choices=("bc", "tb"),
        help="bech32 HRP (mainnet=bc, testnet=tb)",
    )
    parser.add_argument("--btc-account", type=uint31_arg("--btc-account"), default=0)
    parser.add_argument("--btc-change", type=uint31_arg("--btc-change"), default=0)
    parser.add_argument("--btc-start", type=uint31_arg("--btc-start"), default=0)
    parser.add_argument(
        "--btc-count",
        type=non_negative_arg("--btc-count"),
        default=0,
        help="how many BTC addresses to derive (0=skip)",
    )
    parser.add_argument("--eth-account", type=uint31_arg("--eth-account"), default=0)
    parser.add_argument("--eth-start", type=uint31_arg("--eth-start"), default=0)
    parser.add_argument(
        "--eth-count",
        type=non_negative_arg("--eth-count"),
        default=0,
        help="how many ETH addresses to derive (0=skip)",
    )
    args = parser.parse_args()
    passphrase = resolve_passphrase(args, parser)

    if args.btc_count == 0 and args.eth_count == 0:
        print("Nothing to do. Specify --btc-count and/or --eth-count > 0")
        return

    try:
        validate_mnemonic(args.mnemonic)

        if args.btc_count > 0:
            print("=== BTC (BIP84 P2WPKH) ===")
            btc = derive_btc_addresses(
                args.mnemonic,
                passphrase,
                account=args.btc_account,
                change=args.btc_change,
                start=args.btc_start,
                count=args.btc_count,
                hrp=args.btc_hrp,
                coin_type=0 if args.btc_hrp == "bc" else 1,
            )
            for path, addr, cpub in btc:
                print(f"{path}  |  {addr}  |  pubkey(compressed)={cpub}")
            print()

        if args.eth_count > 0:
            print("=== ETH (BIP44) ===")
            eth = derive_eth_addresses(
                args.mnemonic,
                passphrase,
                account=args.eth_account,
                start=args.eth_start,
                count=args.eth_count,
            )
            for path, addr in eth:
                print(f"{path}  |  {addr}")
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
