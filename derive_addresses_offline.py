#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Offline watch-only derivation tool:
- Input: BIP39 mnemonic (+ optional passphrase)
- Output:
  * BTC bech32 (BIP84, m/84'/0'/0'/0/i) addresses
  * ETH (BIP44, m/44'/60'/0'/0/i) addresses

This script intentionally delegates derivation logic to `wallet_core.py`
to avoid duplicate cryptographic implementations across tools.
"""

import argparse

from wallet_core import derive_btc_addresses, derive_eth_addresses, validate_mnemonic


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mnemonic", required=True, help="BIP39 mnemonic words")
    parser.add_argument("--passphrase", default="", help="BIP39 passphrase (optional)")
    parser.add_argument(
        "--btc-hrp",
        default="bc",
        help="bech32 HRP (mainnet=bc, testnet=tb)",
    )
    parser.add_argument("--btc-account", type=int, default=0)
    parser.add_argument("--btc-change", type=int, default=0)
    parser.add_argument("--btc-start", type=int, default=0)
    parser.add_argument(
        "--btc-count",
        type=int,
        default=0,
        help="how many BTC addresses to derive (0=skip)",
    )
    parser.add_argument("--eth-account", type=int, default=0)
    parser.add_argument("--eth-start", type=int, default=0)
    parser.add_argument(
        "--eth-count",
        type=int,
        default=0,
        help="how many ETH addresses to derive (0=skip)",
    )
    args = parser.parse_args()

    if args.btc_count == 0 and args.eth_count == 0:
        print("Nothing to do. Specify --btc-count and/or --eth-count > 0")
        return

    validate_mnemonic(args.mnemonic)

    if args.btc_count > 0:
        print("=== BTC (BIP84 P2WPKH) ===")
        btc = derive_btc_addresses(
            args.mnemonic,
            args.passphrase,
            account=args.btc_account,
            change=args.btc_change,
            start=args.btc_start,
            count=args.btc_count,
            hrp=args.btc_hrp,
        )
        for path, addr, cpub in btc:
            print(f"{path}  |  {addr}  |  pubkey(compressed)={cpub}")
        print()

    if args.eth_count > 0:
        print("=== ETH (BIP44) ===")
        eth = derive_eth_addresses(
            args.mnemonic,
            args.passphrase,
            account=args.eth_account,
            start=args.eth_start,
            count=args.eth_count,
        )
        for path, addr in eth:
            print(f"{path}  |  {addr}")


if __name__ == "__main__":
    main()
