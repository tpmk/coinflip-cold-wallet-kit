# Security Audit: CoinFlip Cold Wallet Kit

Date: 2026-02-24

## Scope

Full security audit of all source files: `wallet_core.py`, `coin_flip_wallet.py`,
`coin_to_bip39_hex.py`, `derive_addresses_offline.py`, tests, and configuration.

## Findings

### P0 - Spec Deviation (Cryptographic Correctness)

**F-01: BIP32 master key generation missing `IL >= N` check**
- File: `wallet_core.py:232`
- BIP32 spec requires: if `parse256(IL) >= n`, the master key is invalid.
- Code uses `bytes_to_int(il) % N`, which silently wraps instead of rejecting.
- Probability: ~1/2^128, but spec compliance matters for correctness claims.

**F-02: CKD child key derivation missing `IL >= N` check**
- File: `wallet_core.py:249`
- BIP32 CKD spec: if `parse256(IL) >= n` or `ki = 0`, skip index and increment.
- Code checks zero but not the `IL >= N` condition.

### P1 - Code Bugs

**F-03: `path.lstrip("m/")` strips character set, not substring**
- File: `wallet_core.py:261`
- `lstrip("m/")` removes any leading `m` or `/` characters individually.
- Standard paths happen to work, but semantics are wrong.
- Fix: use `path.removeprefix("m/")` or `path[2:]`.

**F-04: `is_hex()` accepts negative numbers**
- File: `wallet_core.py:175-180`
- `int("-ff", 16)` succeeds, so `is_hex("-ff")` returns True.
- Length checks downstream catch this, but the validator itself is incorrect.

### P2 - Security Hardening

**F-05: No mnemonic validation in derive_addresses_offline.py**
- Accepts any string as mnemonic without BIP39 wordlist or checksum verification.
- Typos in mnemonic lead to silent derivation of wrong addresses.

**F-06: Non-constant-time scalar multiplication**
- File: `wallet_core.py:134-144`
- Standard double-and-add leaks key bits via timing.
- Acceptable for offline single-use, but noted.

**F-07: Passphrase visible in process list and shell history**
- `--passphrase` argument appears in `ps` output and `.bash_history`.
- Document risk; consider stdin-based passphrase input.

**F-08: Python cannot guarantee memory zeroing**
- Private keys remain in GC-managed memory.
- Acceptable for offline tool; document limitation.

### P3 - Improvements

**F-09: `bip39-standalone.html` provenance undocumented**
- Large third-party file with no recorded source, version, or integrity hash.

**F-10: Test coverage gaps**
- No end-to-end BTC address test vector (mnemonic -> known bech32 address).
- No end-to-end ETH address test vector (mnemonic -> known EIP-55 address).
- No edge-case tests for `derive_priv_path`, `scalar_mult`, `point_add`.

**F-11: `VALID_NIBBLES` set ordering in error message**
- `wallet_core.py:211` - set printed with unpredictable order.
- Use `sorted()` for deterministic, user-friendly output.

## Remediation Plan

### Phase 1: P0 + P1 fixes (wallet_core.py)

1. Add `IL >= N` guard in `bip32_master_key()` - raise ValueError.
2. Add `IL >= N` guard in `ckd_priv()` - raise ValueError per BIP32 spec.
3. Replace `path.lstrip("m/")` with `path[2:]`.
4. Fix `is_hex()` to reject strings containing non-hex characters (e.g., `-`).
5. Fix `VALID_NIBBLES` error message to use `sorted()`.

### Phase 2: P2 security hardening

6. Add `validate_mnemonic()` function in wallet_core.py.
7. Call it in `derive_addresses_offline.py` before derivation.
8. Add passphrase security note in README.

### Phase 3: P3 test coverage

9. Add BTC address end-to-end test vector.
10. Add ETH address end-to-end test vector.
11. Add `derive_priv_path` edge-case tests.
12. Document `bip39-standalone.html` provenance in README.

## Audit Verdict

**PASS with caveats** - suitable for educational/offline use after remediation.
