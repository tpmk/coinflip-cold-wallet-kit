# Security Audit v2: CoinFlip Cold Wallet Kit

Date: 2026-02-24
Auditor: Claude Opus 4.6
Scope: Full incremental audit — verify prior fixes + discover new issues

## Prior Audit Fix Verification (F-01 to F-11)

| ID | Issue | Status | Notes |
|----|-------|--------|-------|
| F-01 | `bip32_master_key` missing `IL >= N` check | **Fixed** | `wallet_core.py:265-266`, raises ValueError |
| F-02 | `ckd_priv` missing `IL >= N` check | **Fixed** | `wallet_core.py:284-285`, raises ValueError |
| F-03 | `path.lstrip("m/")` char-set strip | **Fixed** | `wallet_core.py:298`, uses `path[2:]` |
| F-04 | `is_hex()` accepts negatives | **Fixed** | `wallet_core.py:175-178`, whitelist approach |
| F-05 | No mnemonic validation | **Fixed** | `wallet_core.py:220-251`, full BIP39 validation |
| F-06 | Non-constant-time scalar mult | **Documented** | Acceptable for offline use |
| F-07 | Passphrase in process list | **Documented** | Needs stdin-based input |
| F-08 | No memory zeroing in Python | **Documented** | Language limitation |
| F-09 | `bip39-standalone.html` provenance | **NOT FIXED** | Still no hash/version/source |
| F-10 | Test coverage gaps | **Fixed** | BTC/ETH e2e test vectors added |
| F-11 | VALID_NIBBLES sort order | **Fixed** | Uses `sorted()` |

## New Findings

### P1 — Code Bugs (Should Fix)

**N-01: `convertbits()` return value unchecked**
- File: `wallet_core.py:358`
- `encode_segwit_address`: `data = [witver] + convertbits(witprog, 8, 5)`
- `convertbits()` returns `None` on invalid input → `TypeError` on list concat
- Currently safe (always called with valid `hash160` output), but no defensive check
- Fix: check for `None` return, raise `ValueError`

**N-02: `read_wordlist()` reads file twice — TOCTOU race**
- File: `wallet_core.py:163` and `169`
- First `read_bytes()` for SHA256, then `read_text()` for content
- File could be swapped between reads (bypasses integrity check)
- Fix: read bytes once, verify hash, then decode

**N-03: `ckd_priv` does not implement BIP32 "try next index" semantics**
- File: `wallet_core.py:284-288`
- BIP32 spec: when `parse256(IL) >= n` or `ki = 0`, proceed with next index
- Current code raises ValueError instead
- Probability: ~1/2^128; current behavior (fail fast) is arguably safer
- Recommendation: document as known spec deviation

**N-04: `derive_priv_path` segment parsing lacks range validation**
- File: `wallet_core.py:300-305`
- `int(seg)` accepts negative values and values >= 2^31
- Negative: `int("-1") | 0x80000000` = `-1` in Python → `struct.pack(">L", -1)` raises `struct.error`
- Large non-hardened values overlap hardened index space
- Fix: validate `0 <= idx < 0x80000000` for each segment

### P2 — Security Hardening (Recommended)

**N-05: `coin_flip_wallet.py` skips mnemonic self-verification**
- File: `coin_flip_wallet.py:210`
- After `entropy_to_mnemonic()`, mnemonic goes directly to address derivation
- `derive_addresses_offline.py` validates (line 51), but `coin_flip_wallet.py` does not
- Fix: call `validate_mnemonic()` after generation as round-trip check

**N-06: CLI integer args lack upper bounds — local DoS**
- File: `derive_addresses_offline.py:28-44`
- `--btc-count 999999999` causes CPU exhaustion via pure-Python EC math
- Negative `--btc-start` is semantically wrong (produces empty range)
- Fix: cap count at reasonable limit (e.g., 1000), require start >= 0

**N-07: `0x` prefix handling uses `replace` instead of `removeprefix`**
- File: `wallet_core.py:205`
- `hex_entropy.lower().replace("0x", "")` replaces ALL occurrences, not just prefix
- Input `"0x0xABCD..."` becomes `"ABCD..."` instead of `"0xABCD..."`
- Not exploitable (is_hex called after replace), but semantically imprecise
- Fix: use `.removeprefix("0x")`

**N-08: `bip39-standalone.html` still has no integrity verification (F-09 carry-over)**
- 4.5MB third-party JavaScript, no SHA256 hash, no version, no source URL
- Significant risk surface for a cold wallet tool
- Fix: document provenance in README + add SHA256 hash

### P3 — Improvements (Optional)

**N-09: Redundant computation in `coin_to_bip39_hex.py`**
- File: `coin_to_bip39_hex.py:77-82`
- Manually calls `bits_from_hex` → `add_checksum` → `split_to_11`, then `entropy_to_mnemonic` repeats same ops
- Risk: logic divergence between two paths
- Fix: extract intermediate steps from `entropy_to_mnemonic` or reuse

**N-10: Test temp file written to CWD instead of temp directory**
- File: `tests/test_wordlist_integrity.py:15`
- Uses CWD for temp file; `finally` block cleans up but SIGKILL leaves residue
- Fix: use pytest `tmp_path` fixture

**N-11: Missing `conftest.py` in tests/ directory**
- Tests rely on project root being on `sys.path`
- Works with `uv run python -m pytest` but fragile with other invocations

## Positive Security Findings

- **Zero network connectivity** — no socket, urllib, requests, or http imports
- **Zero software PRNG** — no random, os.urandom, or secrets imports
- **Wordlist integrity** — SHA256 pinning with hash verification
- **Clean layering** — wallet_core has no CLI imports (enforced by tests)
- **Clean git history** — no real keys, seeds, or mnemonics ever committed
- **Sensitive file gitignore** — patterns block entropy/seed/mnemonic/private files
- **Correct secp256k1 parameters** — verified against reference implementation
- **NFKD normalization** — BIP39-compliant Unicode handling
- **BIP84/BIP44 test vectors** — verified against known addresses

## Overall Verdict

**PASS with minor issues** — suitable for educational/offline use.
No critical vulnerabilities found. P1 items (N-01, N-02, N-04) improve robustness.
N-03 is a documented spec deviation with negligible practical impact.

## Remediation Plan

### Phase 1: P1 fixes (wallet_core.py)
1. N-01: Add `convertbits` return value check in `encode_segwit_address`
2. N-02: Refactor `read_wordlist` to single-read pattern
3. N-04: Add range validation in `derive_priv_path` segment parsing
4. N-03: Add doc comment noting spec deviation in `ckd_priv`

### Phase 2: P2 hardening
5. N-05: Add `validate_mnemonic()` call in `coin_flip_wallet.py` after generation
6. N-06: Add bounds checks on CLI integer args
7. N-07: Replace `replace("0x", "")` with `removeprefix("0x")`
8. N-08: Document `bip39-standalone.html` provenance in README

### Phase 3: P3 improvements (optional)
9. N-09: Refactor redundant computation in `coin_to_bip39_hex.py`
10. N-10: Use `tmp_path` fixture in `test_wordlist_integrity.py`
11. N-11: Add `conftest.py` with sys.path setup

### Phase 4: Tests for new fixes
12. Add tests for N-01 through N-07 fixes
