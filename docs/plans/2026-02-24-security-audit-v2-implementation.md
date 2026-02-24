# Security Audit v2 Remediation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix remaining security audit v2 findings (N-01, N-02, N-03, N-05, N-07, N-09, N-10) and add tests.

**Architecture:** All fixes are in `wallet_core.py` (core), `coin_flip_wallet.py` (CLI), and `coin_to_bip39_hex.py` (CLI). Tests go in `tests/test_security_audit_v2.py`. N-04, N-06, and F-07 are already fixed in uncommitted changes — this plan covers only the remaining items.

**Tech Stack:** Python 3.10+, pytest, pycryptodome

---

### Task 1: N-01 — Add `convertbits` return value check

**Files:**
- Modify: `wallet_core.py:368-370`
- Test: `tests/test_security_audit_v2.py`

**Step 1: Write the failing test**

```python
# tests/test_security_audit_v2.py
import pytest
import wallet_core as core


class TestConvertbitsNoneCheck:
    """N-01: encode_segwit_address must raise on invalid witprog."""

    def test_encode_segwit_address_rejects_invalid_witprog(self):
        """convertbits returns None for out-of-range values; must not TypeError."""
        bad_witprog = [256]  # >255, invalid for 8-bit conversion
        with pytest.raises(ValueError, match="convertbits"):
            core.encode_segwit_address("bc", 0, bad_witprog)
```

**Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_security_audit_v2.py::TestConvertbitsNoneCheck -v`
Expected: FAIL with `TypeError` (None + list)

**Step 3: Write minimal implementation**

In `wallet_core.py`, change `encode_segwit_address`:

```python
def encode_segwit_address(hrp, witver, witprog):
    ret = convertbits(witprog, 8, 5)
    if ret is None:
        raise ValueError("convertbits failed: invalid witness program")
    data = [witver] + ret
    return bech32_encode(hrp, data)
```

**Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_security_audit_v2.py::TestConvertbitsNoneCheck -v`
Expected: PASS

**Step 5: Run full test suite to verify no regressions**

Run: `uv run python -m pytest -v`
Expected: All tests PASS (BTC/ETH address vectors still correct)

---

### Task 2: N-02 — Refactor `read_wordlist` to single-read pattern

**Files:**
- Modify: `wallet_core.py:161-179`
- Test: `tests/test_security_audit_v2.py`

**Step 1: Write the failing test**

```python
class TestReadWordlistSingleRead:
    """N-02: read_wordlist should read the file only once (TOCTOU fix)."""

    def test_read_wordlist_calls_read_once(self, monkeypatch, tmp_path):
        """Ensure only one file read occurs (not two separate reads)."""
        import shutil
        wordlist_src = core.PROJECT_DIR / "wordlist.txt"
        wordlist_copy = tmp_path / "wordlist.txt"
        shutil.copy(wordlist_src, wordlist_copy)

        read_count = {"n": 0}
        original_read_bytes = Path.read_bytes

        def counting_read_bytes(self_path):
            if self_path == wordlist_copy:
                read_count["n"] += 1
            return original_read_bytes(self_path)

        monkeypatch.setattr(Path, "read_bytes", counting_read_bytes)
        words = core.read_wordlist(str(wordlist_copy))
        assert len(words) == 2048
        assert read_count["n"] == 1, f"Expected 1 file read, got {read_count['n']}"
```

**Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_security_audit_v2.py::TestReadWordlistSingleRead -v`
Expected: FAIL (current code reads file twice: `read_bytes` then `read_text`)

**Step 3: Write minimal implementation**

In `wallet_core.py`, refactor `read_wordlist`:

```python
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
```

**Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_security_audit_v2.py::TestReadWordlistSingleRead -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `uv run python -m pytest -v`
Expected: All PASS

---

### Task 3: N-03 — Document spec deviation in `ckd_priv`

**Files:**
- Modify: `wallet_core.py:280-296`

**Step 1: Add doc comment to `ckd_priv`**

```python
def ckd_priv(k_parent: int, c_parent: bytes, index: int):
    """BIP32 child key derivation (private).

    NOTE — spec deviation: BIP32 says if parse256(IL) >= n or ki == 0,
    proceed with the next index value.  We raise ValueError instead
    because (a) the probability is ~1/2^128 and (b) silently skipping
    to a different index would change the derived path without the
    caller's knowledge, which is arguably less safe for a cold-wallet
    tool than failing loudly.
    """
```

**Step 2: No test needed — documentation only**

**Step 3: Run full test suite**

Run: `uv run python -m pytest -v`
Expected: All PASS

---

### Task 4: N-05 — Add mnemonic self-verification in `coin_flip_wallet.py`

**Files:**
- Modify: `coin_flip_wallet.py:16-23` (import) and `coin_flip_wallet.py:250` (after generation)
- Test: `tests/test_security_audit_v2.py`

**Step 1: Write the failing test**

```python
class TestCoinFlipValidatesMnemonic:
    """N-05: coin_flip_wallet must validate the mnemonic it generates."""

    def test_entropy_to_mnemonic_result_is_validated(self, monkeypatch):
        """Verify validate_mnemonic is called on the generated mnemonic."""
        validated = {"called": False}
        original_validate = core.validate_mnemonic

        def tracking_validate(mnemonic, wordlist_path="wordlist.txt"):
            validated["called"] = True
            return original_validate(mnemonic, wordlist_path)

        import coin_flip_wallet as cfw
        monkeypatch.setattr(cfw, "validate_mnemonic", tracking_validate)

        # Use --hex mode with --yes to skip prompts
        monkeypatch.setattr(
            "sys.argv",
            ["coin_flip_wallet.py", "--hex", "0" * 64, "--yes"],
        )
        # Capture stdout to suppress output
        import io
        monkeypatch.setattr("sys.stdout", io.StringIO())
        try:
            cfw.main()
        except SystemExit:
            pass
        assert validated["called"], "validate_mnemonic was not called after generation"
```

**Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_security_audit_v2.py::TestCoinFlipValidatesMnemonic -v`
Expected: FAIL (`validated["called"]` is False)

**Step 3: Write minimal implementation**

In `coin_flip_wallet.py`, add `validate_mnemonic` to the import:

```python
from wallet_core import (
    derive_btc_addresses,
    derive_eth_addresses,
    entropy_to_mnemonic,
    is_hex,
    keccak_256,
    mnemonic_to_seed,
    ripemd160,
    validate_mnemonic,
)
```

Then after line 250 (`mnemonic = entropy_to_mnemonic(...)`) add:

```python
        validate_mnemonic(mnemonic, args.wordlist)
```

**Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_security_audit_v2.py::TestCoinFlipValidatesMnemonic -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `uv run python -m pytest -v`
Expected: All PASS

---

### Task 5: N-07 — Replace `replace("0x", "")` with `removeprefix("0x")`

**Files:**
- Modify: `wallet_core.py:212` (`entropy_to_mnemonic`)
- Modify: `wallet_core.py:189` (`bits_from_hex`)
- Modify: `coin_flip_wallet.py:70` (`collect_batch`)
- Modify: `coin_to_bip39_hex.py:42,47` (`load_hex`)
- Test: `tests/test_security_audit_v2.py`

**Step 1: Write the failing test**

```python
class TestRemovePrefix:
    """N-07: 0x prefix handling must use removeprefix, not replace."""

    def test_entropy_to_mnemonic_strips_only_prefix(self):
        """Input containing '0x' in the middle should not have it removed."""
        # "0x" + 62 hex chars = 64 nibbles total after prefix removal
        # If replace is used, embedded "0x" would also be removed
        hex_with_embedded_0x = "0x" + "a0" * 31 + "b0"  # 0x + 62 chars = valid
        mnemonic = core.entropy_to_mnemonic(hex_with_embedded_0x)
        assert len(mnemonic.split()) == 24  # 256 bits -> 24 words
```

**Step 2: Run test to verify it passes (this test passes with both old and new code)**

Since both approaches produce the same result for valid "0x"-prefixed input, we verify the fix is correct by reading the code. The test above confirms no regression.

**Step 3: Apply the fix**

In `wallet_core.py:212`:
```python
# Before:
hex_entropy = hex_entropy.lower().replace("0x", "").strip()
# After:
hex_entropy = hex_entropy.strip().lower().removeprefix("0x")
```

In `wallet_core.py:189`:
```python
# Before:
hex_str = hex_str.lower().replace("0x", "")
# After:
hex_str = hex_str.lower().removeprefix("0x")
```

In `coin_flip_wallet.py:70`:
```python
# Before:
hex_cleaned = hex_input.lower().replace("0x", "").strip()
# After:
hex_cleaned = hex_input.strip().lower().removeprefix("0x")
```

In `coin_to_bip39_hex.py:42`:
```python
# Before:
hex_s = args.hex.strip().lower().replace("0x", "")
# After:
hex_s = args.hex.strip().lower().removeprefix("0x")
```

In `coin_to_bip39_hex.py:47`:
```python
# Before:
hex_s = path.read_text(encoding="utf-8").strip().lower().replace("0x", "")
# After:
hex_s = path.read_text(encoding="utf-8").strip().lower().removeprefix("0x")
```

**Step 4: Run full test suite**

Run: `uv run python -m pytest -v`
Expected: All PASS

---

### Task 6: N-09 — Eliminate redundant computation in `coin_to_bip39_hex.py`

**Files:**
- Modify: `coin_to_bip39_hex.py:77-89`

**Step 1: Refactor main() to compute intermediate values from `entropy_to_mnemonic` inputs**

The display needs `ent_bits_len`, `cs_len`, `full_bits`, and `idxs` for informational output. Rather than calling the internal functions separately and then calling `entropy_to_mnemonic` (which repeats the same work), compute the mnemonic first, then derive display values from shared helpers.

```python
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

    # Compute display info from the canonical hex (no duplicate crypto ops)
    ent_bits_len = len(hex_s) * 4
    cs_len = ent_bits_len // 32
    total_bits = ent_bits_len + cs_len
    idxs = [core.read_wordlist(args.wordlist).index(w) for w in mnemonic.split()]

    print("=== BIP39 Conversion ===")
    print(f"ENT = {ent_bits_len} bits, CS = {cs_len} bits, Total = {total_bits} bits")
    print("Indexes (11-bit):")
    print(",".join(map(str, idxs)))
    print("\nMnemonic:")
    print(mnemonic)
    print("\nNotes: Keep this mnemonic OFFLINE. Consider an optional BIP39 passphrase (backup separately).")
```

Wait — this calls `read_wordlist` again. Better approach: keep the intermediate calls but remove the redundant `entropy_to_mnemonic` call:

```python
    mnemonic = entropy_to_mnemonic(hex_s, args.wordlist)

    # Derive display values arithmetically (no re-hashing)
    ent_bits_len = len(hex_s) * 4
    cs_len = ent_bits_len // 32
    total_bits = ent_bits_len + cs_len
    words = mnemonic.split()
    wordlist = core.read_wordlist(args.wordlist)
    word_map = {w: i for i, w in enumerate(wordlist)}
    idxs = [word_map[w] for w in words]

    print("=== BIP39 Conversion ===")
    print(f"ENT = {ent_bits_len} bits, CS = {cs_len} bits, Total = {total_bits} bits")
    print("Indexes (11-bit):")
    print(",".join(map(str, idxs)))
    print("\nMnemonic:")
    print(mnemonic)
    print("\nNotes: Keep this mnemonic OFFLINE. Consider an optional BIP39 passphrase (backup separately).")
```

**Step 2: Run full test suite**

Run: `uv run python -m pytest -v`
Expected: All PASS

---

### Task 7: N-10 — Use `tmp_path` fixture in `test_wordlist_integrity.py`

**Files:**
- Modify: `tests/test_wordlist_integrity.py`

**Step 1: Rewrite the test to use `tmp_path`**

```python
from pathlib import Path

import pytest

import wallet_core as core


def test_rejects_tampered_wordlist_even_if_word_count_is_2048(tmp_path):
    original = (core.PROJECT_DIR / "wordlist.txt").read_text(encoding="utf-8").splitlines()
    assert len(original) == 2048

    tampered = original.copy()
    tampered[0] = "zzzzzz"
    tampered_path = tmp_path / "tampered_wordlist.txt"
    tampered_path.write_text("\n".join(tampered) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        core.read_wordlist(str(tampered_path))
```

**Step 2: Run test**

Run: `uv run python -m pytest tests/test_wordlist_integrity.py -v`
Expected: PASS

---

### Task 8: Commit all fixes

**Step 1: Run the full test suite one final time**

Run: `uv run python -m pytest -v`
Expected: All PASS

**Step 2: Commit**

```bash
git add wallet_core.py coin_flip_wallet.py coin_to_bip39_hex.py tests/test_security_audit_v2.py tests/test_wordlist_integrity.py
git commit -m "fix: security audit v2 — TOCTOU, convertbits guard, removeprefix, mnemonic self-check"
```
