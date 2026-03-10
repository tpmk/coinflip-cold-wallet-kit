# Security Audit v3 — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 7 findings from security audit v3: S-01 (mnemonic CLI exposure), S-02 (repeated PBKDF2), S-03 (dead code), S-04 (entropy quality warning), N-06 (unbounded count), N-10 (test tmp_path), N-11 (conftest.py).

**Architecture:** Fix infrastructure (conftest, test hygiene) first, then core logic (dead code, count cap, entropy warning, PBKDF2 optimization), then CLI security (mnemonic input modes). Each fix is TDD: failing test → implementation → passing test → commit.

**Tech Stack:** Python 3.10+, pytest, wallet_core.py, CLI scripts

---

### Task 1: N-11 — Add `conftest.py` for test path setup

**Files:**
- Create: `tests/conftest.py`

**Step 1: Create conftest.py**

```python
import sys
from pathlib import Path

# Ensure project root is on sys.path so `import wallet_core` works
# regardless of how pytest is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
```

**Step 2: Verify all tests still pass**

Run: `uv run python -m pytest -q`
Expected: 42 passed

**Step 3: Commit**

```bash
git add tests/conftest.py
git commit -m "chore: add conftest.py for portable test imports (N-11)"
```

---

### Task 2: N-10 — Migrate test temp files to `tmp_path`

**Files:**
- Modify: `tests/test_wordlist_integrity.py`
- Modify: `tests/test_security_audit_v2.py` (TestReadWordlistSingleRead class)

**Step 1: Rewrite `test_wordlist_integrity.py` to use `tmp_path`**

Replace the entire file with:

```python
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

**Step 2: Rewrite `TestReadWordlistSingleRead` in `test_security_audit_v2.py`**

Replace the class with:

```python
class TestReadWordlistSingleRead:
    """N-02: read_wordlist should not call read_text (single-read via read_bytes + decode)."""

    def test_no_read_text_called(self, tmp_path):
        wordlist_copy = tmp_path / "wordlist.txt"
        shutil.copy(core.PROJECT_DIR / "wordlist.txt", wordlist_copy)

        original_read_text = Path.read_text
        called = {"v": False}

        def spy_read_text(self_path, *a, **kw):
            if str(self_path) == str(wordlist_copy):
                called["v"] = True
            return original_read_text(self_path, *a, **kw)

        old = Path.read_text
        Path.read_text = spy_read_text
        try:
            words = core.read_wordlist(str(wordlist_copy))
            assert len(words) == 2048
            assert not called["v"], "read_text was called — expected only read_bytes + decode"
        finally:
            Path.read_text = old
```

Remove the `uuid` import from `test_security_audit_v2.py` if no longer used.

**Step 3: Verify tests pass**

Run: `uv run python -m pytest tests/test_wordlist_integrity.py tests/test_security_audit_v2.py -q`
Expected: all pass, no temp dirs left in project tree

**Step 4: Commit**

```bash
git add tests/test_wordlist_integrity.py tests/test_security_audit_v2.py
git commit -m "fix: migrate test temp files to tmp_path (N-10)"
```

---

### Task 3: S-03 — Remove dead code in `point_add`

**Files:**
- Modify: `wallet_core.py:131-134`
- Test: `tests/test_security_audit_v3.py` (new file)

**Step 1: Write test confirming `point_add` correctness after dead code removal**

Create `tests/test_security_audit_v3.py`:

```python
"""Tests for security audit v3 findings."""

import wallet_core as core


class TestPointAddNoDeadCode:
    """S-03: point_add should not have unreachable branches."""

    def test_point_add_identity(self):
        assert core.point_add(None, core.G) == core.G
        assert core.point_add(core.G, None) == core.G

    def test_point_add_inverse(self):
        """P + (-P) = infinity."""
        neg_G = (core.G[0], core.P - core.G[1])
        assert core.point_add(core.G, neg_G) is None

    def test_point_add_doubling(self):
        """G + G == scalar_mult(2, G)."""
        doubled = core.point_add(core.G, core.G)
        expected = core.scalar_mult(2, core.G)
        assert doubled == expected

    def test_point_add_distinct(self):
        """G + 2G == 3G."""
        two_g = core.scalar_mult(2, core.G)
        three_g = core.scalar_mult(3, core.G)
        assert core.point_add(core.G, two_g) == three_g
```

**Step 2: Run test to verify it passes (before code change — these test existing behavior)**

Run: `uv run python -m pytest tests/test_security_audit_v3.py::TestPointAddNoDeadCode -v`
Expected: PASS (behavior is correct, we're just removing dead code)

**Step 3: Remove dead code**

In `wallet_core.py`, replace the `else` branch of `point_add`:

```python
    # Before (lines 131-134):
    else:
        if x1 == x2:
            return None
        m = (y2 - y1) * pow(x2 - x1, P - 2, P) % P

    # After:
    else:
        m = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
```

The guard `if x1 == x2: return None` is unreachable here: if `pt != qt` (line 127 fell through) and `x1 == x2`, then `y1 != y2` (valid curve points), which was already caught at line 125.

**Step 4: Run test to verify still passes**

Run: `uv run python -m pytest tests/test_security_audit_v3.py::TestPointAddNoDeadCode -v`
Expected: PASS

**Step 5: Commit**

```bash
git add wallet_core.py tests/test_security_audit_v3.py
git commit -m "fix: remove unreachable branch in point_add (S-03)"
```

---

### Task 4: N-06 — Cap CLI count arguments

**Files:**
- Modify: `derive_addresses_offline.py:38-48` (`non_negative_arg` → `bounded_count_arg`)
- Modify: `wallet_core.py:437-438,461-462` (add `MAX_DERIVE_COUNT`)
- Test: `tests/test_security_audit_v3.py`

**Step 1: Write failing test**

Append to `tests/test_security_audit_v3.py`:

```python
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

ABANDON_12 = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def run_script(script: str, *args: str, input_text: str | None = None):
    return subprocess.run(
        [sys.executable, str(PROJECT_ROOT / script), *args],
        cwd=PROJECT_ROOT,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestCountUpperBound:
    """N-06: CLI count args must have a reasonable upper bound."""

    def test_derive_rejects_excessive_btc_count(self):
        proc = run_script(
            "derive_addresses_offline.py",
            "--mnemonic", ABANDON_12,
            "--btc-count", "10001",
        )
        assert proc.returncode != 0

    def test_derive_rejects_excessive_eth_count(self):
        proc = run_script(
            "derive_addresses_offline.py",
            "--mnemonic", ABANDON_12,
            "--eth-count", "10001",
        )
        assert proc.returncode != 0

    def test_derive_accepts_max_count(self):
        """count=10000 is the upper limit — accepted but not run (too slow for test)."""
        # Just verify argparse accepts 10000 (derive will run but we test acceptance)
        proc = run_script(
            "derive_addresses_offline.py",
            "--mnemonic", ABANDON_12,
            "--btc-count", "10000",
            "--btc-start", "0",
        )
        # Should be accepted by argparse (might be slow, but won't error on bounds)
        assert "must be" not in proc.stderr

    def test_core_rejects_excessive_count(self):
        """wallet_core.derive_btc_addresses rejects count > MAX_DERIVE_COUNT."""
        import pytest
        with pytest.raises(ValueError, match="count"):
            core.derive_btc_addresses(ABANDON_12, "", count=10001)
```

**Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_security_audit_v3.py::TestCountUpperBound -v`
Expected: FAIL (no upper bound currently)

**Step 3: Implement count cap**

In `wallet_core.py`, add constant and modify both derive functions:

```python
MAX_DERIVE_COUNT = 10000
```

In `derive_btc_addresses`, after `if count < 0:` block:
```python
    if count > MAX_DERIVE_COUNT:
        raise ValueError(f"count must be <= {MAX_DERIVE_COUNT}, got {count}")
```

In `derive_eth_addresses`, same pattern.

In `derive_addresses_offline.py`, replace `non_negative_arg` with `bounded_count_arg`:

```python
MAX_DERIVE_COUNT = 10000


def bounded_count_arg(flag_name: str):
    def _parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{flag_name} must be an integer") from exc
        if parsed < 0 or parsed > MAX_DERIVE_COUNT:
            raise argparse.ArgumentTypeError(
                f"{flag_name} must be between 0 and {MAX_DERIVE_COUNT}"
            )
        return parsed

    return _parse
```

Update `--btc-count` and `--eth-count` to use `bounded_count_arg`.

**Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_security_audit_v3.py::TestCountUpperBound -v`
Expected: PASS

**Step 5: Commit**

```bash
git add wallet_core.py derive_addresses_offline.py tests/test_security_audit_v3.py
git commit -m "fix: cap derive count at 10000 to prevent local DoS (N-06)"
```

---

### Task 5: S-04 — Add entropy quality warning

**Files:**
- Modify: `wallet_core.py` (add `check_entropy_quality`)
- Modify: `coin_flip_wallet.py` (call it before derivation)
- Modify: `coin_to_bip39_hex.py` (call it before derivation)
- Test: `tests/test_security_audit_v3.py`

**Step 1: Write failing test**

Append to `tests/test_security_audit_v3.py`:

```python
import pytest


class TestEntropyQualityWarning:
    """S-04: warn on pathologically weak entropy."""

    def test_all_zeros_warns(self):
        warnings = core.check_entropy_quality("00" * 32)
        assert len(warnings) > 0

    def test_all_ones_warns(self):
        warnings = core.check_entropy_quality("ff" * 32)
        assert len(warnings) > 0

    def test_repeated_pattern_warns(self):
        warnings = core.check_entropy_quality("ab" * 32)
        assert len(warnings) > 0

    def test_good_entropy_no_warning(self):
        # Known diverse entropy
        warnings = core.check_entropy_quality(
            "a3f7c2e9b1d486520fa3e7c1b9d2f5e8a4c6d1f3b7e2a5c8d9f1e4b6a2c7d3f8"
        )
        assert len(warnings) == 0

    def test_cli_shows_entropy_warning(self):
        proc = run_script(
            "coin_flip_wallet.py",
            "--hex", "00" * 32,
            "--yes",
        )
        assert proc.returncode == 0
        # Warning should appear in stderr
        assert "entropy" in proc.stderr.lower() or "熵" in proc.stderr
```

**Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_security_audit_v3.py::TestEntropyQualityWarning -v`
Expected: FAIL (function doesn't exist)

**Step 3: Implement entropy quality check**

In `wallet_core.py`, add:

```python
def check_entropy_quality(hex_entropy: str) -> list[str]:
    """Return a list of warnings if entropy looks pathologically weak."""
    hex_clean = hex_entropy.strip().lower().removeprefix("0x")
    warnings = []

    # Check all identical bytes
    if len(set(hex_clean)) <= 1:
        warnings.append("All bytes are identical — entropy is effectively zero")
        return warnings

    # Check repeating 1-byte pattern (e.g., "abababab...")
    if len(hex_clean) >= 4:
        two_char = hex_clean[:2]
        if hex_clean == two_char * (len(hex_clean) // 2):
            warnings.append(
                f"Entropy is a repeating byte pattern (0x{two_char}) — effectively ~8 bits of entropy"
            )
            return warnings

    # Check bit bias: if more than 87.5% of bits are 0 or 1
    try:
        value = int(hex_clean, 16)
        total_bits = len(hex_clean) * 4
        ones = bin(value).count("1")
        zeros = total_bits - ones
        ratio = max(ones, zeros) / total_bits
        if ratio > 0.875:
            dominant = "1" if ones > zeros else "0"
            warnings.append(
                f"Severe bit bias: {ratio:.0%} of bits are '{dominant}' — very low entropy"
            )
    except ValueError:
        pass

    return warnings
```

In `coin_flip_wallet.py`, after `entropy_hex` is obtained (around line 256), add:

```python
        from wallet_core import check_entropy_quality
        entropy_warnings = check_entropy_quality(entropy_hex)
        if entropy_warnings:
            for w in entropy_warnings:
                print(f"WARNING: {w}", file=sys.stderr)
            print(
                "WARNING: 熵值质量极差，生成的钱包极不安全！",
                file=sys.stderr,
            )
```

In `coin_to_bip39_hex.py`, before calling `entropy_to_mnemonic`, add similar warning to stderr.

**Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_security_audit_v3.py::TestEntropyQualityWarning -v`
Expected: PASS

**Step 5: Commit**

```bash
git add wallet_core.py coin_flip_wallet.py coin_to_bip39_hex.py tests/test_security_audit_v3.py
git commit -m "fix: warn on pathologically weak entropy (S-04)"
```

---

### Task 6: S-02 — Eliminate repeated PBKDF2 per address

**Files:**
- Modify: `wallet_core.py:408-473` (refactor derive functions)
- Test: `tests/test_security_audit_v3.py`

**Step 1: Write test that verifies identical output after refactor**

Append to `tests/test_security_audit_v3.py`:

```python
class TestPBKDF2Optimization:
    """S-02: derive functions must produce identical results after PBKDF2 optimization."""

    def test_btc_addresses_match_known_vector(self):
        """BTC derivation must match the known test vector after refactor."""
        results = core.derive_btc_addresses(ABANDON_12, "", count=1)
        path, addr, _ = results[0]
        assert path == "m/84'/0'/0'/0/0"
        assert addr == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

    def test_eth_addresses_match_known_vector(self):
        """ETH derivation must match the known test vector after refactor."""
        results = core.derive_eth_addresses(ABANDON_12, "", count=1)
        path, addr = results[0]
        assert path == "m/44'/60'/0'/0/0"
        assert addr == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

    def test_multiple_btc_addresses_consistent(self):
        """Verify N addresses match individual derive_pubkey_at calls."""
        results = core.derive_btc_addresses(ABANDON_12, "", count=3)
        for path, addr, pubhex in results:
            point = core.derive_pubkey_at(ABANDON_12, "", path)
            pubkey = core.serP(point, compressed=True)
            single_addr = core.btc_p2wpkh_address(pubkey)
            assert addr == single_addr

    def test_multiple_eth_addresses_consistent(self):
        """Verify N ETH addresses match individual derive_pubkey_at calls."""
        results = core.derive_eth_addresses(ABANDON_12, "", count=3)
        for path, addr in results:
            point = core.derive_pubkey_at(ABANDON_12, "", path)
            pubkey = core.serP(point, compressed=False)
            single_addr = core.eth_address(pubkey)
            assert addr == single_addr
```

**Step 2: Run test to verify it passes (pre-refactor baseline)**

Run: `uv run python -m pytest tests/test_security_audit_v3.py::TestPBKDF2Optimization -v`
Expected: PASS (tests lock current behavior)

**Step 3: Refactor `derive_btc_addresses` and `derive_eth_addresses`**

Replace the implementations to derive seed, master key, and common path prefix **once**:

```python
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
    if count > MAX_DERIVE_COUNT:
        raise ValueError(f"count must be <= {MAX_DERIVE_COUNT}, got {count}")
    if count > 0:
        _require_index_range("last index", start + count - 1)

    # Derive seed and common path prefix once (avoids N × PBKDF2)
    seed = mnemonic_to_seed(mnemonic, passphrase)
    k_master, _, c_master = bip32_master_key(seed)
    prefix_path = f"m/84'/{coin_type}'/{account}'/{change}"
    k_prefix, c_prefix = derive_priv_path(k_master, c_master, prefix_path)

    results = []
    for i in range(start, start + count):
        k_child, _ = ckd_priv(k_prefix, c_prefix, i)
        point = scalar_mult(k_child, G)
        pubkey_compressed = serP(point, compressed=True)
        address = btc_p2wpkh_address(pubkey_compressed, hrp=hrp)
        path = f"{prefix_path}/{i}"
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
    if count > MAX_DERIVE_COUNT:
        raise ValueError(f"count must be <= {MAX_DERIVE_COUNT}, got {count}")
    if count > 0:
        _require_index_range("last index", start + count - 1)

    # Derive seed and common path prefix once (avoids N × PBKDF2)
    seed = mnemonic_to_seed(mnemonic, passphrase)
    k_master, _, c_master = bip32_master_key(seed)
    prefix_path = f"m/44'/60'/{account}'/0"
    k_prefix, c_prefix = derive_priv_path(k_master, c_master, prefix_path)

    results = []
    for i in range(start, start + count):
        k_child, _ = ckd_priv(k_prefix, c_prefix, i)
        point = scalar_mult(k_child, G)
        pubkey_uncompressed = serP(point, compressed=False)
        address = eth_address(pubkey_uncompressed)
        path = f"{prefix_path}/{i}"
        results.append((path, address))
    return results
```

**Step 4: Run test to verify still passes**

Run: `uv run python -m pytest tests/test_security_audit_v3.py::TestPBKDF2Optimization -v`
Expected: PASS

Run full suite: `uv run python -m pytest -q`
Expected: all pass

**Step 5: Commit**

```bash
git add wallet_core.py tests/test_security_audit_v3.py
git commit -m "perf: derive seed and common path once per batch (S-02)"
```

---

### Task 7: S-01 — Add mnemonic-stdin and mnemonic-prompt to `derive_addresses_offline.py`

**Files:**
- Modify: `derive_addresses_offline.py`
- Test: `tests/test_security_audit_v3.py`

**Step 1: Write failing tests**

Append to `tests/test_security_audit_v3.py`:

```python
class TestMnemonicInputModes:
    """S-01: mnemonic must not be exposed in process list."""

    def test_mnemonic_stdin(self):
        proc = run_script(
            "derive_addresses_offline.py",
            "--mnemonic-stdin",
            "--btc-count", "1",
            input_text=ABANDON_12 + "\n",
        )
        assert proc.returncode == 0, proc.stderr
        assert "bc1q" in proc.stdout

    def test_mnemonic_prompt_rejects_non_tty_without_stdin_flag(self):
        """--mnemonic-prompt requires a TTY (cannot test real getpass in CI)."""
        # At minimum, verify the flag is accepted by argparse
        proc = run_script(
            "derive_addresses_offline.py",
            "--mnemonic-prompt",
            "--btc-count", "1",
            input_text=ABANDON_12 + "\n",
        )
        # Will fail because getpass doesn't work on piped stdin, but
        # should NOT fail with "unrecognized arguments"
        assert "unrecognized" not in proc.stderr

    def test_plaintext_mnemonic_warns(self):
        proc = run_script(
            "derive_addresses_offline.py",
            "--mnemonic", ABANDON_12,
            "--btc-count", "1",
        )
        assert proc.returncode == 0, proc.stderr
        assert "WARNING" in proc.stderr
        assert "mnemonic" in proc.stderr.lower()

    def test_mnemonic_stdin_and_passphrase_stdin_reads_both_lines(self):
        """First line = mnemonic, second line = passphrase."""
        proc = run_script(
            "derive_addresses_offline.py",
            "--mnemonic-stdin",
            "--passphrase-stdin",
            "--btc-count", "1",
            input_text=ABANDON_12 + "\nTREZOR\n",
        )
        assert proc.returncode == 0, proc.stderr
        assert "bc1q" in proc.stdout

    def test_mnemonic_and_mnemonic_stdin_mutually_exclusive(self):
        proc = run_script(
            "derive_addresses_offline.py",
            "--mnemonic", ABANDON_12,
            "--mnemonic-stdin",
            "--btc-count", "1",
        )
        assert proc.returncode != 0
```

**Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_security_audit_v3.py::TestMnemonicInputModes -v`
Expected: FAIL (flags don't exist yet)

**Step 3: Implement mnemonic input modes**

In `derive_addresses_offline.py`:

1. Replace the `--mnemonic` argument with a mutually exclusive group:

```python
    mnemonic_group = parser.add_mutually_exclusive_group(required=True)
    mnemonic_group.add_argument(
        "--mnemonic",
        default=None,
        help=(
            "BIP39 mnemonic words (WARNING: visible in process list and shell history; "
            "prefer --mnemonic-stdin or --mnemonic-prompt)"
        ),
    )
    mnemonic_group.add_argument(
        "--mnemonic-stdin",
        action="store_true",
        help="Read BIP39 mnemonic from first line of stdin (recommended for scripts)",
    )
    mnemonic_group.add_argument(
        "--mnemonic-prompt",
        action="store_true",
        help="Prompt mnemonic with hidden input (recommended for interactive use)",
    )
```

2. Add `resolve_mnemonic` function:

```python
def resolve_mnemonic(args, parser: argparse.ArgumentParser) -> str:
    if args.mnemonic_stdin:
        if sys.stdin.isatty():
            parser.error("--mnemonic-stdin requires piped stdin input")
        return sys.stdin.readline().rstrip("\r\n")
    if args.mnemonic_prompt:
        return getpass.getpass("Enter BIP39 mnemonic: ")
    # --mnemonic (plaintext CLI arg)
    print(
        "WARNING: --mnemonic is visible in process list and shell history. "
        "Prefer --mnemonic-stdin or --mnemonic-prompt.",
        file=sys.stderr,
    )
    return args.mnemonic
```

3. Update `resolve_passphrase` to handle the case where stdin was already consumed by `resolve_mnemonic`:

When both `--mnemonic-stdin` and `--passphrase-stdin` are used, mnemonic is line 1 and passphrase is line 2 — both read via `sys.stdin.readline()`. This naturally works because `readline()` reads one line at a time.

4. Update `main()` to call `resolve_mnemonic` before `resolve_passphrase`, and use the returned mnemonic:

```python
    mnemonic = resolve_mnemonic(args, parser)
    passphrase = resolve_passphrase(args, parser)
```

Replace `args.mnemonic` references with `mnemonic` in the rest of `main()`.

**Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_security_audit_v3.py::TestMnemonicInputModes -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `uv run python -m pytest -q`
Expected: all pass (existing tests that use `--mnemonic` still work)

**Step 6: Commit**

```bash
git add derive_addresses_offline.py tests/test_security_audit_v3.py
git commit -m "fix: add mnemonic-stdin and mnemonic-prompt input modes (S-01)"
```

---

### Task 8: Final verification

**Step 1: Run full test suite**

Run: `uv run python -m pytest -q`
Expected: all pass

**Step 2: Verify no regressions with known test vectors**

Run: `uv run python -m pytest tests/test_security_audit_fixes.py tests/test_coin_flip_wallet_pytest.py -v`
Expected: all pass

**Step 3: Commit the audit design document**

```bash
git add docs/plans/2026-03-10-security-audit-v3-implementation.md
git commit -m "docs: security audit v3 implementation plan"
```
