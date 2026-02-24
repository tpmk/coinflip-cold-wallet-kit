# Shared Core And Noninteractive Flag Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove duplicated wallet derivation logic by introducing a shared core module, and add a `--yes` flag for non-interactive batch usage.

**Architecture:** Keep `coin_flip_wallet.py` as the canonical implementation source for cryptographic primitives and derivation behavior. Add a lightweight `wallet_core.py` facade and refactor `derive_addresses_offline.py` to consume shared functions only. Extend CLI parsing in `coin_flip_wallet.py` so batch runs can bypass manual Enter confirmation safely when explicitly requested.

**Tech Stack:** Python 3.10+, argparse, pytest, uv.

---

### Task 1: Add Failing Tests For Shared Core And `--yes`

**Files:**
- Create: `tests/test_shared_core_and_cli.py`
- Test: `tests/test_shared_core_and_cli.py`

**Step 1: Write the failing tests**
- Assert `wallet_core` can be imported and returns identical addresses as `coin_flip_wallet`.
- Assert `coin_flip_wallet.py --hex ... --yes` exits successfully and does not require `Enter`.

**Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_shared_core_and_cli.py -q`  
Expected: FAIL (module not found / unknown `--yes`).

### Task 2: Implement Shared Core Module

**Files:**
- Create: `wallet_core.py`
- Modify: `derive_addresses_offline.py`

**Step 1: Write minimal implementation**
- Add shared exports/wrappers in `wallet_core.py`.
- Refactor `derive_addresses_offline.py` to only contain CLI code and call shared functions.

**Step 2: Run tests for shared behavior**

Run: `uv run python -m pytest tests/test_shared_core_and_cli.py -q`  
Expected: shared-core tests move toward pass.

### Task 3: Implement `--yes` Non-Interactive Mode

**Files:**
- Modify: `coin_flip_wallet.py`
- Modify: `README_COIN_FLIP.md`

**Step 1: Write minimal implementation**
- Add `--yes` flag.
- Make security prompt skippable only when `--yes` is provided.

**Step 2: Re-run targeted tests**

Run: `uv run python -m pytest tests/test_shared_core_and_cli.py -q`  
Expected: PASS.

### Task 4: Full Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/PROJECT_OVERVIEW.md`

**Step 1: Run full verification**

Run:
- `uv run python -m pytest -q`
- `uv run python test_coin_flip_wallet.py`

Expected: all tests pass.
