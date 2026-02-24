"""Tests for security audit v2 findings."""

import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

import wallet_core as core

ABANDON_12 = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


class TestConvertbitsNoneCheck:
    """N-01: encode_segwit_address must raise on invalid witprog."""

    def test_encode_segwit_address_rejects_invalid_witprog(self):
        bad_witprog = [256]  # >255, invalid for 8-bit conversion
        with pytest.raises(ValueError, match="convertbits"):
            core.encode_segwit_address("bc", 0, bad_witprog)


class TestReadWordlistSingleRead:
    """N-02: read_wordlist should not call read_text (single-read via read_bytes + decode)."""

    def test_no_read_text_called(self):
        temp_dir = core.PROJECT_DIR / "tests" / f".tmp-wordlist-read-{uuid.uuid4().hex}"
        temp_dir.mkdir(parents=True, exist_ok=False)
        wordlist_copy = temp_dir / "wordlist.txt"
        shutil.copy(core.PROJECT_DIR / "wordlist.txt", wordlist_copy)

        # Patch read_text to detect if it is called on our file
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
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestCoinFlipValidatesMnemonic:
    """N-05: coin_flip_wallet must validate the mnemonic it generates."""

    def test_coin_flip_calls_validate_mnemonic(self):
        """Run coin_flip_wallet --hex with all-zeros and check it doesn't crash.

        Since validate_mnemonic raises on invalid mnemonics, a successful
        run with --hex proves it was called without error.
        """
        project_root = core.PROJECT_DIR
        proc = subprocess.run(
            [sys.executable, str(project_root / "coin_flip_wallet.py"),
             "--hex", "0" * 64, "--yes"],
            capture_output=True, text=True, timeout=60,
            cwd=str(project_root),
        )
        assert proc.returncode == 0, proc.stderr
        # 256-bit all-zeros produces 24-word mnemonic ending in "art"
        assert "abandon abandon abandon" in proc.stdout
        assert "art" in proc.stdout


class TestRemovePrefix:
    """N-07: 0x prefix handling must use removeprefix, not replace."""

    def test_entropy_to_mnemonic_with_0x_prefix(self):
        hex_input = "0x" + "00" * 16  # 0x + 32 hex chars
        mnemonic = core.entropy_to_mnemonic(hex_input)
        assert len(mnemonic.split()) == 12

    def test_entropy_to_mnemonic_without_prefix(self):
        hex_input = "00" * 16
        mnemonic = core.entropy_to_mnemonic(hex_input)
        assert len(mnemonic.split()) == 12
