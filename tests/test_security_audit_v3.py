"""Tests for security audit v3 findings."""

import subprocess
import sys
from pathlib import Path

import pytest

import wallet_core as core

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

    def test_derive_accepts_valid_count(self):
        """A count within the limit is accepted by argparse and runs correctly."""
        proc = run_script(
            "derive_addresses_offline.py",
            "--mnemonic", ABANDON_12,
            "--btc-count", "1",
        )
        assert proc.returncode == 0, proc.stderr
        assert "bc1q" in proc.stdout

    def test_core_rejects_excessive_btc_count(self):
        with pytest.raises(ValueError, match="count"):
            core.derive_btc_addresses(ABANDON_12, "", count=10001)

    def test_core_rejects_excessive_eth_count(self):
        with pytest.raises(ValueError, match="count"):
            core.derive_eth_addresses(ABANDON_12, "", count=10001)


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
        assert "WARNING" in proc.stderr

    def test_coin_to_bip39_shows_entropy_warning(self):
        proc = run_script(
            "coin_to_bip39_hex.py",
            "--hex", "00" * 32,
        )
        assert proc.returncode == 0
        assert "WARNING" in proc.stderr


class TestPBKDF2Optimization:
    """S-02: derive functions must produce identical results after PBKDF2 optimization."""

    def test_btc_addresses_match_known_vector(self):
        results = core.derive_btc_addresses(ABANDON_12, "", count=1)
        path, addr, _ = results[0]
        assert path == "m/84'/0'/0'/0/0"
        assert addr == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

    def test_eth_addresses_match_known_vector(self):
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


class TestAddressEncodingValidation:
    def test_encode_segwit_address_rejects_non_v0(self):
        with pytest.raises(ValueError, match="witness version 0"):
            core.encode_segwit_address("bc", 1, [0] * 20)

    def test_eth_address_rejects_wrong_length_pubkey(self):
        bad_pubkey = bytes.fromhex("04" + "11" * 10)
        with pytest.raises(ValueError, match="65-byte"):
            core.eth_address(bad_pubkey)


class TestLegacyP2PKHSupport:
    def test_legacy_btc_address_matches_known_vector(self):
        results = core.derive_btc_legacy_addresses(ABANDON_12, "", count=1)
        path, addr, _ = results[0]
        assert path == "m/44'/0'/0'/0/0"
        assert addr == "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"

    def test_multiple_legacy_btc_addresses_consistent(self):
        results = core.derive_btc_legacy_addresses(ABANDON_12, "", count=3)
        for path, addr, pubhex in results:
            point = core.derive_pubkey_at(ABANDON_12, "", path)
            pubkey = core.serP(point, compressed=True)
            single_addr = core.btc_p2pkh_address(pubkey)
            assert addr == single_addr
            assert pubhex == pubkey.hex()

    def test_coin_flip_wallet_shows_legacy_addresses(self):
        proc = run_script(
            "coin_flip_wallet.py",
            "--hex", "00" * 32,
            "--yes",
        )
        assert proc.returncode == 0, proc.stderr
        assert "Legacy" in proc.stdout
        assert "1" in proc.stdout

    def test_derive_addresses_offline_shows_legacy_addresses(self):
        proc = run_script(
            "derive_addresses_offline.py",
            "--mnemonic", ABANDON_12,
            "--btc-count", "1",
        )
        assert proc.returncode == 0, proc.stderr
        assert "BTC Legacy" in proc.stdout
        assert "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA" in proc.stdout


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

    def test_mnemonic_prompt_flag_accepted(self):
        """--mnemonic-prompt is accepted by argparse (verify via --help)."""
        proc = run_script(
            "derive_addresses_offline.py",
            "--help",
        )
        assert proc.returncode == 0
        assert "--mnemonic-prompt" in proc.stdout

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
