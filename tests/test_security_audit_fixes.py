"""Tests for security audit findings (2026-02-24).

Covers: BIP32 IL>=N checks, lstrip fix, is_hex fix, validate_mnemonic,
and end-to-end BTC/ETH address test vectors.
"""

import pytest

import wallet_core as core


# ---------------------------------------------------------------------------
# F-01 / F-02: BIP32 IL >= N guard
# ---------------------------------------------------------------------------

class TestBIP32ILGuard:
    """Verify that IL >= N is rejected per BIP32 spec."""

    def test_bip32_master_key_rejects_il_ge_n(self, monkeypatch):
        """If HMAC-SHA512 returns IL >= N, bip32_master_key must raise."""
        fake_il = core.int_to_bytes(core.N, 32)  # IL == N (invalid)
        fake_ir = b"\x01" * 32
        fake_hmac_result = fake_il + fake_ir
        monkeypatch.setattr(core, "hmac_sha512", lambda k, d: fake_hmac_result)
        with pytest.raises(ValueError, match="parse256\\(IL\\) >= n"):
            core.bip32_master_key(b"\x00" * 64)

    def test_bip32_master_key_rejects_il_zero(self, monkeypatch):
        fake_il = b"\x00" * 32
        fake_ir = b"\x01" * 32
        monkeypatch.setattr(core, "hmac_sha512", lambda k, d: fake_il + fake_ir)
        with pytest.raises(ValueError, match="zero"):
            core.bip32_master_key(b"\x00" * 64)

    def test_ckd_priv_rejects_il_ge_n(self, monkeypatch):
        """If HMAC-SHA512 returns IL >= N during CKD, must raise."""
        fake_il = core.int_to_bytes(core.N, 32)
        fake_ir = b"\x01" * 32
        monkeypatch.setattr(core, "hmac_sha512", lambda k, d: fake_il + fake_ir)
        with pytest.raises(ValueError, match="parse256\\(IL\\) >= n"):
            core.ckd_priv(1, b"\x01" * 32, 0x80000000)


# ---------------------------------------------------------------------------
# F-03: path.lstrip("m/") -> path[2:]
# ---------------------------------------------------------------------------

class TestDerivePrivPath:
    def test_standard_path_works(self):
        seed = core.mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about"
        )
        k, _, c = core.bip32_master_key(seed)
        k2, _ = core.derive_priv_path(k, c, "m/84'/0'/0'/0/0")
        assert k2 > 0

    def test_root_path_returns_master(self):
        seed = core.mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about"
        )
        k, _, c = core.bip32_master_key(seed)
        k2, c2 = core.derive_priv_path(k, c, "m")
        assert k2 == k

    def test_invalid_path_prefix_raises(self):
        with pytest.raises(ValueError, match="must start with m/"):
            core.derive_priv_path(1, b"\x01" * 32, "x/0")


# ---------------------------------------------------------------------------
# F-04: is_hex rejects negative and edge cases
# ---------------------------------------------------------------------------

class TestIsHex:
    def test_valid_hex(self):
        assert core.is_hex("0123456789abcdef") is True
        assert core.is_hex("ABCDEF") is True
        assert core.is_hex("0" * 64) is True

    def test_rejects_negative(self):
        assert core.is_hex("-1") is False
        assert core.is_hex("-ff") is False

    def test_rejects_empty(self):
        assert core.is_hex("") is False

    def test_rejects_non_hex(self):
        assert core.is_hex("xyz") is False
        assert core.is_hex("0xABCD") is False  # contains 'x'
        assert core.is_hex(" ") is False


# ---------------------------------------------------------------------------
# F-05: validate_mnemonic
# ---------------------------------------------------------------------------

ABANDON_12 = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


class TestValidateMnemonic:
    def test_valid_mnemonic_passes(self):
        core.validate_mnemonic(ABANDON_12)

    def test_wrong_word_count_raises(self):
        with pytest.raises(ValueError, match="words"):
            core.validate_mnemonic("abandon abandon abandon")

    def test_unknown_word_raises(self):
        bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz"
        with pytest.raises(ValueError, match="not in the BIP39 wordlist"):
            core.validate_mnemonic(bad)

    def test_checksum_mismatch_raises(self):
        # Replace last word with a valid BIP39 word that gives wrong checksum
        bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        with pytest.raises(ValueError, match="checksum"):
            core.validate_mnemonic(bad)


# ---------------------------------------------------------------------------
# F-10: End-to-end BTC address test vector (BIP84 official)
# ---------------------------------------------------------------------------

class TestBTCAddressVector:
    """BIP84 official test vector: abandon*11 + about -> bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"""

    def test_btc_first_receive_address(self):
        btc = core.derive_btc_addresses(ABANDON_12, "", account=0, change=0, start=0, count=1)
        path, addr, _ = btc[0]
        assert path == "m/84'/0'/0'/0/0"
        assert addr == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


# ---------------------------------------------------------------------------
# F-10: End-to-end ETH address test vector
# ---------------------------------------------------------------------------

class TestETHAddressVector:
    """Abandon*11 + about -> 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 (m/44'/60'/0'/0/0)"""

    def test_eth_first_address(self):
        eth = core.derive_eth_addresses(ABANDON_12, "", account=0, start=0, count=1)
        path, addr = eth[0]
        assert path == "m/44'/60'/0'/0/0"
        assert addr == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"


# ---------------------------------------------------------------------------
# F-11: VALID_NIBBLES error message uses sorted()
# ---------------------------------------------------------------------------

class TestErrorMessages:
    def test_entropy_error_shows_sorted_lengths(self):
        with pytest.raises(ValueError, match=r"\[32, 40, 48, 56, 64\]"):
            core.entropy_to_mnemonic("abc")
