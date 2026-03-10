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
