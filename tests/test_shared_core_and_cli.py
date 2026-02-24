import subprocess
import sys
from pathlib import Path

import coin_flip_wallet as cfw


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ABANDON_12 = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_wallet_core_derivation_matches_coin_flip_wallet():
    from wallet_core import derive_btc_addresses, derive_eth_addresses

    btc_from_core = derive_btc_addresses(ABANDON_12, "", count=2)
    btc_from_cfw = cfw.derive_btc_addresses(ABANDON_12, "", count=2)
    assert btc_from_core == btc_from_cfw

    eth_from_core = derive_eth_addresses(ABANDON_12, "", count=2)
    eth_from_cfw = cfw.derive_eth_addresses(ABANDON_12, "", count=2)
    assert eth_from_core == eth_from_cfw


def test_hex_mode_can_skip_enter_prompt_with_yes_flag():
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "coin_flip_wallet.py"),
        "--hex",
        "0" * 64,
        "--yes",
    ]
    proc = subprocess.run(
        cmd,
        cwd=PROJECT_ROOT / "docs",
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert proc.returncode == 0, proc.stderr
    assert "按 Enter 继续" not in proc.stdout
