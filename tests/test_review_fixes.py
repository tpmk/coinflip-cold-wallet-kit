import re
import subprocess
import sys
from pathlib import Path

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


def _first_btc_address(output: str) -> str:
    match = re.search(r"#0:\s*(bc1[0-9a-z]+)", output)
    assert match is not None, f"cannot find first BTC address in output:\n{output}"
    return match.group(1)


def test_coin_flip_wallet_passphrase_stdin_not_consumed_by_confirmation():
    with_yes = run_script(
        "coin_flip_wallet.py",
        "--hex",
        "0" * 64,
        "--yes",
        "--passphrase-stdin",
        input_text="TREZOR\n",
    )
    without_yes = run_script(
        "coin_flip_wallet.py",
        "--hex",
        "0" * 64,
        "--passphrase-stdin",
        input_text="TREZOR\n",
    )

    assert with_yes.returncode == 0, with_yes.stderr
    assert without_yes.returncode == 0, without_yes.stderr
    assert _first_btc_address(with_yes.stdout) == _first_btc_address(without_yes.stdout)


def test_coin_flip_wallet_rejects_interactive_with_passphrase_stdin_without_traceback():
    proc = run_script(
        "coin_flip_wallet.py",
        "--interactive",
        "--yes",
        "--passphrase-stdin",
        input_text="TREZOR\n",
    )
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert "interactive" in proc.stderr.lower() and "passphrase-stdin" in proc.stderr


def test_derive_addresses_rejects_invalid_btc_hrp():
    proc = run_script(
        "derive_addresses_offline.py",
        "--mnemonic",
        ABANDON_12,
        "--btc-count",
        "1",
        "--btc-hrp",
        "zz",
    )
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert "invalid choice" in proc.stderr.lower()


def test_derive_btc_testnet_uses_coin_type_1():
    btc = core.derive_btc_addresses(ABANDON_12, "", account=0, change=0, start=0, count=1, hrp="tb")
    path, addr, _ = btc[0]
    assert path == "m/84'/1'/0'/0/0"
    assert addr == "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"
