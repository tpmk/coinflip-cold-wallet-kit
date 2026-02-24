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


def test_derive_addresses_supports_passphrase_stdin():
    proc = run_script(
        "derive_addresses_offline.py",
        "--mnemonic",
        ABANDON_12,
        "--btc-count",
        "1",
        "--passphrase-stdin",
        input_text="TREZOR\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert "=== BTC (BIP84 P2WPKH) ===" in proc.stdout


def test_coin_flip_wallet_supports_passphrase_stdin():
    proc = run_script(
        "coin_flip_wallet.py",
        "--hex",
        "0" * 64,
        "--yes",
        "--passphrase-stdin",
        input_text="TREZOR\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert "助记词(BIP39)" in proc.stdout


def test_derive_addresses_warns_on_plaintext_passphrase():
    proc = run_script(
        "derive_addresses_offline.py",
        "--mnemonic",
        ABANDON_12,
        "--btc-count",
        "1",
        "--passphrase",
        "plain-secret",
    )
    assert proc.returncode == 0, proc.stderr
    assert "WARNING" in proc.stderr
    assert "--passphrase" in proc.stderr


def test_coin_flip_wallet_warns_on_plaintext_passphrase():
    proc = run_script(
        "coin_flip_wallet.py",
        "--hex",
        "0" * 64,
        "--yes",
        "--passphrase",
        "plain-secret",
    )
    assert proc.returncode == 0, proc.stderr
    assert "WARNING" in proc.stderr
    assert "--passphrase" in proc.stderr


def test_derive_addresses_rejects_negative_account_without_traceback():
    proc = run_script(
        "derive_addresses_offline.py",
        "--mnemonic",
        ABANDON_12,
        "--btc-count",
        "1",
        "--btc-account",
        "-1",
    )
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert "btc-account" in proc.stderr


def test_derive_addresses_rejects_overflow_account_without_traceback():
    proc = run_script(
        "derive_addresses_offline.py",
        "--mnemonic",
        ABANDON_12,
        "--btc-count",
        "1",
        "--btc-account",
        str(2**31),
    )
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert "btc-account" in proc.stderr


def test_readme_documents_bip39_standalone_provenance():
    zh = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    en = (PROJECT_ROOT / "README_EN.md").read_text(encoding="utf-8")
    assert "bip39-standalone.html" in zh
    assert "bip39-standalone.html" in en
    assert "iancoleman" in zh.lower()
    assert "iancoleman" in en.lower()
