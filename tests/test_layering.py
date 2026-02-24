import subprocess
import sys


def test_wallet_core_does_not_import_coin_flip_wallet():
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import wallet_core; "
            "print('coin_flip_wallet' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "False"


def test_coin_flip_reexports_core_derivation_functions():
    import coin_flip_wallet as cfw
    import wallet_core as core

    assert cfw.derive_btc_addresses is core.derive_btc_addresses
    assert cfw.derive_eth_addresses is core.derive_eth_addresses


def test_coin_to_bip39_reexports_core_entropy_converter():
    import coin_to_bip39_hex as c2b
    import wallet_core as core

    assert c2b.entropy_to_mnemonic is core.entropy_to_mnemonic
