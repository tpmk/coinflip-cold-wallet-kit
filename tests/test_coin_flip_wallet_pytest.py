from pathlib import Path

import pytest

from coin_flip_wallet import entropy_to_mnemonic, mnemonic_to_seed


ABANDON_12 = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_entropy_to_mnemonic_bip39_vector_1():
    mnemonic = entropy_to_mnemonic("00000000000000000000000000000000")
    assert mnemonic == ABANDON_12


def test_mnemonic_to_seed_bip39_vector_with_trezor_passphrase():
    seed = mnemonic_to_seed(ABANDON_12, "TREZOR")
    assert (
        seed.hex()
        == "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e"
        "9efa3708e53495531f09a6987599d18264c1e1c92f2cf141"
        "630c7a3c4ab7c81b2f001698e7463b04"
    )


def test_default_wordlist_resolution_not_tied_to_cwd(monkeypatch):
    docs_dir = Path(__file__).resolve().parents[1] / "docs"
    monkeypatch.chdir(docs_dir)
    mnemonic = entropy_to_mnemonic("00000000000000000000000000000000")
    assert mnemonic == ABANDON_12
