from pathlib import Path

import pytest

import wallet_core as core


def test_rejects_tampered_wordlist_even_if_word_count_is_2048(tmp_path):
    original = (core.PROJECT_DIR / "wordlist.txt").read_text(encoding="utf-8").splitlines()
    assert len(original) == 2048

    tampered = original.copy()
    tampered[0] = "zzzzzz"
    tampered_path = tmp_path / "tampered_wordlist.txt"
    tampered_path.write_text("\n".join(tampered) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        core.read_wordlist(str(tampered_path))
