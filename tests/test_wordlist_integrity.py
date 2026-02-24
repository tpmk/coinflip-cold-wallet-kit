from pathlib import Path
from uuid import uuid4

import pytest

import wallet_core as core


def test_rejects_tampered_wordlist_even_if_word_count_is_2048():
    original = Path("wordlist.txt").read_text(encoding="utf-8").splitlines()
    assert len(original) == 2048

    tampered = original.copy()
    tampered[0] = "zzzzzz"
    tampered_path = Path(f".tmp_wordlist_tampered_{uuid4().hex}.txt")
    try:
        tampered_path.write_text("\n".join(tampered) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="SHA256 mismatch"):
            core.read_wordlist(str(tampered_path))
    finally:
        if tampered_path.exists():
            tampered_path.unlink()
