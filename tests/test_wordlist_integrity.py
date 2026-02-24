import shutil
import uuid

import pytest

import wallet_core as core


def test_rejects_tampered_wordlist_even_if_word_count_is_2048():
    original = (core.PROJECT_DIR / "wordlist.txt").read_text(encoding="utf-8").splitlines()
    assert len(original) == 2048

    tampered = original.copy()
    tampered[0] = "zzzzzz"
    temp_dir = core.PROJECT_DIR / "tests" / f".tmp-wordlist-{uuid.uuid4().hex}"
    temp_dir.mkdir(parents=True, exist_ok=False)
    try:
        tampered_path = temp_dir / "tampered_wordlist.txt"
        tampered_path.write_text("\n".join(tampered) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="SHA256 mismatch"):
            core.read_wordlist(str(tampered_path))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
