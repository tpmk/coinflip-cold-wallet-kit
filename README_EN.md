# CoinFlip Cold Wallet Kit

[中文说明 (Chinese README)](README.md)

Offline wallet toolkit for generating BIP39 mnemonics from entropy and deriving BTC/ETH addresses.  
Dependencies are managed with `uv`, with an offline-first, security-first workflow.

Core positioning:

- Use physical coin flips as entropy to reduce trust in PRNGs.
- Build a cold-wallet generation flow at very low cost (coins + offline machine).
- Keep mnemonic generation and derivation fully local and offline.

## 1. Scope and Security Notice

This project is suitable for:

- Learning BIP39/BIP32/BIP44/BIP84 derivation flow
- Auditable offline address derivation
- Local mnemonic/address verification

This project does not provide:

- Custody services
- Hardware-wallet-grade guarantees
- Formally audited production wallet implementation

Security rules:

- Run on an offline/air-gapped environment
- Keep mnemonics on paper only (no screenshots/photos)
- Never enter real mnemonics on online machines
- Clear terminal history and temporary traces after use
- `wordlist.txt` is checked against a pinned SHA256 to detect tampering

## 2. Components

### 2.1 CLI tools

- `coin_flip_wallet.py`
  - Interactive coin-flip input (4 bits per round, 64 rounds)
  - Batch 64-hex entropy input
  - BIP39 mnemonic generation
  - BTC(BIP84) + ETH(BIP44) address derivation

- `coin_to_bip39_hex.py`
  - Convert `bits` or `hex` entropy to BIP39 mnemonic
  - Output 11-bit indexes for manual verification

- `derive_addresses_offline.py`
  - Derive BTC/ETH addresses from mnemonic (+ optional passphrase)
  - Watch-only output

### 2.2 Shared core

- `wallet_core.py`
  - Shared cryptographic and derivation implementation
  - Reused by all CLI tools to prevent logic drift

## 3. Architecture / Data Flow

1. Entropy input (`hex`, `bits`, or interactive)
2. Entropy + checksum -> BIP39 mnemonic
3. Mnemonic + passphrase -> seed (PBKDF2-HMAC-SHA512)
4. Seed -> BIP32 master key -> child path derivation
5. Address encoding:
   - BTC: BIP84 / bech32 / P2WPKH
   - ETH: BIP44 / EIP-55 checksum address

## 4. Requirements

- Python `>=3.10`
- `uv` (recommended)
- `wordlist.txt` (official 2048 English words)

Managed in `pyproject.toml`:

- Runtime: `pycryptodome`
- Dev: `pytest`

## 5. Quick Start (uv)

### 5.1 Install

```bash
uv sync --dev
```

### 5.2 Test

```bash
uv run python -m pytest -q
```

### 5.3 Sanity check (test vector)

```bash
uv run python coin_to_bip39_hex.py --hex 00000000000000000000000000000000
```

## 6. CLI Usage

### 6.1 `coin_flip_wallet.py`

```bash
# Interactive mode (recommended for manual offline flow)
uv run python coin_flip_wallet.py --interactive

# Batch hex mode
uv run python coin_flip_wallet.py --hex <64-hex>

# Non-interactive batch mode (skip Enter confirmation)
uv run python coin_flip_wallet.py --hex <64-hex> --yes

# Safer: read passphrase from stdin
echo "my secret" | uv run python coin_flip_wallet.py --hex <64-hex> --yes --passphrase-stdin

# Safer: hidden passphrase prompt
uv run python coin_flip_wallet.py --interactive --passphrase-prompt
```

Arguments:

- `--interactive`, `-i`
- `--hex`
- `--wordlist` (default: `wordlist.txt`)
- `--passphrase` (HIGH RISK: visible in process list and shell history)
- `--passphrase-stdin` (recommended for scripts)
- `--passphrase-prompt` (recommended for interactive sessions)
- `--yes`

Output:

- 256-bit entropy (hex)
- BIP39 mnemonic
- BTC receive addresses (5) + change addresses (2)
- ETH addresses (5)

### 6.2 `coin_to_bip39_hex.py`

```bash
uv run python coin_to_bip39_hex.py --hex <hex>
uv run python coin_to_bip39_hex.py --hex-file my_entropy_hex.txt
uv run python coin_to_bip39_hex.py --bits <bitstring>
uv run python coin_to_bip39_hex.py --bits-file bits.txt
```

Constraints:

- `bits` length must be `128/160/192/224/256`
- `hex` length must be `32/40/48/56/64`

### 6.3 `derive_addresses_offline.py`

```bash
uv run python derive_addresses_offline.py \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --btc-count 3 \
  --eth-count 3

# Safer: read passphrase from stdin
echo "my secret" | uv run python derive_addresses_offline.py \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --btc-count 3 \
  --passphrase-stdin
```

Key arguments:

- `--mnemonic` (required)
- `--passphrase` (optional, HIGH RISK on shared systems)
- `--passphrase-stdin` / `--passphrase-prompt` (safer alternatives)
- `--btc-count`, `--eth-count` (at least one > 0)
- `--btc-account`, `--btc-change`, `--btc-start`, `--btc-hrp`
- `--eth-account`, `--eth-start`

## 7. Recommended Secure Workflow

1. Prepare an offline environment
2. Run `uv sync --dev`
3. Run `uv run python -m pytest -q`
4. Validate with known test vectors first
5. Process real entropy only after validation
6. Write mnemonic on paper and verify manually
7. Remove traces/history

## 8. Testing Strategy

Current coverage includes:

- BIP39 official vectors (mnemonic + seed)
- BTC/ETH derivation regression
- Wordlist path and layered architecture checks
- Non-interactive `--yes` path
- Wordlist SHA256 integrity enforcement

## 9. Project Structure

```text
.
|- wallet_core.py
|- coin_flip_wallet.py
|- coin_to_bip39_hex.py
|- derive_addresses_offline.py
|- wordlist.txt
|- tests/
|  |- test_coin_flip_wallet_pytest.py
|  |- test_shared_core_and_cli.py
|  |- test_layering.py
|  `- test_wordlist_integrity.py
|- pyproject.toml
|- uv.lock
`- docs/
   |- PROJECT_OVERVIEW.md
   `- plans/
```

## 10. FAQ

### Q1: `Wordlist file not found`

- Ensure `wordlist.txt` exists and has 2048 words.
- Or pass `--wordlist /path/to/wordlist.txt`.

### Q1.1: `Wordlist SHA256 mismatch`

- Your wordlist content differs from the pinned official hash.
- Replace with the official BIP39 English wordlist content.

### Q2: Missing RIPEMD160 / Keccak backend

- Install runtime dependencies:

```bash
uv sync --dev
```

### Q3: `derive_addresses_offline.py` prints nothing

- Set at least one of:
  - `--btc-count > 0`
  - `--eth-count > 0`

## 11. Disclaimer

For education and technical research only.  
You are fully responsible for any real-asset risk when using this project.

## 12. Reference File Provenance

- `bip39-standalone.html` is kept as a reference-only offline artifact and is not used by the core derivation path.
- Upstream source: `iancoleman/bip39`  
  Repo: https://github.com/iancoleman/bip39  
  Releases: https://github.com/iancoleman/bip39/releases/latest/
- Embedded version marker in the file: `v0.5.6` (page `.version` text)
- Current file SHA256: `129b03505824879b8a4429576e3de6951c8599644c1afcaae80840f79237695a`
