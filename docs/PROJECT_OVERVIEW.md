# 项目总览（hex-to-bip-address）

## 目标

该项目提供离线钱包相关工具，覆盖三类能力：

1. 从熵值生成 BIP39 助记词
2. 从助记词派生 BTC/ETH 地址
3. 通过交互式“抛硬币”流程获取 256-bit 熵值

## 核心文件

- `coin_flip_wallet.py`
  - 交互式/批量熵输入
  - BIP39 助记词生成
  - BTC(BIP84) + ETH(BIP44) 地址派生
- `wallet_core.py`
  - 共享派生核心接口（供多个脚本复用）
- `coin_to_bip39_hex.py`
  - bits/hex 到 BIP39 助记词转换（复用 `wallet_core.py`）
- `derive_addresses_offline.py`
  - watch-only CLI（通过 `wallet_core.py` 调用共享派生逻辑）
- `wordlist.txt`
  - BIP39 英文词库（2048 词）
- `test_coin_flip_wallet.py`
  - 命令行回归测试脚本
- `tests/test_coin_flip_wallet_pytest.py`
  - pytest 自动化测试

## 数据流

1. 熵输入（hex/bits/抛硬币）
2. 熵 + 校验位 -> 助记词（BIP39）
3. 助记词 + passphrase -> seed（PBKDF2-HMAC-SHA512）
4. seed -> BIP32 主密钥 -> 按路径派生子密钥
5. 公钥编码 -> BTC bech32 或 ETH EIP-55 地址

## 安全边界

- 设计定位是“离线工具”，不是在线服务。
- 私钥相关信息不应写盘或联网传输。
- 助记词属于最高敏感信息，只建议纸质备份。
- `wordlist.txt` 是运行时关键资源，默认相对脚本目录加载。

## 运行与验证（uv）

```bash
uv sync --dev
uv run python -m pytest -q
uv run python test_coin_flip_wallet.py
```
