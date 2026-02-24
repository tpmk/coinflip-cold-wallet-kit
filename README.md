# CoinFlip Cold Wallet Kit

离线钱包工具集：从熵值生成 BIP39 助记词，并派生 BTC/ETH 地址。  
项目采用 `uv` 管理依赖，默认以“离线、安全、可验证”为使用前提。

本项目强调三点：

- 抛硬币获取物理熵，降低对软件伪随机数的信任依赖
- 仅需硬币和离线电脑，低成本即可搭建冷钱包生成流程
- 助记词与派生过程全程本地离线，形成更清晰的安全边界

## 1. 适用范围与安全声明

本项目适用于：

- 学习 BIP39/BIP32/BIP44/BIP84 派生流程
- 在离线环境做可审计的地址推导
- 对助记词与地址生成流程进行本地验证

本项目不提供：

- 资金托管或在线服务能力
- 硬件钱包级安全保障
- 已审计生产级钱包实现

关键安全原则：

- 仅在断网或气隙环境运行
- 助记词仅纸质备份，不拍照不截图
- 不在联网设备输入真实资产助记词
- 完成后清理终端历史和临时文件
- `wordlist.txt` 在加载时会做 SHA256 固定值校验，防止被静默篡改

## 2. 功能总览

### 2.1 CLI 脚本

- `coin_flip_wallet.py`
  - 交互模式：模拟物理抛硬币输入（每轮 4 bit，共 64 轮）
  - 批量模式：直接输入 64 位 hex 熵值
  - 生成 BIP39 助记词
  - 派生 BTC(BIP84) 与 ETH(BIP44) 地址

- `coin_to_bip39_hex.py`
  - 支持 `bits` 或 `hex` 输入
  - 输出 BIP39 助记词和 11-bit 索引（便于核对）

- `derive_addresses_offline.py`
  - 输入助记词与可选 passphrase
  - 派生 BTC/ETH 地址（watch-only 输出）

### 2.2 核心模块

- `wallet_core.py`
  - 项目统一的密码学与派生核心
  - 所有 CLI 统一复用，减少重复实现和漂移风险

## 3. 架构与数据流

统一流程：

1. 熵输入（hex 或 bits 或交互输入）
2. 熵 + checksum -> BIP39 助记词
3. 助记词 + passphrase -> seed（PBKDF2-HMAC-SHA512）
4. seed -> BIP32 主密钥 -> 子路径派生
5. 地址编码：
   - BTC：BIP84 / bech32 / P2WPKH
   - ETH：BIP44 / EIP-55 校验地址

## 4. 环境要求

- Python `>=3.10`
- `uv`（推荐）
- 离线词库文件：`wordlist.txt`（2048 英文单词）

依赖由 `pyproject.toml` 管理：

- 运行依赖：`pycryptodome`
- 开发依赖：`pytest`

## 5. 快速开始（uv）

### 5.1 安装依赖

```bash
uv sync --dev
```

### 5.2 运行测试

```bash
uv run python -m pytest -q
```

### 5.3 一条命令试跑（测试向量）

```bash
uv run python coin_to_bip39_hex.py --hex 00000000000000000000000000000000
```

## 6. 命令详解

### 6.1 `coin_flip_wallet.py`

用途：从熵值直接生成助记词与地址。

基本命令：

```bash
# 交互式（推荐手动离线操作）
uv run python coin_flip_wallet.py --interactive

# 批量 hex 输入
uv run python coin_flip_wallet.py --hex <64位hex>

# 批量非交互（跳过 Enter 确认）
uv run python coin_flip_wallet.py --hex <64位hex> --yes
```

参数说明：

- `--interactive`, `-i`：交互输入 0/1 比特
- `--hex`：64 位 hex 熵值
- `--wordlist`：词库路径，默认 `wordlist.txt`
- `--passphrase`：BIP39 passphrase（可选）
- `--yes`：跳过启动时 Enter 确认（用于脚本场景）

输出内容：

- 256-bit 熵值（hex）
- BIP39 助记词
- BTC 接收地址 5 个 + 找零地址 2 个
- ETH 地址 5 个

### 6.2 `coin_to_bip39_hex.py`

用途：将 bits/hex 熵值转换为 BIP39 助记词。

基本命令：

```bash
uv run python coin_to_bip39_hex.py --hex <hex>
uv run python coin_to_bip39_hex.py --hex-file my_entropy_hex.txt
uv run python coin_to_bip39_hex.py --bits <01比特串>
uv run python coin_to_bip39_hex.py --bits-file bits.txt
```

参数说明：

- `--hex` / `--hex-file`
- `--bits` / `--bits-file`
- `--wordlist`：词库路径（默认 `wordlist.txt`）

约束：

- `bits` 长度必须是 `128/160/192/224/256`
- `hex` 长度必须是 `32/40/48/56/64`

### 6.3 `derive_addresses_offline.py`

用途：仅从助记词派生地址，不做熵采集。

基本命令：

```bash
uv run python derive_addresses_offline.py \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --btc-count 3 \
  --eth-count 3
```

参数说明（核心）：

- `--mnemonic`：必填
- `--passphrase`：可选
- `--btc-count` / `--eth-count`：需要大于 0 才会输出
- `--btc-account` / `--btc-change` / `--btc-start`
- `--eth-account` / `--eth-start`
- `--btc-hrp`：`bc` 或 `tb`

## 7. 安全上手流程（建议照做）

1. 准备离线环境（断网/Live OS/专用机）
2. 执行 `uv sync --dev`
3. 执行 `uv run python -m pytest -q`
4. 用测试向量先跑通命令
5. 再处理真实熵值
6. 手抄助记词并核对
7. 清理终端与临时文件

## 8. 测试与验证策略

当前测试覆盖：

- BIP39 官方向量（助记词 + seed）
- BTC/ETH 派生回归
- 非项目根目录运行时词库加载
- 分层约束（CLI 复用 `wallet_core`）
- `--yes` 非交互路径

常用验证命令：

```bash
uv run python -m pytest -q
```

## 9. 项目结构

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
|  `- test_layering.py
|- pyproject.toml
|- uv.lock
`- docs/
   |- PROJECT_OVERVIEW.md
   `- plans/
```

## 10. 常见问题（FAQ）

### Q1: 运行时报 `Wordlist file not found`？

- 确认 `wordlist.txt` 存在且为 2048 词
- 或显式传入 `--wordlist /path/to/wordlist.txt`

### Q1.1: 运行时报 `Wordlist SHA256 mismatch`？

- 说明词库文件内容与项目固定值不一致（可能被修改/换行符变化/非官方文件）
- 请替换为官方 BIP39 英文词库并保持原始内容

### Q2: 为什么提示 RIPEMD160 / Keccak 缺失？

- 当前环境密码后端不完整
- 执行 `uv sync --dev` 安装 `pycryptodome`

### Q3: `derive_addresses_offline.py` 没有输出？

- 需至少设置一个大于 0 的计数：
  - `--btc-count > 0` 或
  - `--eth-count > 0`

### Q4: 可以在线机器运行吗？

- 技术上可以运行，安全上不建议处理真实资产
- 对真实资产请始终离线

## 11. 免责声明

本项目仅用于学习和技术研究。  
涉及真实资产时，风险由使用者自行承担。建议优先使用经过长期审计的成熟硬件钱包方案。
