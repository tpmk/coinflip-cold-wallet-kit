#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
硬币熵钱包生成器 - Coin Flip Wallet Generator

CLI layer only:
- Entropy collection (interactive/batch)
- Output formatting and safety prompts
- Delegates cryptographic derivation to wallet_core
"""

import argparse
import getpass
import sys

from wallet_core import (
    derive_btc_addresses,
    derive_eth_addresses,
    entropy_to_mnemonic,
    is_hex,
    keccak_256,
    mnemonic_to_seed,
    ripemd160,
    validate_mnemonic,
)


class EntropyCollector:
    """硬币抛掷熵值收集器"""

    def __init__(self, coins_per_flip=4):
        self.coins_per_flip = coins_per_flip
        self.total_bits = 256
        self.total_rounds = self.total_bits // coins_per_flip

    def _validate_input(self, user_input: str) -> bool:
        cleaned = user_input.strip()
        if len(cleaned) != self.coins_per_flip:
            return False
        if not all(c in "01" for c in cleaned):
            return False
        return True

    def _binary_to_hex(self, binary_str: str) -> str:
        if len(binary_str) != 256:
            raise ValueError(f"Binary string must be 256 bits, got {len(binary_str)}")
        return hex(int(binary_str, 2))[2:].zfill(64)

    def collect_interactive(self) -> str:
        print("\n开始收集熵值...")
        print(f"每轮请抛{self.coins_per_flip}枚硬币，总共{self.total_rounds}轮")
        print("用 1 表示正面，0 表示反面\n")

        bits = []
        for round_num in range(1, self.total_rounds + 1):
            while True:
                user_input = input(
                    f"第 {round_num}/{self.total_rounds} 轮: "
                    f"请输入{self.coins_per_flip}个数字 (0或1): "
                )
                if self._validate_input(user_input):
                    bits.append(user_input.strip())
                    break
                print(f"❌ 输入无效，请输入{self.coins_per_flip}个数字(仅0或1)")

        hex_entropy = self._binary_to_hex("".join(bits))
        print("\n✓ 熵值收集完成!")
        return hex_entropy

    def collect_batch(self, hex_input: str) -> str:
        hex_cleaned = hex_input.strip().lower().removeprefix("0x")
        if not is_hex(hex_cleaned):
            raise ValueError("Invalid hex string: must contain only 0-9 and a-f")
        if len(hex_cleaned) != 64:
            raise ValueError(
                f"Hex entropy must be exactly 64 characters (256 bits), got {len(hex_cleaned)}"
            )
        return hex_cleaned


def show_security_warning(require_confirmation: bool = True):
    print(
        """
╔═══════════════════════════════════════════════════════╗
║      硬币熵钱包生成器 - 离线安全版 v1.0              ║
║      Coin Flip Wallet Generator                        ║
╚═══════════════════════════════════════════════════════╝

⚠️  安全提醒：
  1. 请确保设备已断网（拔掉网线/关闭WiFi）
  2. 建议在Live OS或虚拟机中运行
  3. 使用真实硬币抛掷，避免伪随机数
  4. 完成后请销毁屏幕历史记录
"""
    )
    if require_confirmation:
        print("按 Enter 继续...")
        input()


def show_completion_reminder():
    print(
        """
╔═══════════════════════════════════════════════════════╗
║                  生成完成！                            ║
╚═══════════════════════════════════════════════════════╝

📝 下一步操作：
  1. ✓ 手抄助记词到纸上（建议多份备份）
  2. ✓ 验证抄写无误（重新输入验证）
  3. ✓ 安全保存纸质备份（防火防水）
  4. ✓ 清除屏幕历史：clear 或 cls
  5. ✓ 关闭终端窗口

⚠️  警告：
  - 助记词一旦丢失，资产将永久丢失
  - 切勿截图、拍照或数字化存储助记词
  - 切勿向任何人透露助记词
"""
    )


def format_output(entropy_hex: str, mnemonic: str, btc_receive, btc_change, eth_addrs):
    print("\n" + "=" * 60)
    print("熵值(Hex-256bit):", entropy_hex[:32])
    print("                 ", entropy_hex[32:])
    print()
    print("助记词(BIP39):", mnemonic)
    print("=" * 60)

    print("\n比特币地址 (BIP84 P2WPKH - bc1):")
    print("  接收地址:")
    for i, (_, addr, _) in enumerate(btc_receive):
        print(f"    #{i}: {addr}")

    print("  找零地址:")
    for i, (_, addr, _) in enumerate(btc_change):
        print(f"    #{i}: {addr}")

    print("=" * 60)
    print("\n以太坊地址 (BIP44):")
    for i, (_, addr) in enumerate(eth_addrs):
        print(f"    #{i}: {addr}")
    print("=" * 60 + "\n")


def check_crypto_dependencies():
    errors = []
    try:
        ripemd160(b"test")
    except RuntimeError:
        errors.append("RIPEMD160不可用 - BTC地址生成将失败")
        errors.append("  解决方案: pip install pycryptodome")

    try:
        keccak_256(b"test")
    except RuntimeError:
        errors.append("Keccak256不可用 - ETH地址生成将失败")
        errors.append("  解决方案: pip install pycryptodome")

    if errors:
        print("⚠️  依赖检查警告:")
        for err in errors:
            print(f"  {err}")
        print()


def resolve_passphrase(args) -> str:
    if args.passphrase_stdin:
        if sys.stdin.isatty():
            raise ValueError("--passphrase-stdin 需要通过管道提供输入")
        return sys.stdin.readline().rstrip("\r\n")
    if args.passphrase_prompt:
        return getpass.getpass("请输入 BIP39 密码短语（可留空）: ")
    if args.passphrase is not None:
        print(
            "WARNING: --passphrase 会暴露在进程列表和历史命令中；"
            "建议改用 --passphrase-stdin 或 --passphrase-prompt。",
            file=sys.stderr,
        )
        return args.passphrase
    return ""


def main():
    parser = argparse.ArgumentParser(
        description="硬币熵钱包生成器 - 完全离线的BTC/ETH钱包生成工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  交互模式 (推荐):
    python coin_flip_wallet.py --interactive

  批量模式:
    python coin_flip_wallet.py --hex a3f7c2e9b1d486520fa3e7c1b9d2f5e8a4c6d1f3b7e2a5c8d9f1e4b6a2c7d3f8

  使用密码短语（高风险，不推荐命令行明文）:
    python coin_flip_wallet.py --interactive --passphrase "my secret phrase"

  更安全：从 stdin 读取密码短语:
    echo "my secret phrase" | python coin_flip_wallet.py --hex <64位hex> --passphrase-stdin --yes

  交互模式建议使用隐藏输入:
    python coin_flip_wallet.py --interactive --passphrase-prompt
""",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="交互模式：逐轮输入抛硬币结果（64轮，每轮4个数字）",
    )
    group.add_argument("--hex", type=str, help="批量模式：直接提供64位十六进制熵值")
    parser.add_argument("--wordlist", default="wordlist.txt", help="BIP39词库文件路径（默认: wordlist.txt）")
    passphrase_group = parser.add_mutually_exclusive_group()
    passphrase_group.add_argument(
        "--passphrase",
        default=None,
        help=(
            "BIP39可选密码短语（高风险：命令行参数会暴露在进程列表和历史命令中；"
            "建议使用 --passphrase-stdin 或 --passphrase-prompt）"
        ),
    )
    passphrase_group.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="从stdin读取BIP39密码短语（推荐脚本场景）",
    )
    passphrase_group.add_argument(
        "--passphrase-prompt",
        action="store_true",
        help="通过隐藏输入交互读取BIP39密码短语（推荐交互场景）",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="跳过启动时按 Enter 确认（适合批量非交互运行）",
    )
    args = parser.parse_args()
    if args.interactive and args.passphrase_stdin:
        parser.error(
            "--interactive 不能与 --passphrase-stdin 同时使用；"
            "请改用 --passphrase-prompt。"
        )

    try:
        check_crypto_dependencies()
        show_security_warning(require_confirmation=not args.yes and not args.passphrase_stdin)

        collector = EntropyCollector(coins_per_flip=4)
        passphrase = resolve_passphrase(args)
        if args.interactive:
            entropy_hex = collector.collect_interactive()
        else:
            entropy_hex = collector.collect_batch(args.hex)

        print("\n正在生成助记词...")
        mnemonic = entropy_to_mnemonic(entropy_hex, args.wordlist)
        validate_mnemonic(mnemonic, args.wordlist)

        print("正在派生地址...")
        btc_receive = derive_btc_addresses(mnemonic, passphrase, account=0, change=0, start=0, count=5)
        btc_change = derive_btc_addresses(mnemonic, passphrase, account=0, change=1, start=0, count=2)
        eth_addrs = derive_eth_addresses(mnemonic, passphrase, account=0, start=0, count=5)

        format_output(entropy_hex, mnemonic, btc_receive, btc_change, eth_addrs)
        show_completion_reminder()

    except FileNotFoundError as e:
        print(f"❌ 错误: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"❌ 输入错误: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"❌ 运行时错误: {e}")
        sys.exit(1)
    except EOFError:
        print("❌ 输入流已结束：交互模式需要终端输入。若脚本化请使用 --hex。")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  用户中断操作")
        print("   提示: 已输入的数据未保存")
        sys.exit(0)


if __name__ == "__main__":
    main()
