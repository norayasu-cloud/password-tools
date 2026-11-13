#!/usr/bin/env python3
"""パスワード生成＆強さチェックツール

使い方:
  python password_tool.py gen [--length 16] [--count 3] [--no-symbols] [--exclude-ambiguous]
  python password_tool.py check

- gen: 暗号学的に安全な乱数（secrets モジュール）でパスワードを生成します。
- check: パスワードを入力（画面には表示されません）して、強さを判定します。
  判定は目安です。入力したパスワードが保存・送信されることはありません。

標準ライブラリだけを使うので、追加のインストールは不要です（Python 3.10 以上）。
"""

import argparse
import getpass
import math
import re
import secrets
import string
import sys

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
# 紛らわしくなりにくい、実用的な記号のセット
SYMBOLS = "!#$%&*+,-.:;=?@^_~"
# --exclude-ambiguous で取り除く紛らわしい文字
AMBIGUOUS = "Il1O0|`'\"()[]{}<>/\\"

# よく使われていて危険なパスワードの例
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein",
    "welcome", "monkey", "dragon", "football", "iloveyou", "sunshine",
    "master", "shadow", "superman", "trustno1", "passw0rd",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def build_charset(use_symbols: bool, exclude_ambiguous: bool) -> tuple[str, list[str]]:
    """使える文字の集合と、種類ごとのグループを返す。"""
    groups = [LOWER, UPPER, DIGITS]
    if use_symbols:
        groups.append(SYMBOLS)
    if exclude_ambiguous:
        groups = ["".join(c for c in g if c not in AMBIGUOUS) for g in groups]
        groups = [g for g in groups if g]
    return "".join(groups), groups


def generate_password(length: int, use_symbols: bool = True,
                      exclude_ambiguous: bool = False) -> str:
    """各グループから最低1文字を含むパスワードを生成する。"""
    charset, groups = build_charset(use_symbols, exclude_ambiguous)
    if length < len(groups):
        raise ValueError("長さが短すぎます（使う文字の種類より長くしてください）")
    chars = [secrets.choice(g) for g in groups]
    chars += [secrets.choice(charset) for _ in range(length - len(chars))]
    # 位置をランダムに入れ替える（Fisher-Yates、乱数は secrets を使用）
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def pool_size(pw: str) -> int:
    """パスワードに使われている文字種から、候補の総数をざっくり見積もる。"""
    pool = 0
    if any(c in LOWER for c in pw):
        pool += 26
    if any(c in UPPER for c in pw):
        pool += 26
    if any(c in DIGITS for c in pw):
        pool += 10
    if any(c in SYMBOLS for c in pw):
        pool += len(SYMBOLS)
    others = {c for c in pw if c not in LOWER + UPPER + DIGITS + SYMBOLS}
    pool += len(others) * 8  # 想定外の文字は控えめに見積もる
    return pool


def entropy_bits(pw: str) -> float:
    """推定エントロピー（ビット）。総当たりのしにくさの目安。"""
    pool = pool_size(pw)
    if pool == 0:
        return 0.0
    return len(pw) * math.log2(pool)


def has_sequence(pw: str) -> bool:
    """abc・123・qwerty のような連続パターンがあるかを見る。"""
    lower = pw.lower()
    targets = KEYBOARD_ROWS + [string.ascii_lowercase, string.digits]
    targets += [t[::-1] for t in targets]
    for t in targets:
        for i in range(len(t) - 2):
            if t[i:i + 3] in lower:
                return True
    return False


def check_password(pw: str) -> dict:
    """パスワードの強さを 0〜6 のスコアと改善ポイントで返す。"""
    issues: list[str] = []
    score = 0

    length = len(pw)
    if length >= 16:
        score += 2
    elif length >= 12:
        score += 1
    elif length < 8:
        issues.append("8文字未満です。最低でも12文字以上がおすすめです")

    kinds = sum([
        any(c in LOWER for c in pw),
        any(c in UPPER for c in pw),
        any(c in DIGITS for c in pw),
        any(c in SYMBOLS for c in pw),
    ])
    score += max(0, kinds - 1)
    if kinds <= 2:
        issues.append("文字の種類が少ないです（英小文字・英大文字・数字・記号を混ぜると強くなります）")

    bits = entropy_bits(pw)
    if bits >= 80:
        score += 2
    elif bits >= 60:
        score += 1

    if pw.lower() in COMMON_PASSWORDS:
        score = 0
        issues.append("よく使われるパスワードそのものです。絶対に使わないでください")
    if re.search(r"(.)\1\1", pw):
        score -= 1
        issues.append("同じ文字の繰り返し（aaa など）があります")
    if has_sequence(pw):
        score -= 1
        issues.append("キーボードの並びや abc・123 のような連続パターンがあります")
    if re.search(r"(19|20)\d{2}", pw):
        issues.append("西暦らしい数字が入っています（誕生年などは推測されやすいです）")

    score = max(0, min(score, 6))
    if score <= 1:
        label = "弱い"
    elif score <= 3:
        label = "普通"
    elif score <= 5:
        label = "強い"
    else:
        label = "とても強い"
    return {"length": length, "entropy": round(bits), "score": score,
            "label": label, "issues": issues}


def main() -> int:
    parser = argparse.ArgumentParser(description="パスワード生成＆強さチェック")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("gen", help="パスワードを生成する")
    p_gen.add_argument("--length", type=int, default=16, help="長さ（既定: 16）")
    p_gen.add_argument("--count", type=int, default=1, help="生成する個数（既定: 1）")
    p_gen.add_argument("--no-symbols", action="store_true", help="記号を使わない")
    p_gen.add_argument("--exclude-ambiguous", action="store_true",
                       help="I・l・1・O・0 など紛らわしい文字を除く")

    sub.add_parser("check", help="パスワードの強さをチェックする")

    args = parser.parse_args()

    if args.command == "gen":
        for _ in range(max(1, args.count)):
            print(generate_password(args.length,
                                    use_symbols=not args.no_symbols,
                                    exclude_ambiguous=args.exclude_ambiguous))
        return 0

    pw = getpass.getpass("チェックするパスワードを入力してください（画面には表示されません）: ")
    if not pw:
        print("入力が空です")
        return 1
    r = check_password(pw)
    print(f"長さ: {r['length']} 文字")
    print(f"推定エントロピー: 約 {r['entropy']} ビット")
    print(f"強さ: {r['label']}（スコア {r['score']}/6）")
    if r["issues"]:
        print("改善ポイント:")
        for issue in r["issues"]:
            print(f"  - {issue}")
    else:
        print("目立つ弱点は見つかりませんでした")
    return 0


if __name__ == "__main__":
    sys.exit(main())
