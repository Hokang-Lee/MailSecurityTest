#!/usr/bin/env python3
"""
imap_mail_injector_burst_eicar.py

IMAP/SMTP 負荷テスト用メール送信ツール（EICAR 添付対応版）

用途:
  - 検証環境・許可済み環境で、EICAR テストファイル(eicar.com)を添付したメールを
    指定ユーザー範囲へ一斉送信する。
  - ウイルス対策/メールゲートウェイ/IMAP格納後スキャンの検知確認に利用する。

注意:
  - EICAR は実害のない標準テスト文字列ですが、セキュリティ製品は「テストウイルス」として検知します。
  - 本番環境・第三者環境・許可のない宛先への送信は禁止です。

使用例:
  # まずはドライラン
  python imap_mail_injector_burst_eicar.py --dry-run --eicar-attach --burst-count 1

  # user001〜user999 へ 1 回だけ EICAR 添付メールを送信
  python imap_mail_injector_burst_eicar.py --host 192.168.0.38 --port 25 --eicar-attach --burst-count 1

  # 送信元を指定
  python imap_mail_injector_burst_eicar.py --from-addr administrator@testhve12.jp --eicar-attach --burst-count 1

  # バースト間隔30秒、3回送信
  python imap_mail_injector_burst_eicar.py --interval 30 --burst-count 3 --eicar-attach
"""

import argparse
import concurrent.futures
import smtplib
import signal
import sys
import threading
import time
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

DEFAULT_HOST = "192.168.0.38"
DEFAULT_PORT = 25
DEFAULT_FROM = "administrator@testhve12.jp"
DEFAULT_USER_PREFIX = "user"
DEFAULT_USER_START = 1
DEFAULT_USER_END = 999
DEFAULT_USER_WIDTH = 3
DEFAULT_DOMAIN = "testhvb.jp"
DEFAULT_INTERVAL = 10.0
DEFAULT_TIMEOUT = 10
DEFAULT_WORKERS = 50
DEFAULT_BURST_COUNT = 0  # 0=無制限

# EICAR 標準テストファイル文字列（末尾改行なしで 68 bytes）
EICAR_TEST_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

STOP_EVENT = threading.Event()


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def make_address(prefix: str, n: int, width: int, domain: str) -> str:
    return f"{prefix}{n:0{width}d}@{domain}"


def make_message(args, to_addr: str, burst_no: int, seq_no: int) -> MIMEMultipart:
    msg = MIMEMultipart()
    msg["From"] = args.from_addr
    msg["To"] = to_addr
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=args.from_addr.split("@")[-1] if "@" in args.from_addr else None)
    msg["Subject"] = f"{args.subject_prefix} Burst#{burst_no} Seq#{seq_no}"

    body = (
        "これはメール/IMAP/ウイルス対策検知の検証用メールです。\n\n"
        f"バースト番号 : {burst_no}\n"
        f"送信番号     : {seq_no}\n"
        f"送信時刻     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"宛先         : {to_addr}\n"
        f"送信元       : {args.from_addr}\n\n"
    )

    if args.eicar_attach:
        body += (
            "添付ファイル eicar.com は EICAR 標準アンチウイルステストファイルです。\n"
            "実害のあるマルウェアではありませんが、セキュリティ製品では検知されます。\n"
        )
    else:
        body += "EICAR 添付は無効です。通常の負荷テストメールです。\n"

    msg.attach(MIMEText(body, "plain", "utf-8"))

    if args.eicar_attach:
        payload = EICAR_TEST_STRING.encode("ascii")
        part = MIMEApplication(payload, _subtype="octet-stream")
        part.add_header("Content-Disposition", "attachment", filename=args.eicar_filename)
        part.add_header("Content-Description", "EICAR anti-virus test file")
        msg.attach(part)

    return msg


def send_one(args, to_addr: str, msg: MIMEMultipart) -> tuple[bool, str]:
    if args.dry_run:
        return True, "dry-run"

    try:
        with smtplib.SMTP(args.host, args.port, timeout=args.timeout) as smtp:
            if args.ehlo:
                smtp.ehlo()
            if args.starttls:
                smtp.starttls()
                smtp.ehlo()
            if args.smtp_user:
                smtp.login(args.smtp_user, args.smtp_password)
            smtp.sendmail(args.from_addr, [to_addr], msg.as_string())
        return True, "ok"
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:200]}"


def send_burst(args, burst_no: int) -> tuple[int, int]:
    recipients = [
        make_address(args.user_prefix, n, args.user_width, args.domain)
        for n in range(args.user_start, args.user_end + 1)
    ]

    ok = 0
    ng = 0
    started = time.time()
    log(f"Burst#{burst_no} start: recipients={len(recipients)}, workers={args.workers}")

    def task(item):
        seq_no, to_addr = item
        msg = make_message(args, to_addr, burst_no, seq_no)
        return to_addr, send_one(args, to_addr, msg)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(task, item) for item in enumerate(recipients, start=1)]
        for i, fut in enumerate(concurrent.futures.as_completed(futures), start=1):
            if STOP_EVENT.is_set():
                break
            to_addr, (success, info) = fut.result()
            if success:
                ok += 1
            else:
                ng += 1
                log(f"NG {to_addr}: {info}")
            if args.progress_every > 0 and i % args.progress_every == 0:
                log(f"Burst#{burst_no} progress: done={i}/{len(recipients)} ok={ok} ng={ng}")

    elapsed = time.time() - started
    log(f"Burst#{burst_no} done: ok={ok} ng={ng} elapsed={elapsed:.2f}s rate={(ok+ng)/elapsed if elapsed > 0 else 0:.1f}/s")
    return ok, ng


def sleep_with_stop(seconds: float) -> None:
    end = time.time() + max(0.0, seconds)
    while not STOP_EVENT.is_set() and time.time() < end:
        time.sleep(min(0.5, end - time.time()))


def install_signal_handlers() -> None:
    def handler(signum, frame):
        log(f"signal received: {signum}; stopping...")
        STOP_EVENT.set()
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def parse_args():
    p = argparse.ArgumentParser(description="SMTP一斉送信シミュレーター（EICAR添付対応）")
    p.add_argument("--host", default=DEFAULT_HOST, help="SMTPサーバ")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="SMTPポート")
    p.add_argument("--from-addr", default=DEFAULT_FROM, help="Envelope From / Header From")
    p.add_argument("--domain", default=DEFAULT_DOMAIN, help="宛先ドメイン")
    p.add_argument("--user-prefix", default=DEFAULT_USER_PREFIX, help="宛先ユーザー接頭辞")
    p.add_argument("--user-start", type=int, default=DEFAULT_USER_START)
    p.add_argument("--user-end", type=int, default=DEFAULT_USER_END)
    p.add_argument("--user-width", type=int, default=DEFAULT_USER_WIDTH, help="user001 の 001 部分の桁数")
    p.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="バースト間隔秒")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="SMTP接続タイムアウト秒")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="並列SMTP送信数")
    p.add_argument("--burst-count", type=int, default=DEFAULT_BURST_COUNT, help="バースト回数。0=無制限")
    p.add_argument("--dry-run", action="store_true", help="実送信せずに動作確認")
    p.add_argument("--progress-every", type=int, default=100, help="進捗ログ出力間隔。0=無効")

    p.add_argument("--eicar-attach", action="store_true", help="EICAR テストファイル eicar.com を添付")
    p.add_argument("--eicar-filename", default="eicar.com", help="添付ファイル名")
    p.add_argument("--subject-prefix", default="[AV-Test/EICAR]", help="件名プレフィックス")

    p.add_argument("--ehlo", action="store_true", help="送信前に EHLO を明示実行")
    p.add_argument("--starttls", action="store_true", help="STARTTLS を使用")
    p.add_argument("--smtp-user", default="", help="SMTP AUTH ユーザー名")
    p.add_argument("--smtp-password", default="", help="SMTP AUTH パスワード")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    install_signal_handlers()

    if args.user_end < args.user_start:
        log("ERROR: --user-end must be >= --user-start")
        return 2
    if args.workers < 1:
        log("ERROR: --workers must be >= 1")
        return 2

    user_count = args.user_end - args.user_start + 1
    log("=== SMTP一斉送信シミュレーター（EICAR添付対応）開始 ===")
    log(f"SMTPサーバ : {args.host}:{args.port}")
    log(f"送信元     : {args.from_addr}")
    log(f"宛先範囲   : {make_address(args.user_prefix, args.user_start, args.user_width, args.domain)} ～ {make_address(args.user_prefix, args.user_end, args.user_width, args.domain)}")
    log(f"宛先数     : {user_count}")
    log(f"間隔       : {args.interval} 秒")
    log(f"並列数     : {args.workers}")
    log(f"EICAR添付  : {'有効' if args.eicar_attach else '無効'}")
    log(f"DRY-RUN    : {'有効' if args.dry_run else '無効'}")
    log(f"バースト数 : {'無制限' if args.burst_count == 0 else args.burst_count}")

    total_ok = 0
    total_ng = 0
    burst_no = 0

    while not STOP_EVENT.is_set():
        burst_no += 1
        ok, ng = send_burst(args, burst_no)
        total_ok += ok
        total_ng += ng

        if args.burst_count and burst_no >= args.burst_count:
            break
        if STOP_EVENT.is_set():
            break
        sleep_with_stop(args.interval)

    log(f"=== 終了: bursts={burst_no} total_ok={total_ok} total_ng={total_ng} ===")
    return 0 if total_ng == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
