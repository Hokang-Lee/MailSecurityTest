#!/usr/bin/env python3
"""Tkinter GUI for imap_mail_injector_burst_eicar.py.

Keep this file beside the original CLI script.  The GUI imports and reuses the
CLI's message construction and SMTP/burst functions; the original is unchanged.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from urllib.parse import urlparse


HERE = Path(__file__).resolve().parent
CLI_PATH = HERE / "imap_mail_injector_burst_eicar.py"
SETTINGS_PATH = HERE / "imap_mail_injector_burst_eicar_gui_settings.json"
UNSAVED_SETTINGS = {"smtp_password", "show_password"}


def load_cli():
    if not CLI_PATH.is_file():
        raise FileNotFoundError(f"元CLIファイルが見つかりません: {CLI_PATH}")
    spec = importlib.util.spec_from_file_location("mail_security_cli", CLI_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"元CLIファイルを読み込めません: {CLI_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MailSecurityApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SMTP メールセキュリティ送信試験")
        self.geometry("980x760")
        self.minsize(860, 650)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.cli = load_cli()
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.vars: dict[str, tk.Variable] = {}
        self._build_ui()
        self._load_settings(show_message=False)
        self.after(100, self._drain_log)

    def _var(self, name: str, value, kind="str"):
        cls = {"str": tk.StringVar, "bool": tk.BooleanVar}[kind]
        var = cls(self, value=value)
        self.vars[name] = var
        return var

    def _entry(self, parent, row, col, label, name, value, width=20, show=None):
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="w", padx=5, pady=4)
        entry = ttk.Entry(parent, textvariable=self._var(name, value), width=width, show=show)
        entry.grid(row=row, column=col + 1, sticky="ew", padx=5, pady=4)
        return entry

    def _check(self, parent, row, col, label, name, value=False):
        widget = ttk.Checkbutton(parent, text=label, variable=self._var(name, value, "bool"))
        widget.grid(row=row, column=col, sticky="w", padx=5, pady=4)
        return widget

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=10)
        outer.pack(fill="both", expand=True)

        smtp = ttk.LabelFrame(outer, text="SMTP設定", padding=8)
        smtp.pack(fill="x", pady=(0, 8))
        for c in (1, 3):
            smtp.columnconfigure(c, weight=1)
        self._entry(smtp, 0, 0, "ホスト", "host", self.cli.DEFAULT_HOST)
        self._entry(smtp, 0, 2, "ポート", "port", str(self.cli.DEFAULT_PORT))
        self._entry(smtp, 1, 0, "送信元", "from_addr", self.cli.DEFAULT_FROM)
        self._entry(smtp, 1, 2, "タイムアウト(秒)", "timeout", str(self.cli.DEFAULT_TIMEOUT))
        self._entry(smtp, 2, 0, "AUTHユーザー", "smtp_user", "")
        self.password_entry = self._entry(smtp, 2, 2, "AUTHパスワード", "smtp_password", "", show="*")
        self._check(smtp, 3, 0, "EHLOを明示実行", "ehlo", False)
        self._check(smtp, 3, 1, "STARTTLS", "starttls", False)
        self._check(smtp, 3, 2, "パスワード表示", "show_password", False).configure(command=self._toggle_password)

        recipients = ttk.LabelFrame(outer, text="宛先・送信設定", padding=8)
        recipients.pack(fill="x", pady=(0, 8))
        for c in (1, 3, 5):
            recipients.columnconfigure(c, weight=1)
        self._entry(recipients, 0, 0, "接頭辞", "user_prefix", self.cli.DEFAULT_USER_PREFIX, 12)
        self._entry(recipients, 0, 2, "開始番号", "user_start", str(self.cli.DEFAULT_USER_START), 12)
        self._entry(recipients, 0, 4, "終了番号", "user_end", str(self.cli.DEFAULT_USER_END), 12)
        self._entry(recipients, 1, 0, "桁数", "user_width", str(self.cli.DEFAULT_USER_WIDTH), 12)
        self._entry(recipients, 1, 2, "ドメイン", "domain", self.cli.DEFAULT_DOMAIN, 18)
        self._entry(recipients, 1, 4, "並列数", "workers", str(self.cli.DEFAULT_WORKERS), 12)
        self._entry(recipients, 2, 0, "バースト回数", "burst_count", "1", 12)
        self._entry(recipients, 2, 2, "間隔(秒)", "interval", str(self.cli.DEFAULT_INTERVAL), 12)
        self._entry(recipients, 2, 4, "進捗ログ間隔", "progress_every", "100", 12)
        self._entry(recipients, 3, 0, "件名接頭辞", "subject_prefix", "[AntiVirus-Test/EICAR]", 18)
        self._entry(recipients, 3, 2, "EICARファイル名", "eicar_filename", "eicar.com", 18)
        self._entry(recipients, 4, 0, "スパム試験URL", "spam_url", "https://example.invalid/spam-test", 40)

        options = ttk.Frame(outer)
        options.pack(fill="x", pady=(0, 8))
        self._check(options, 0, 0, "ドライラン（実送信しない）", "dry_run", True)
        self._check(options, 0, 1, "EICARテストファイルを添付", "eicar_attach", False)
        self._check(options, 0, 2, "スパムURLリンクを本文に追加", "spam_url_enabled", False)

        controls = ttk.Frame(outer)
        controls.pack(fill="x", pady=(0, 8))
        self.start_button = ttk.Button(controls, text="開始", command=self.start)
        self.start_button.pack(side="left", padx=(0, 6))
        self.stop_button = ttk.Button(controls, text="停止", command=self.stop, state="disabled")
        self.stop_button.pack(side="left")
        ttk.Button(controls, text="設定を保存", command=self._save_settings).pack(side="left", padx=(12, 6))
        ttk.Button(controls, text="設定を再読込", command=lambda: self._load_settings(True)).pack(side="left")
        self.status_var = tk.StringVar(self, "待機中")
        ttk.Label(controls, textvariable=self.status_var).pack(side="left", padx=14)

        self.progress = ttk.Progressbar(outer, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 8))
        self.log_box = scrolledtext.ScrolledText(outer, height=18, state="disabled", font=("Consolas", 10))
        self.log_box.pack(fill="both", expand=True)

        ttk.Label(
            outer,
            text="注意: 許可された隔離試験環境でのみ使用してください。EICARは無害な標準検知文字列ですが、AntiVirus製品により隔離されます。",
            foreground="#a33",
            wraplength=900,
        ).pack(fill="x", pady=(8, 0))

    def _toggle_password(self):
        self.password_entry.configure(show="" if self.vars["show_password"].get() else "*")

    def _settings_data(self) -> dict[str, object]:
        return {name: var.get() for name, var in self.vars.items() if name not in UNSAVED_SETTINGS}

    def _save_settings(self, show_message: bool = True) -> bool:
        try:
            SETTINGS_PATH.write_text(
                json.dumps(self._settings_data(), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            if show_message:
                messagebox.showerror("設定保存エラー", f"設定を保存できませんでした。\n{exc}", parent=self)
            return False
        if show_message:
            messagebox.showinfo(
                "設定保存",
                f"設定を保存しました。\n{SETTINGS_PATH}\n\nSMTPパスワードは保存されません。",
                parent=self,
            )
        return True

    def _load_settings(self, show_message: bool = True) -> None:
        if not SETTINGS_PATH.exists():
            if show_message:
                messagebox.showinfo("設定再読込", "保存済みの設定はありません。", parent=self)
            return
        try:
            data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("設定ファイルの形式が正しくありません")
            for name, value in data.items():
                if name in self.vars and name not in UNSAVED_SETTINGS:
                    self.vars[name].set(value)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("設定読込エラー", f"設定を読み込めませんでした。\n{exc}", parent=self)
            return
        if show_message:
            messagebox.showinfo("設定再読込", "保存済みの設定を読み込みました。", parent=self)

    def _value(self, name: str) -> str:
        return str(self.vars[name].get()).strip()

    def _args(self) -> argparse.Namespace:
        def integer(name, minimum=None):
            try:
                value = int(self._value(name))
            except ValueError as exc:
                raise ValueError(f"{name} は整数で入力してください") from exc
            if minimum is not None and value < minimum:
                raise ValueError(f"{name} は {minimum} 以上にしてください")
            return value

        def number(name, minimum=None):
            try:
                value = float(self._value(name))
            except ValueError as exc:
                raise ValueError(f"{name} は数値で入力してください") from exc
            if minimum is not None and value < minimum:
                raise ValueError(f"{name} は {minimum} 以上にしてください")
            return value

        start, end = integer("user_start", 0), integer("user_end", 0)
        if end < start:
            raise ValueError("終了番号は開始番号以上にしてください")
        host = self._value("host")
        from_addr = self._value("from_addr")
        domain = self._value("domain")
        if not host or not from_addr or not domain:
            raise ValueError("ホスト、送信元、ドメインは必須です")
        spam_url = self._value("spam_url")
        if self.vars["spam_url_enabled"].get():
            parsed = urlparse(spam_url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ValueError("スパム試験URLは http:// または https:// から始まる完全なURLにしてください")
        return argparse.Namespace(
            host=host, port=integer("port", 1), from_addr=from_addr, domain=domain,
            user_prefix=self._value("user_prefix"), user_start=start, user_end=end,
            user_width=integer("user_width", 1), interval=number("interval", 0),
            timeout=integer("timeout", 1), workers=integer("workers", 1),
            burst_count=integer("burst_count", 0), dry_run=bool(self.vars["dry_run"].get()),
            progress_every=integer("progress_every", 0),
            eicar_attach=bool(self.vars["eicar_attach"].get()),
            eicar_filename=self._value("eicar_filename") or "eicar.com",
            spam_url_enabled=bool(self.vars["spam_url_enabled"].get()), spam_url=spam_url,
            subject_prefix=self._value("subject_prefix"), ehlo=bool(self.vars["ehlo"].get()),
            starttls=bool(self.vars["starttls"].get()), smtp_user=self._value("smtp_user"),
            smtp_password=str(self.vars["smtp_password"].get()),
        )

    def _log(self, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.log_queue.put(f"[{stamp}] {message}\n")

    def _drain_log(self) -> None:
        try:
            while True:
                line = self.log_queue.get_nowait()
                self.log_box.configure(state="normal")
                self.log_box.insert("end", line)
                self.log_box.see("end")
                self.log_box.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(100, self._drain_log)

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        try:
            args = self._args()
        except ValueError as exc:
            messagebox.showerror("入力エラー", str(exc), parent=self)
            return
        count = args.user_end - args.user_start + 1
        bursts = "停止するまで" if args.burst_count == 0 else str(args.burst_count)
        if not args.dry_run:
            warning = f"実際にSMTP送信します。\n宛先: {count}件\nバースト: {bursts}"
            if args.eicar_attach:
                warning += "\n\nEICARテストファイルを添付します。"
            if args.spam_url_enabled:
                warning += f"\n\nスパム試験URLを本文に追加します:\n{args.spam_url}"
            if not messagebox.askyesno("実送信の確認", warning + "\n\n許可済み試験環境ですか？", parent=self):
                return
        self._save_settings(show_message=False)
        self.cli.STOP_EVENT.clear()
        self.cli.log = self._log
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_var.set("実行中")
        self.progress.start(12)
        self.worker = threading.Thread(target=self._run, args=(args,), daemon=True)
        self.worker.start()

    def _run(self, args) -> None:
        total_ok = total_ng = burst_no = 0
        self._log(f"開始: {args.host}:{args.port} / 宛先 {args.user_start}～{args.user_end} / dry-run={args.dry_run}")
        original_make_message = self.cli.make_message

        def make_message_with_url(cli_args, to_addr, burst_no_value, seq_no):
            msg = original_make_message(cli_args, to_addr, burst_no_value, seq_no)
            if cli_args.spam_url_enabled:
                text = (
                    "これは許可されたメールセキュリティ試験用のURLリンクです。\n"
                    "実運用環境や許可されていない宛先では使用しないでください。\n\n"
                    f"試験URL: {cli_args.spam_url}\n"
                )
                msg.attach(self.cli.MIMEText(text, "plain", "utf-8"))
            return msg

        self.cli.make_message = make_message_with_url
        try:
            while not self.cli.STOP_EVENT.is_set():
                burst_no += 1
                ok, ng = self.cli.send_burst(args, burst_no)
                total_ok += ok
                total_ng += ng
                if args.burst_count and burst_no >= args.burst_count:
                    break
                self.cli.sleep_with_stop(args.interval)
        except Exception as exc:
            self._log(f"ERROR: {type(exc).__name__}: {exc}")
        finally:
            self.cli.make_message = original_make_message
            self._log(f"終了: bursts={burst_no} total_ok={total_ok} total_ng={total_ng}")
            self.after(0, self._finished)

    def stop(self) -> None:
        if self.worker and self.worker.is_alive():
            self.cli.STOP_EVENT.set()
            self.status_var.set("停止処理中…")
            self.stop_button.configure(state="disabled")
            self._log("停止要求を受け付けました。進行中のSMTP処理の完了を待ちます。")

    def _finished(self) -> None:
        self.progress.stop()
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_var.set("停止" if self.cli.STOP_EVENT.is_set() else "完了")

    def on_close(self) -> None:
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno("終了確認", "送信処理中です。停止要求を出して終了しますか？", parent=self):
                return
            self.cli.STOP_EVENT.set()
        self._save_settings(show_message=False)
        self.destroy()


def main() -> int:
    try:
        app = MailSecurityApp()
    except Exception as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("起動エラー", str(exc), parent=root)
        root.destroy()
        return 1
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
