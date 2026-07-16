#!/usr/bin/env python3
"""Tkinter GUI for imap_mail_injector_burst_eicar.py.

Keep this file beside the original CLI script.  The GUI imports and reuses the
CLI's message construction and SMTP/burst functions; the original is unchanged.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import queue
import ssl
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from urllib.parse import urlparse


HERE = Path(__file__).resolve().parent
CLI_PATH = HERE / "imap_mail_injector_burst_eicar.py"
SETTINGS_PATH = HERE / "imap_mail_injector_burst_eicar_gui_settings.json"
LOG_DIR = HERE / "logs"
UNSAVED_SETTINGS = {"smtp_password", "show_password"}
MICROSOFT_SMTP_SCOPE = "https://outlook.office.com/SMTP.Send offline_access"


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
        self.log_file_path: Path | None = None
        self.log_file_lock = threading.Lock()
        self.settings_path = SETTINGS_PATH
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
        self._check(smtp, 3, 1, "通常SMTP（25）", "plain_smtp", True).configure(command=self._select_plain_smtp)
        self._check(smtp, 3, 2, "STARTTLS（587）", "starttls", False).configure(command=self._select_starttls)
        self._check(smtp, 3, 3, "SSL/TLS（465）", "implicit_ssl", False).configure(command=self._select_implicit_ssl)
        self._check(smtp, 4, 0, "パスワード表示", "show_password", False).configure(command=self._toggle_password)

        recipients = ttk.LabelFrame(outer, text="宛先・送信設定", padding=8)
        self._check(smtp, 4, 2, "Microsoft OAuth 2.0", "oauth_enabled", False)
        self._entry(smtp, 5, 0, "Entra テナントID", "oauth_tenant_id", "", 34)
        self._entry(smtp, 5, 2, "Entra クライアントID", "oauth_client_id", "", 34)

        recipients.pack(fill="x", pady=(0, 8))
        for c in (1, 3, 5):
            recipients.columnconfigure(c, weight=1)
        self._entry(recipients, 0, 0, "接頭辞", "user_prefix", self.cli.DEFAULT_USER_PREFIX, 12)
        self._entry(recipients, 0, 2, "開始番号", "user_start", str(self.cli.DEFAULT_USER_START), 12)
        self._entry(recipients, 0, 4, "終了番号", "user_end", str(self.cli.DEFAULT_USER_END), 12)
        self._entry(recipients, 1, 0, "桁数（0=単一宛先）", "user_width", str(self.cli.DEFAULT_USER_WIDTH), 16)
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
        ttk.Button(controls, text="JSONを選んで読込", command=self._choose_settings_file).pack(side="left", padx=(6, 0))
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

    def _select_plain_smtp(self) -> None:
        if self.vars["plain_smtp"].get():
            self.vars["starttls"].set(False)
            self.vars["implicit_ssl"].set(False)
            self.vars["port"].set("25")
        else:
            self.vars["plain_smtp"].set(True)

    def _select_starttls(self) -> None:
        if self.vars["starttls"].get():
            self.vars["plain_smtp"].set(False)
            self.vars["implicit_ssl"].set(False)
            self.vars["port"].set("587")
        else:
            self.vars["starttls"].set(True)

    def _select_implicit_ssl(self) -> None:
        if self.vars["implicit_ssl"].get():
            self.vars["plain_smtp"].set(False)
            self.vars["starttls"].set(False)
            self.vars["port"].set("465")
        else:
            self.vars["implicit_ssl"].set(True)

    def _normalize_transport_selection(self) -> None:
        """Normalize old settings without replacing a saved custom port."""
        if self.vars["implicit_ssl"].get():
            self.vars["plain_smtp"].set(False)
            self.vars["starttls"].set(False)
        elif self.vars["starttls"].get():
            self.vars["plain_smtp"].set(False)
        else:
            self.vars["plain_smtp"].set(True)

    def _settings_data(self) -> dict[str, object]:
        return {name: var.get() for name, var in self.vars.items() if name not in UNSAVED_SETTINGS}

    def _save_settings(self, show_message: bool = True) -> bool:
        try:
            self.settings_path.write_text(
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
                f"設定を保存しました。\n{self.settings_path}\n\nSMTPパスワードは保存されません。",
                parent=self,
            )
        return True

    def _choose_settings_file(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="読み込む設定JSONを選択",
            initialdir=str(HERE),
            filetypes=(("JSON設定ファイル", "*.json"), ("すべてのファイル", "*.*")),
        )
        if selected:
            self._load_settings(show_message=True, path=Path(selected))

    def _load_settings(self, show_message: bool = True, path: Path | None = None) -> None:
        source_path = path or self.settings_path
        if not source_path.exists():
            if show_message:
                messagebox.showinfo("設定再読込", "保存済みの設定はありません。", parent=self)
            return
        try:
            data = json.loads(source_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("設定ファイルの形式が正しくありません")
            for name, value in data.items():
                if name in self.vars and name not in UNSAVED_SETTINGS:
                    self.vars[name].set(value)
            self._normalize_transport_selection()
            self.settings_path = source_path
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror(
                "設定読込エラー",
                f"設定を読み込めませんでした。\n{source_path}\n\n{exc}",
                parent=self,
            )
            return
        if show_message:
            messagebox.showinfo(
                "設定再読込",
                f"設定を読み込みました。\n{source_path}\n\nSMTPパスワードは読み込まれません。",
                parent=self,
            )

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
        user_width = integer("user_width", 0)
        if user_width > 0 and end < start:
            raise ValueError("終了番号は開始番号以上にしてください")
        if user_width == 0:
            end = start
        host = self._value("host")
        from_addr = self._value("from_addr")
        domain = self._value("domain")
        if not host or not from_addr or not domain:
            raise ValueError("ホスト、送信元、ドメインは必須です")
        transport_count = sum(
            bool(self.vars[name].get())
            for name in ("plain_smtp", "starttls", "implicit_ssl")
        )
        if transport_count != 1:
            raise ValueError("SMTP接続方式は1つだけ選択してください")
        spam_url = self._value("spam_url")
        if self.vars["spam_url_enabled"].get():
            parsed = urlparse(spam_url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ValueError("スパム試験URLは http:// または https:// から始まる完全なURLにしてください")
        oauth_enabled = bool(self.vars["oauth_enabled"].get())
        if oauth_enabled:
            if not self._value("oauth_tenant_id") or not self._value("oauth_client_id"):
                raise ValueError("OAuth使用時はテナントIDとクライアントIDが必要です")
            if not self._value("smtp_user"):
                raise ValueError("OAuth使用時はAUTHユーザー（Microsoft 365メールアドレス）が必要です")
            if not self.vars["starttls"].get() or self.vars["implicit_ssl"].get():
                raise ValueError("Microsoft OAuth送信ではSTARTTLS（ポート587）を選択してください")
        return argparse.Namespace(
            host=host, port=integer("port", 1), from_addr=from_addr, domain=domain,
            user_prefix=self._value("user_prefix"), user_start=start, user_end=end,
            user_width=user_width, interval=number("interval", 0),
            timeout=integer("timeout", 1), workers=integer("workers", 1),
            burst_count=integer("burst_count", 0), dry_run=bool(self.vars["dry_run"].get()),
            progress_every=integer("progress_every", 0),
            eicar_attach=bool(self.vars["eicar_attach"].get()),
            eicar_filename=self._value("eicar_filename") or "eicar.com",
            spam_url_enabled=bool(self.vars["spam_url_enabled"].get()), spam_url=spam_url,
            subject_prefix=self._value("subject_prefix"), ehlo=bool(self.vars["ehlo"].get()),
            starttls=bool(self.vars["starttls"].get()),
            implicit_ssl=bool(self.vars["implicit_ssl"].get()), smtp_user=self._value("smtp_user"),
            smtp_password=str(self.vars["smtp_password"].get()),
            oauth_enabled=oauth_enabled,
            oauth_tenant_id=self._value("oauth_tenant_id"),
            oauth_client_id=self._value("oauth_client_id"),
        )

    @staticmethod
    def _post_form_json(url: str, form: dict[str, str]) -> dict:
        data = urllib.parse.urlencode(form).encode("ascii")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))

    def _acquire_microsoft_token(self, args) -> str:
        tenant = urllib.parse.quote(args.oauth_tenant_id, safe="")
        base_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"
        device = self._post_form_json(
            f"{base_url}/devicecode",
            {"client_id": args.oauth_client_id, "scope": MICROSOFT_SMTP_SCOPE},
        )
        device_code = device["device_code"]
        user_code = device["user_code"]
        verification_uri = device.get("verification_uri") or device.get("verification_url")
        expires_at = time.monotonic() + int(device.get("expires_in", 900))
        interval = max(1, int(device.get("interval", 5)))
        self._log(f"Microsoft OAuth認証待ち: {verification_uri} / ログインコード: {user_code}")

        def show_sign_in() -> None:
            messagebox.showinfo(
                "Microsoft OAuth認証",
                f"ブラウザーでMicrosoftにサインインしてください。\n\nURL: {verification_uri}\nコード: {user_code}",
                parent=self,
            )
            if verification_uri:
                webbrowser.open(verification_uri)

        self.after(0, show_sign_in)
        token_url = f"{base_url}/token"
        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": args.oauth_client_id,
            "device_code": device_code,
        }
        while time.monotonic() < expires_at:
            if self.cli.STOP_EVENT.wait(interval):
                raise InterruptedError("OAuth認証を中止しました")
            try:
                token = self._post_form_json(token_url, form)
            except urllib.error.HTTPError as exc:
                try:
                    detail = json.loads(exc.read().decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    raise RuntimeError(f"Microsoftトークン取得エラー: HTTP {exc.code}") from exc
                error = detail.get("error", "unknown_error")
                if error == "authorization_pending":
                    continue
                if error == "slow_down":
                    interval += 5
                    continue
                description = detail.get("error_description", error).splitlines()[0]
                raise RuntimeError(f"Microsoft OAuthエラー: {description}") from exc
            access_token = token.get("access_token")
            if not access_token:
                raise RuntimeError("Microsoftからアクセストークンが返されませんでした")
            self._log("Microsoft OAuth認証に成功しました")
            return str(access_token)
        raise TimeoutError("Microsoft OAuth認証の有効時間が切れました")

    def _send_one_oauth(self, cli_args, to_addr, msg):
        try:
            with self.cli.smtplib.SMTP(
                cli_args.host, cli_args.port, timeout=cli_args.timeout
            ) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                xoauth2 = (
                    f"user={cli_args.smtp_user}\x01"
                    f"auth=Bearer {cli_args.oauth_access_token}\x01\x01"
                )
                encoded = base64.b64encode(xoauth2.encode("utf-8")).decode("ascii")
                code, response = smtp.docmd("AUTH", "XOAUTH2 " + encoded)
                if code != 235:
                    raise self.cli.smtplib.SMTPAuthenticationError(code, response)
                smtp.sendmail(cli_args.from_addr, [to_addr], msg.as_string())
            return True, "ok"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {str(exc)[:200]}"

    def _log(self, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {message}\n"
        self.log_queue.put(line)
        if self.log_file_path is not None:
            try:
                with self.log_file_lock:
                    with self.log_file_path.open("a", encoding="utf-8", newline="") as log_file:
                        log_file.write(line)
            except OSError:
                # GUI送信処理は継続する。ファイル書込みエラーの再帰ログは避ける。
                pass

    def _start_log_file(self) -> Path:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d")
        path = LOG_DIR / f"send_{stamp}.log"
        path.touch(exist_ok=True)
        self.log_file_path = path
        return path

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
        send_time_suffix = datetime.now().strftime("%H%M")
        args.subject_prefix = f"{args.subject_prefix}{send_time_suffix}"
        self._save_settings(show_message=False)
        try:
            log_path = self._start_log_file()
        except OSError as exc:
            messagebox.showerror("ログ保存エラー", f"送信ログファイルを作成できませんでした。\n{exc}", parent=self)
            return
        self.cli.STOP_EVENT.clear()
        self.cli.log = self._log
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_var.set("実行中")
        self.progress.start(12)
        self.worker = threading.Thread(target=self._run, args=(args,), daemon=True)
        self._log("-" * 60)
        self._log(f"ログ保存先: {log_path}")
        self._log(f"今回の件名接頭辞: {args.subject_prefix}")
        self.worker.start()

    def _run(self, args) -> None:
        total_ok = total_ng = burst_no = 0
        if args.oauth_enabled and not args.dry_run:
            try:
                args.oauth_access_token = self._acquire_microsoft_token(args)
            except Exception as exc:
                self._log(f"OAuth ERROR: {type(exc).__name__}: {exc}")
                self.after(0, self._finished)
                return
        if args.user_width == 0:
            recipient_description = f"{args.user_prefix}@{args.domain}（単一宛先）"
        else:
            recipient_description = f"番号 {args.user_start}～{args.user_end}"
        self._log(f"開始: {args.host}:{args.port} / 宛先 {recipient_description} / dry-run={args.dry_run}")
        original_make_message = self.cli.make_message
        original_make_address = self.cli.make_address
        original_send_one = self.cli.send_one

        def make_address_with_single_mode(prefix, number, width, domain):
            if width == 0:
                return f"{prefix}@{domain}"
            return original_make_address(prefix, number, width, domain)

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

        def send_one_with_recipient_log(cli_args, to_addr, msg):
            if cli_args.oauth_enabled and not cli_args.dry_run:
                result = self._send_one_oauth(cli_args, to_addr, msg)
            elif cli_args.implicit_ssl and not cli_args.dry_run:
                try:
                    context = ssl.create_default_context()
                    with self.cli.smtplib.SMTP_SSL(
                        cli_args.host,
                        cli_args.port,
                        timeout=cli_args.timeout,
                        context=context,
                    ) as smtp:
                        if cli_args.ehlo:
                            smtp.ehlo()
                        if cli_args.smtp_user:
                            smtp.login(cli_args.smtp_user, cli_args.smtp_password)
                        smtp.sendmail(cli_args.from_addr, [to_addr], msg.as_string())
                    result = (True, "ok")
                except Exception as exc:
                    result = (False, f"{type(exc).__name__}: {str(exc)[:200]}")
            else:
                result = original_send_one(cli_args, to_addr, msg)
            success, info = result
            if success:
                if cli_args.dry_run:
                    self._log(f"DRY-RUN {to_addr}: 実送信なし")
                else:
                    self._log(f"SENT {to_addr}")
            return result

        self.cli.make_address = make_address_with_single_mode
        self.cli.make_message = make_message_with_url
        self.cli.send_one = send_one_with_recipient_log
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
            self.cli.make_address = original_make_address
            self.cli.make_message = original_make_message
            self.cli.send_one = original_send_one
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
