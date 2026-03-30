#!/usr/bin/env python3
"""
AES-256-GCM text encryptor/decryptor with a Tkinter GUI.

Requirements:
    pip install cryptography

GUI:
    py aes256_tool.py

CLI examples:
    py aes256_tool.py encrypt --password "my-password" --text "secret message"
    py aes256_tool.py decrypt --password "my-password" --data "<BASE64_PAYLOAD>"
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import sys
import tkinter as tk
from tkinter import messagebox

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


NONCE_SIZE = 12
SALT_SIZE = 16
PBKDF2_ITERATIONS = 200_000
FORMAT_PASSWORD = b"P2"
SUPPORTED_KEY_SIZES = {128: 16, 192: 24, 256: 32}
KEY_SIZE_CODES = {128: 1, 192: 2, 256: 3}
CODE_TO_KEY_SIZE = {value: key for key, value in KEY_SIZE_CODES.items()}
DEFAULT_KEY_SIZE_BITS = 256


def validate_key_size(key_size_bits: int) -> int:
    if key_size_bits not in SUPPORTED_KEY_SIZES:
        raise ValueError("\u041f\u043e\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u044e\u0442\u0441\u044f \u0442\u043e\u043b\u044c\u043a\u043e \u0440\u0430\u0437\u043c\u0435\u0440\u044b \u043a\u043b\u044e\u0447\u0430 128, 192 \u0438\u043b\u0438 256 \u0431\u0438\u0442.")
    return SUPPORTED_KEY_SIZES[key_size_bits]


def derive_key_from_password(password: str, salt: bytes, key_size_bits: int) -> bytes:
    if not password:
        raise ValueError("\u041a\u043b\u044e\u0447 \u043d\u0435 \u0434\u043e\u043b\u0436\u0435\u043d \u0431\u044b\u0442\u044c \u043f\u0443\u0441\u0442\u044b\u043c.")

    key_length = validate_key_size(key_size_bits)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(secret: str, plaintext: str, key_size_bits: int = 256) -> str:
    validate_key_size(key_size_bits)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key_from_password(secret, salt, key_size_bits)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    header = FORMAT_PASSWORD + bytes([KEY_SIZE_CODES[key_size_bits]])
    payload = header + salt + nonce + ciphertext
    return base64.b64encode(payload).decode("ascii")


def decrypt_text(secret: str, payload_b64: str) -> str:
    try:
        payload = base64.b64decode(payload_b64.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("\u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442 \u0434\u043b\u044f \u0434\u0435\u043a\u043e\u0434\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u044f \u0434\u043e\u043b\u0436\u0435\u043d \u0431\u044b\u0442\u044c \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u044b\u043c Base64-\u0442\u0435\u043a\u0441\u0442\u043e\u043c.") from exc

    min_len = 2 + 1 + SALT_SIZE + NONCE_SIZE + 16
    if len(payload) < min_len:
        raise ValueError("\u0417\u0430\u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0435 \u0434\u0430\u043d\u043d\u044b\u0435 \u0441\u043b\u0438\u0448\u043a\u043e\u043c \u043a\u043e\u0440\u043e\u0442\u043a\u0438\u0435.")

    marker = payload[:2]
    if marker != FORMAT_PASSWORD:
        raise ValueError("\u041d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u044b\u0439 \u0444\u043e\u0440\u043c\u0430\u0442 \u0437\u0430\u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0445 \u0434\u0430\u043d\u043d\u044b\u0445.")

    key_size_code = payload[2]
    key_size_bits = CODE_TO_KEY_SIZE.get(key_size_code)
    if key_size_bits is None:
        raise ValueError("\u041d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u044b\u0439 \u0440\u0430\u0437\u043c\u0435\u0440 \u043a\u043b\u044e\u0447\u0430 \u0432 \u0437\u0430\u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0445 \u0434\u0430\u043d\u043d\u044b\u0445.")

    salt_start = 3
    salt_end = salt_start + SALT_SIZE
    nonce_end = salt_end + NONCE_SIZE

    salt = payload[salt_start:salt_end]
    nonce = payload[salt_end:nonce_end]
    ciphertext = payload[nonce_end:]

    try:
        key = derive_key_from_password(secret, salt, key_size_bits)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0434\u0435\u043a\u043e\u0434\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0434\u0430\u043d\u043d\u044b\u0435. \u041f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 \u043a\u043b\u044e\u0447 \u0438 \u0438\u0441\u0445\u043e\u0434\u043d\u044b\u0439 \u0448\u0438\u0444\u0440\u043e\u0442\u0435\u043a\u0441\u0442.") from exc

    return plaintext.decode("utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AES-256-GCM text encryptor/decryptor")
    subparsers = parser.add_subparsers(dest="command")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text")
    encrypt_parser.add_argument("--password", required=True, help="Password text")
    encrypt_parser.add_argument("--text", required=True, help="Plain text to encrypt")
    encrypt_parser.add_argument(
        "--size",
        type=int,
        default=DEFAULT_KEY_SIZE_BITS,
        help="Key size for compatibility: 128, 192 or 256",
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text")
    decrypt_parser.add_argument("--password", required=True, help="Password text")
    decrypt_parser.add_argument("--data", required=True, help="Base64-encoded encrypted payload")

    return parser


class AESApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("AES-256-GCM шифрование и дешифрование by Serjio Parutti 2026")
        self.root.geometry("820x560")
        self.root.minsize(760, 500)

        self.show_password_var = tk.BooleanVar(value=False)
        self.context_widget: tk.Widget | None = None
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="\u0412\u044b\u0440\u0435\u0437\u0430\u0442\u044c", command=self._cut_from_menu)
        self.context_menu.add_command(label="\u041a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c", command=self._copy_from_menu)
        self.context_menu.add_command(label="\u0412\u0441\u0442\u0430\u0432\u0438\u0442\u044c", command=self._paste_from_menu)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="\u0412\u044b\u0434\u0435\u043b\u0438\u0442\u044c \u0432\u0441\u0451", command=self._select_all_from_menu)

        self._build_ui()
        self._bind_shortcuts()

    def _build_ui(self) -> None:
        container = tk.Frame(self.root, padx=10, pady=10)
        container.pack(fill="both", expand=True)

        tk.Label(
            container,
            text="Исходные данные:",
            anchor="w",
        ).pack(fill="x")
        self.text_input = tk.Text(container, height=9, wrap="word", undo=True)
        self.text_input.pack(fill="x", pady=(4, 12))

        password_row = tk.Frame(container)
        password_row.pack(fill="x", pady=(0, 8))
        tk.Label(password_row, text="Пароль:", width=12, anchor="w").pack(side="left")
        self.password_entry = tk.Entry(password_row, show="*")
        self.password_entry.pack(side="left", fill="x", expand=True)

        options_row = tk.Frame(container)
        options_row.pack(fill="x", pady=(0, 12))
        tk.Checkbutton(
            options_row,
            text="Показать пароль",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
        ).pack(side="left")
        tk.Label(
            options_row,
            text="Используется режим AES-256-GCM, служебные параметры создаются автоматически.",
            anchor="w",
        ).pack(side="left", padx=(12, 0))

        action_row = tk.Frame(container)
        action_row.pack(fill="x", pady=(0, 12))
        tk.Button(action_row, text="Зашифровать", width=16, command=self.encrypt_ui).pack(side="left")
        tk.Button(action_row, text="Расшифровать", width=16, command=self.decrypt_ui).pack(side="left", padx=(8, 0))
        tk.Button(action_row, text="Копировать результат", width=18, command=self.copy_result).pack(side="left", padx=(8, 0))
        tk.Button(action_row, text="Вставить", width=12, command=self.paste_into_active_widget).pack(side="left", padx=(8, 0))
        tk.Button(action_row, text="Поменять местами", width=16, command=self.swap_texts).pack(side="left", padx=(8, 0))
        tk.Button(action_row, text="Очистить", width=12, command=self.clear_all).pack(side="left", padx=(8, 0))

        tk.Label(container, text="Результат:", anchor="w").pack(fill="x")
        self.result_text = tk.Text(container, height=10, wrap="word", undo=True)
        self.result_text.pack(fill="both", expand=True, pady=(4, 0))

    def _bind_shortcuts(self) -> None:
        for widget_class in ("Text", "Entry"):
            self.root.bind_class(widget_class, "<Control-a>", self._select_all)
            self.root.bind_class(widget_class, "<Control-A>", self._select_all)
            self.root.bind_class(widget_class, "<Button-3>", self._show_context_menu)
            self.root.bind_class(widget_class, "<Shift-Insert>", self._paste_selection)
            self.root.bind_class(widget_class, "<Control-Insert>", self._copy_selection)
            self.root.bind_class(widget_class, "<Shift-Delete>", self._cut_selection)
        self.root.bind_all("<Control-KeyPress>", self._handle_control_keypress, add="+")

    def _handle_control_keypress(self, event: tk.Event) -> str | None:
        widget = getattr(event, "widget", None) or self.root.focus_get()
        if not isinstance(widget, (tk.Text, tk.Entry)):
            return None

        key = event.keysym.lower()
        if key in {"c", "\u0441"}:
            self._copy_widget_selection(widget)
            return "break"
        if key in {"v", "\u043c"}:
            self._paste_into_widget(widget)
            return "break"
        if key in {"x", "\u0447"}:
            self._cut_widget_selection(widget)
            return "break"
        if key in {"a", "\u0444"}:
            self._select_all_widget(widget)
            return "break"
        return None

    def _show_context_menu(self, event: tk.Event) -> str:
        widget = event.widget
        self.context_widget = widget
        widget.focus_set()

        if isinstance(widget, tk.Text):
            widget.mark_set("insert", f"@{event.x},{event.y}")
            widget.see("insert")
        elif isinstance(widget, tk.Entry):
            widget.icursor(widget.index(f"@{event.x}"))

        self.context_menu.tk_popup(event.x_root, event.y_root)
        self.context_menu.grab_release()
        return "break"

    def _copy_from_menu(self) -> None:
        if self.context_widget is not None:
            self._copy_widget_selection(self.context_widget)

    def _paste_from_menu(self) -> None:
        if self.context_widget is not None:
            self._paste_into_widget(self.context_widget)

    def _cut_from_menu(self) -> None:
        if self.context_widget is not None:
            self._cut_widget_selection(self.context_widget)

    def _select_all_from_menu(self) -> None:
        if self.context_widget is not None:
            self._select_all_widget(self.context_widget)

    def _copy_selection(self, event: tk.Event) -> str:
        self._copy_widget_selection(event.widget)
        return "break"

    def _paste_selection(self, event: tk.Event) -> str:
        self._paste_into_widget(event.widget)
        return "break"

    def _cut_selection(self, event: tk.Event) -> str:
        self._cut_widget_selection(event.widget)
        return "break"

    def _select_all(self, event: tk.Event) -> str:
        self._select_all_widget(event.widget)
        return "break"

    def _copy_widget_selection(self, widget: tk.Widget) -> None:
        selected = self._get_selected_text(widget)
        if not selected:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(selected)
        self.root.update()

    def copy_all_from_widget(self, widget: tk.Widget) -> None:
        if isinstance(widget, tk.Text):
            value = widget.get("1.0", "end-1c")
        elif isinstance(widget, tk.Entry):
            value = widget.get()
        else:
            return

        if not value:
            messagebox.showwarning("\u0412\u043d\u0438\u043c\u0430\u043d\u0438\u0435", "\u041d\u0435\u0442 \u0442\u0435\u043a\u0441\u0442\u0430 \u0434\u043b\u044f \u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u044f.")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.root.update()

    def _paste_into_widget(self, widget: tk.Widget) -> None:
        try:
            value = self.root.clipboard_get()
        except tk.TclError:
            return

        if isinstance(widget, tk.Text):
            try:
                widget.delete("sel.first", "sel.last")
            except tk.TclError:
                pass
            widget.insert("insert", value)
            widget.focus_set()
        elif isinstance(widget, tk.Entry):
            try:
                widget.delete("sel.first", "sel.last")
            except tk.TclError:
                pass
            widget.insert("insert", value)
            widget.focus_set()

    def paste_into_active_widget(self) -> None:
        widget = self.root.focus_get()
        if isinstance(widget, (tk.Text, tk.Entry)):
            self._paste_into_widget(widget)
            return

        self._paste_into_widget(self.text_input)

    def _cut_widget_selection(self, widget: tk.Widget) -> None:
        selected = self._get_selected_text(widget)
        if not selected:
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(selected)
        self.root.update()

        if isinstance(widget, tk.Text):
            widget.delete("sel.first", "sel.last")
        elif isinstance(widget, tk.Entry):
            widget.delete("sel.first", "sel.last")

    def _select_all_widget(self, widget: tk.Widget) -> None:
        if isinstance(widget, tk.Text):
            widget.tag_add("sel", "1.0", "end-1c")
            widget.mark_set("insert", "1.0")
            widget.see("insert")
        elif isinstance(widget, tk.Entry):
            widget.select_range(0, "end")
            widget.icursor("end")

    def _get_selected_text(self, widget: tk.Widget) -> str | None:
        try:
            if isinstance(widget, tk.Text):
                return widget.get("sel.first", "sel.last")
            if isinstance(widget, tk.Entry):
                return widget.selection_get()
        except tk.TclError:
            return None
        return None

    def get_text(self, widget: tk.Text) -> str:
        return widget.get("1.0", "end").strip()

    def set_text(self, widget: tk.Text, value: str) -> None:
        widget.delete("1.0", "end")
        widget.insert("1.0", value)

    def toggle_password_visibility(self) -> None:
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def encrypt_ui(self) -> None:
        text_value = self.get_text(self.text_input)
        key_value = self.password_entry.get().strip()

        if not text_value:
            messagebox.showwarning("Внимание", "Введите текст для шифрования.")
            return

        if not key_value:
            messagebox.showwarning("Внимание", "Введите пароль.")
            return

        try:
            result = encrypt_text(key_value, text_value, DEFAULT_KEY_SIZE_BITS)
        except Exception as exc:
            messagebox.showerror("Ошибка шифрования", str(exc))
            return

        self.set_text(self.result_text, result)

    def decrypt_ui(self) -> None:
        source_text = self.get_text(self.text_input)
        key_value = self.password_entry.get().strip()

        if not source_text:
            messagebox.showwarning("Внимание", "Вставьте зашифрованную строку Base64 в поле 'Исходные данные'.")
            return

        if not key_value:
            messagebox.showwarning("Внимание", "Введите пароль.")
            return

        try:
            result = decrypt_text(key_value, source_text)
        except Exception as exc:
            messagebox.showerror("Ошибка дешифрования", str(exc))
            return

        self.set_text(self.result_text, result)

    def copy_result(self) -> None:
        self.copy_all_from_widget(self.result_text)

    def swap_texts(self) -> None:
        source_text = self.get_text(self.text_input)
        result_text = self.get_text(self.result_text)
        self.set_text(self.text_input, result_text)
        self.set_text(self.result_text, source_text)

    def clear_all(self) -> None:
        self.set_text(self.text_input, "")
        self.set_text(self.result_text, "")
        self.text_input.focus_set()


def run_gui() -> int:
    root = tk.Tk()
    AESApp(root)
    root.mainloop()
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        return run_gui()

    try:
        if args.command == "encrypt":
            print(encrypt_text(args.password, args.text, args.size))
        elif args.command == "decrypt":
            print(decrypt_text(args.password, args.data))
        else:
            parser.error("Unknown command.")
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
