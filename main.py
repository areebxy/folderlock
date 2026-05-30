"""
FolderLock — AES-256-GCM Folder Encryption Utility
====================================================
Requirements:  pip install cryptography
Run:           python folder_locker.py
"""

import os
import io
import json
import struct
import hashlib
import secrets
import zipfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ──────────────────────────────────────────────
# Crypto helpers
# ──────────────────────────────────────────────

MAGIC        = b"FLCK"          # file magic
VERSION      = 1
SALT_LEN     = 32
NONCE_LEN    = 12
KDF_ITERS    = 600_000          # OWASP 2023 recommendation for PBKDF2-SHA256


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_folder(folder_path: Path, password: str,
                   progress_cb=None) -> Path:
    """
    1. Zip every file in folder_path (with relative paths preserved).
    2. Encrypt the zip bytes with AES-256-GCM.
    3. Write  <folder>.flck  next to the folder.
    4. Return the .flck path.
    """
    # --- collect files -------------------------------------------------------
    all_files = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            all_files.append(Path(root) / f)

    if not all_files:
        raise ValueError("The selected folder is empty.")

    # --- zip in-memory -------------------------------------------------------
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, fp in enumerate(all_files):
            arcname = fp.relative_to(folder_path.parent)
            zf.write(fp, arcname)
            if progress_cb:
                progress_cb(int((i + 1) / len(all_files) * 50))   # 0-50 %

    plaintext = zip_buf.getvalue()

    # --- encrypt -------------------------------------------------------------
    salt  = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key   = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)   # GCM tag appended

    # --- write .flck ---------------------------------------------------------
    # Format:  MAGIC (4) | VERSION (1) | SALT (32) | NONCE (12) | DATA_LEN (8) | DATA
    out_path = folder_path.parent / (folder_path.name + ".flck")
    with open(out_path, "wb") as fh:
        fh.write(MAGIC)
        fh.write(struct.pack(">B", VERSION))
        fh.write(salt)
        fh.write(nonce)
        fh.write(struct.pack(">Q", len(ciphertext)))
        fh.write(ciphertext)

    if progress_cb:
        progress_cb(75)

    # --- verify round-trip BEFORE touching originals -------------------------
    verify_decrypt(out_path, password)   # raises on failure

    if progress_cb:
        progress_cb(90)

    return out_path


def verify_decrypt(flck_path: Path, password: str) -> bytes:
    """Read + decrypt a .flck file.  Returns raw zip bytes."""
    with open(flck_path, "rb") as fh:
        magic = fh.read(4)
        if magic != MAGIC:
            raise ValueError("Not a valid .flck file.")
        version = struct.unpack(">B", fh.read(1))[0]
        salt  = fh.read(SALT_LEN)
        nonce = fh.read(NONCE_LEN)
        data_len = struct.unpack(">Q", fh.read(8))[0]
        ciphertext = fh.read(data_len)

    key    = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Wrong password or corrupted file.")

    return plaintext


def decrypt_folder(flck_path: Path, password: str,
                   out_dir: Path = None, progress_cb=None) -> Path:
    """
    Decrypt a .flck file and restore the folder tree next to the .flck.
    """
    zip_bytes = verify_decrypt(flck_path, password)
    if progress_cb:
        progress_cb(50)

    restore_root = out_dir or flck_path.parent
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        members = zf.namelist()
        for i, member in enumerate(members):
            zf.extract(member, restore_root)
            if progress_cb:
                progress_cb(50 + int((i + 1) / len(members) * 45))

    if progress_cb:
        progress_cb(100)

    # The top-level folder name is the first component of any member
    top_folder = restore_root / Path(members[0]).parts[0]
    return top_folder


def safe_delete_folder(folder_path: Path):
    """Overwrite every file with zeros then delete."""
    for fp in folder_path.rglob("*"):
        if fp.is_file():
            size = fp.stat().st_size
            with open(fp, "r+b") as fh:
                fh.write(b"\x00" * size)
            fp.unlink()
    # remove empty dirs bottom-up
    for dp in sorted(folder_path.rglob("*"), reverse=True):
        if dp.is_dir():
            try:
                dp.rmdir()
            except OSError:
                pass
    try:
        folder_path.rmdir()
    except OSError:
        pass


# ──────────────────────────────────────────────
# GUI
# ──────────────────────────────────────────────

BG       = "#0d0d0f"
PANEL    = "#16161a"
ACCENT   = "#00e5ff"
ACCENT2  = "#7b2fff"
TEXT     = "#e8e8f0"
MUTED    = "#6b6b80"
SUCCESS  = "#00c896"
DANGER   = "#ff4466"
BORDER   = "#2a2a35"

FONT_HEAD = ("Courier New", 22, "bold")
FONT_SUB  = ("Courier New", 10)
FONT_BODY = ("Segoe UI", 10)
FONT_MONO = ("Courier New", 9)


class FolderLockerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FolderLock By Areeb")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.geometry("560x640")

        self._selected_path: Path | None = None
        self._mode = tk.StringVar(value="lock")

        self._build_ui()
        self._center()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"+{x}+{y}")

    def _build_ui(self):
        # ── header ────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG, pady=20)
        hdr.pack(fill="x", padx=30)

        tk.Label(hdr, text="🔒 FOLDERLOCK BY AREEB", font=FONT_HEAD,
                 bg=BG, fg=ACCENT).pack(anchor="w")
        tk.Label(hdr, text="AES-256-GCM  ·  PBKDF2 600K  ·  Zero-copy verify",
                 font=FONT_SUB, bg=BG, fg=MUTED).pack(anchor="w")

        self._sep(BG)

        # ── mode toggle ───────────────────────────────────────────
        tab_frame = tk.Frame(self, bg=PANEL, bd=0, pady=8)
        tab_frame.pack(fill="x", padx=30, pady=(0, 6))

        for label, val in [("🔐  Lock Folder", "lock"), ("🔓  Unlock File", "unlock")]:
            btn = tk.Radiobutton(
                tab_frame, text=label, variable=self._mode, value=val,
                command=self._on_mode_change,
                bg=PANEL, fg=TEXT, selectcolor=BG,
                activebackground=PANEL, activeforeground=ACCENT,
                font=FONT_BODY, indicatoron=False,
                relief="flat", padx=18, pady=6,
                bd=0, cursor="hand2",
            )
            btn.pack(side="left", padx=(8, 0))

        self._sep(BG)

        # ── file picker ───────────────────────────────────────────
        pick_frame = tk.Frame(self, bg=BG, pady=4)
        pick_frame.pack(fill="x", padx=30)

        self._pick_label = tk.Label(
            pick_frame, text="Select Target", font=FONT_BODY,
            bg=BG, fg=MUTED)
        self._pick_label.pack(anchor="w", pady=(0, 4))

        row = tk.Frame(pick_frame, bg=BG)
        row.pack(fill="x")

        self._path_var = tk.StringVar(value="")
        self._path_entry = tk.Entry(
            row, textvariable=self._path_var,
            bg=PANEL, fg=TEXT, insertbackground=ACCENT,
            relief="flat", font=FONT_MONO,
            bd=0, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=ACCENT)
        self._path_entry.pack(side="left", fill="x", expand=True, ipady=8, ipadx=6)

        tk.Button(
            row, text="Browse", command=self._browse,
            bg=ACCENT2, fg="white", activebackground="#9b4fff",
            activeforeground="white", relief="flat",
            font=FONT_BODY, cursor="hand2", padx=12, pady=7, bd=0
        ).pack(side="left", padx=(8, 0))

        # ── password ──────────────────────────────────────────────
        pw_frame = tk.Frame(self, bg=BG, pady=4)
        pw_frame.pack(fill="x", padx=30)

        tk.Label(pw_frame, text="Password", font=FONT_BODY,
                 bg=BG, fg=MUTED).pack(anchor="w", pady=(0, 4))

        pw_row = tk.Frame(pw_frame, bg=BG)
        pw_row.pack(fill="x")

        self._pw_var   = tk.StringVar()
        self._show_pw  = tk.BooleanVar(value=False)
        self._pw_entry = tk.Entry(
            pw_row, textvariable=self._pw_var, show="●",
            bg=PANEL, fg=TEXT, insertbackground=ACCENT,
            relief="flat", font=FONT_MONO,
            bd=0, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=ACCENT)
        self._pw_entry.pack(side="left", fill="x", expand=True, ipady=8, ipadx=6)

        tk.Checkbutton(
            pw_row, text="Show", variable=self._show_pw,
            command=self._toggle_pw,
            bg=BG, fg=MUTED, activebackground=BG,
            activeforeground=TEXT, selectcolor=BG,
            font=FONT_BODY, cursor="hand2"
        ).pack(side="left", padx=(10, 0))

        # ── confirm password (lock mode only) ─────────────────────
        self._confirm_frame = tk.Frame(self, bg=BG, pady=4)
        self._confirm_frame.pack(fill="x", padx=30)

        tk.Label(self._confirm_frame, text="Confirm Password", font=FONT_BODY,
                 bg=BG, fg=MUTED).pack(anchor="w", pady=(0, 4))
        self._cpw_var = tk.StringVar()
        self._cpw_entry = tk.Entry(
            self._confirm_frame, textvariable=self._cpw_var, show="●",
            bg=PANEL, fg=TEXT, insertbackground=ACCENT,
            relief="flat", font=FONT_MONO,
            bd=0, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=ACCENT)
        self._cpw_entry.pack(fill="x", ipady=8, ipadx=6)

        # ── strength meter ────────────────────────────────────────
        self._strength_frame = tk.Frame(self, bg=BG, pady=2)
        self._strength_frame.pack(fill="x", padx=30)

        self._strength_bar = ttk.Progressbar(
            self._strength_frame, length=400, mode="determinate", maximum=100)
        self._strength_bar.pack(fill="x")
        self._strength_lbl = tk.Label(
            self._strength_frame, text="", font=FONT_MONO,
            bg=BG, fg=MUTED)
        self._strength_lbl.pack(anchor="w")

        self._pw_var.trace_add("write", lambda *_: self._update_strength())

        # ── options (lock only) ───────────────────────────────────
        self._opts_frame = tk.Frame(self, bg=BG, pady=8)
        self._opts_frame.pack(fill="x", padx=30)

        self._delete_orig = tk.BooleanVar(value=True)
        tk.Checkbutton(
            self._opts_frame, text="Securely shred originals after successful encryption",
            variable=self._delete_orig,
            bg=BG, fg=TEXT, activebackground=BG, activeforeground=TEXT,
            selectcolor=BG, font=FONT_BODY, cursor="hand2"
        ).pack(anchor="w")

        self._sep(BG)

        # ── action button ─────────────────────────────────────────
        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(fill="x", padx=30, pady=6)

        self._action_btn = tk.Button(
            btn_frame, text="🔐  Lock Folder",
            command=self._run,
            bg=ACCENT, fg=BG,
            activebackground="#33eeff", activeforeground=BG,
            relief="flat", font=("Segoe UI", 11, "bold"),
            cursor="hand2", padx=20, pady=12, bd=0)
        self._action_btn.pack(fill="x")

        # ── progress ──────────────────────────────────────────────
        prog_frame = tk.Frame(self, bg=BG, pady=8)
        prog_frame.pack(fill="x", padx=30)

        self._prog_bar = ttk.Progressbar(
            prog_frame, length=400, mode="determinate", maximum=100)
        self._prog_bar.pack(fill="x")

        self._status_var = tk.StringVar(value="Ready.")
        tk.Label(prog_frame, textvariable=self._status_var,
                 font=FONT_MONO, bg=BG, fg=MUTED).pack(anchor="w", pady=(4, 0))

        # ── log ───────────────────────────────────────────────────
        log_frame = tk.Frame(self, bg=BG)
        log_frame.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        self._log = tk.Text(
            log_frame, bg=PANEL, fg=MUTED, insertbackground=ACCENT,
            relief="flat", font=FONT_MONO, height=7,
            bd=0, highlightthickness=1,
            highlightbackground=BORDER, state="disabled",
            wrap="word")
        self._log.pack(fill="both", expand=True)

        # style progressbars
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Horizontal.TProgressbar",
                         troughcolor=PANEL, background=ACCENT,
                         bordercolor=PANEL, lightcolor=ACCENT,
                         darkcolor=ACCENT)

        self._on_mode_change()

    def _sep(self, bg):
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=30, pady=8)

    # ── Mode switch ───────────────────────────────────────────────────────────

    def _on_mode_change(self):
        mode = self._mode.get()
        if mode == "lock":
            self._pick_label.config(text="Select Folder to Lock")
            self._confirm_frame.pack(fill="x", padx=30, pady=4)
            self._strength_frame.pack(fill="x", padx=30, pady=2)
            self._opts_frame.pack(fill="x", padx=30, pady=8)
            self._action_btn.config(text="🔐  Lock Folder", bg=ACCENT, fg=BG)
        else:
            self._pick_label.config(text="Select .flck File to Unlock")
            self._confirm_frame.pack_forget()
            self._strength_frame.pack_forget()
            self._opts_frame.pack_forget()
            self._action_btn.config(text="🔓  Unlock File", bg=SUCCESS, fg=BG,
                                     activebackground="#00ffbb")
        self._path_var.set("")
        self._selected_path = None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _toggle_pw(self):
        show = self._show_pw.get()
        self._pw_entry.config(show="" if show else "●")
        self._cpw_entry.config(show="" if show else "●")

    def _browse(self):
        if self._mode.get() == "lock":
            path = filedialog.askdirectory(title="Select folder to lock")
            if path:
                self._selected_path = Path(path)
                self._path_var.set(path)
        else:
            path = filedialog.askopenfilename(
                title="Select .flck file",
                filetypes=[("FolderLock files", "*.flck"), ("All files", "*.*")])
            if path:
                self._selected_path = Path(path)
                self._path_var.set(path)

    def _update_strength(self):
        pw = self._pw_var.get()
        score, label, color = _password_strength(pw)
        self._strength_bar["value"] = score
        self._strength_lbl.config(text=f"Strength: {label}", fg=color)
        style = ttk.Style(self)
        style.configure("Horizontal.TProgressbar", background=color)

    def _log_write(self, msg: str, color=None):
        self._log.config(state="normal")
        self._log.insert("end", msg + "\n")
        self._log.see("end")
        self._log.config(state="disabled")

    def _set_progress(self, val: int):
        self._prog_bar["value"] = val
        self.update_idletasks()

    def _set_status(self, msg: str):
        self._status_var.set(msg)
        self.update_idletasks()

    # ── Run ───────────────────────────────────────────────────────────────────

    def _run(self):
        if not self._selected_path:
            messagebox.showwarning("No path selected", "Please select a folder or .flck file.")
            return

        pw = self._pw_var.get()
        if not pw:
            messagebox.showwarning("Password required", "Please enter a password.")
            return

        if self._mode.get() == "lock":
            if pw != self._cpw_var.get():
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return
            score, label, _ = _password_strength(pw)
            if score < 40:
                if not messagebox.askyesno(
                        "Weak password",
                        f"Your password is rated '{label}'.\n"
                        "A stronger password is highly recommended.\n\nContinue anyway?"):
                    return

        self._action_btn.config(state="disabled")
        threading.Thread(target=self._run_worker, daemon=True).start()

    def _run_worker(self):
        mode = self._mode.get()
        try:
            if mode == "lock":
                self._do_lock()
            else:
                self._do_unlock()
        except Exception as exc:
            self.after(0, lambda: self._on_error(str(exc)))
        finally:
            self.after(0, lambda: self._action_btn.config(state="normal"))

    def _do_lock(self):
        folder = self._selected_path
        pw     = self._pw_var.get()
        delete = self._delete_orig.get()

        self.after(0, lambda: self._set_status("Scanning folder…"))
        self.after(0, lambda: self._log_write(f"  Folder : {folder}"))

        file_count = sum(1 for _ in folder.rglob("*") if _.is_file())
        self.after(0, lambda: self._log_write(f"  Files  : {file_count}"))
        self.after(0, lambda: self._log_write("  Deriving key (PBKDF2 × 600 000)…"))

        def progress(v):
            self.after(0, lambda: self._set_progress(v))
            if v == 50:
                self.after(0, lambda: self._set_status("Encrypting…"))
            elif v == 75:
                self.after(0, lambda: self._set_status("Verifying integrity…"))

        out = encrypt_folder(folder, pw, progress_cb=progress)

        out_size = out.stat().st_size
        self.after(0, lambda: self._log_write(
            f"  Output : {out.name}  ({out_size/1024:.1f} KB)"))
        self.after(0, lambda: self._log_write("  ✔  Integrity verified (AES-GCM tag OK)"))

        if delete:
            self.after(0, lambda: self._set_status("Shredding originals…"))
            self.after(0, lambda: self._log_write("  Shredding original files…"))
            safe_delete_folder(folder)
            self.after(0, lambda: self._log_write("  ✔  Originals securely deleted"))

        self.after(0, lambda: self._set_progress(100))
        self.after(0, lambda: self._set_status("Locked successfully ✔"))
        self.after(0, lambda: messagebox.showinfo(
            "Locked",
            f"Folder locked successfully!\n\n"
            f"Container: {out.name}\n"
            f"Location : {out.parent}"))

    def _do_unlock(self):
        flck   = self._selected_path
        pw     = self._pw_var.get()

        self.after(0, lambda: self._set_status("Deriving key…"))
        self.after(0, lambda: self._log_write(f"  File : {flck.name}"))
        self.after(0, lambda: self._log_write("  Deriving key (PBKDF2 × 600 000)…"))

        def progress(v):
            self.after(0, lambda: self._set_progress(v))
            if v == 50:
                self.after(0, lambda: self._set_status("Decrypting…"))
            elif v >= 95:
                self.after(0, lambda: self._set_status("Restoring files…"))

        restored = decrypt_folder(flck, pw, progress_cb=progress)

        self.after(0, lambda: self._log_write(f"  ✔  Restored → {restored}"))
        self.after(0, lambda: self._set_progress(100))
        self.after(0, lambda: self._set_status("Unlocked successfully ✔"))
        self.after(0, lambda: messagebox.showinfo(
            "Unlocked",
            f"Folder unlocked successfully!\n\n"
            f"Restored to: {restored}"))

    def _on_error(self, msg: str):
        self._set_progress(0)
        self._set_status(f"Error: {msg}")
        self._log_write(f"  ✖  {msg}")
        messagebox.showerror("Error", msg)


# ──────────────────────────────────────────────
# Password strength estimator
# ──────────────────────────────────────────────

def _password_strength(pw: str):
    score = 0
    if len(pw) >= 8:   score += 20
    if len(pw) >= 12:  score += 15
    if len(pw) >= 16:  score += 10
    if any(c.islower() for c in pw): score += 10
    if any(c.isupper() for c in pw): score += 10
    if any(c.isdigit() for c in pw): score += 15
    if any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\" for c in pw): score += 20
    score = min(score, 100)
    if score < 30:   return score, "Very Weak",  DANGER
    if score < 50:   return score, "Weak",       "#ff9944"
    if score < 70:   return score, "Fair",       "#ffdd44"
    if score < 90:   return score, "Strong",     SUCCESS
    return score, "Very Strong", ACCENT


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    app = FolderLockerApp()
    app.mainloop()
