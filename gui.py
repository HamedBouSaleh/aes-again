import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import secrets
import os

from aes_core import (
    SBOX,
    INV_SBOX,
    RCON,
    parse_hex_block,
    parse_hex_key,
    key_expansion,
    encrypt_block,
    decrypt_block,
    encrypt_block_with_rounds,
    decrypt_block_with_rounds,
    one_round_steps,
    words_to_hex_words,
    state_to_hex_grid,
    bit_mismatch,
)

KEY_BLOCK_LEN = 32
DEFAULT_KEY = "000102030405060708090a0b0c0d0e0f"
DEFAULT_BLOCK = "00112233445566778899aabbccddeeff"
NIST_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
NIST_PT = "3243f6a8885a308d313198a2e0370734"
NIST_CT = "3925841d02dc09fbdc118597196a0b32"


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        self.widget.bind("<Enter>", self.show)
        self.widget.bind("<Leave>", self.hide)

    def show(self, event=None):
        if self.tip:
            return
        x, y, _, _ = self.widget.bbox("insert") or (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 20
        y += self.widget.winfo_rooty() + self.widget.winfo_height() + 2
        self.tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        f = tk.Frame(tw, background="#ffffe0", relief="solid", borderwidth=1)
        f.pack()
        label = tk.Label(f, text=self.text, justify="left", background="#ffffe0", font=("TkDefaultFont", 9))
        label.pack(padx=4, pady=2)

    def hide(self, event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


def add_tooltip(widget, text):
    ToolTip(widget, text)


def normalize_hex(s):
    return s.replace(" ", "").replace("\n", "").replace("\t", "").strip().lower()


def is_valid_hex_block(s):
    n = normalize_hex(s)
    return len(n) == KEY_BLOCK_LEN and all(c in "0123456789abcdef" for c in n)


def apply_theme(root, dark=False):
    style = ttk.Style(root)
    if dark:
        bg, bg_elevated, fg, border = "#1a1d23", "#252830", "#e4e6eb", "#3d424a"
        style.configure(".", background=bg, foreground=fg, fieldbackground=bg_elevated)
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
        style.configure("TLabelframe", background=bg, foreground=fg)
        style.configure("TLabelframe.Label", background=bg, foreground=fg, font=("Segoe UI", 10, "bold"))
        style.configure("TButton", background=bg_elevated, foreground=fg, padding=(12, 6))
        style.map("TButton", background=[("active", "#32363e")])
        style.configure("TEntry", fieldbackground=bg_elevated, foreground=fg, insertcolor=fg)
        style.configure("TNotebook", background=bg)
        style.configure("TNotebook.Tab", background=bg_elevated, foreground=fg, padding=(12, 8))
        style.map("TNotebook.Tab", background=[("selected", "#2d3238")])
        style.configure("TRadiobutton", background=bg, foreground=fg)
        root.configure(bg=bg)
    else:
        bg, bg_card, fg, accent = "#f0f2f5", "#ffffff", "#1c1e21", "#1877f2"
        style.configure(".", background=bg, foreground=fg, fieldbackground=bg_card)
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
        style.configure("TLabelframe", background=bg, foreground=fg)
        style.configure("TLabelframe.Label", background=bg, foreground=fg, font=("Segoe UI", 10, "bold"))
        style.configure("TButton", background=accent, foreground="#111111", padding=(12, 6))
        style.map("TButton", background=[("active", "#166fe5")])
        style.configure("TEntry", fieldbackground=bg_card, foreground=fg)
        style.configure("TNotebook", background=bg)
        style.configure("TNotebook.Tab", background=bg_card, foreground=fg, padding=(12, 8))
        style.map("TNotebook.Tab", background=[("selected", bg)])
        style.configure("TRadiobutton", background=bg, foreground=fg)
        root.configure(bg=bg)


def make_state_grid(parent, state, title="", font_size=11):
    f = ttk.LabelFrame(parent, text=title or "State")
    for r in range(4):
        for c in range(4):
            cell = ttk.Label(f, text=f"{state[r][c]:02x}", width=4, font=("Consolas", font_size))
            cell.grid(row=r, column=c, padx=3, pady=3)
    return f


class HexEntry(ttk.Frame):
    def __init__(self, parent, width=44, default="", **kw):
        super().__init__(parent, **kw)
        self.entry = ttk.Entry(self, width=width)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.insert(0, default)
        self.valid_label = ttk.Label(self, text="", width=4)
        self.valid_label.pack(side="right", padx=(4, 0))
        self.entry.bind("<KeyRelease>", self._on_change)

    def _on_change(self, event=None):
        if is_valid_hex_block(self.entry.get()):
            self.valid_label.config(text="✓")
        else:
            self.valid_label.config(text="")

    def get(self):
        return self.entry.get()

    def set(self, s):
        self.entry.delete(0, tk.END)
        self.entry.insert(0, s)
        self._on_change()

    def get_valid_bytes(self):
        if not is_valid_hex_block(self.entry.get()):
            raise ValueError("Invalid hex: need 32 hex characters (128 bits)")
        return bytes.fromhex(normalize_hex(self.entry.get()))


class BaseTab(ttk.Frame):
    def __init__(self, parent, status_callback=None, **kw):
        super().__init__(parent, **kw)
        self.status = status_callback or (lambda s: None)

    def set_status(self, msg):
        if self.status:
            self.status(msg)


class SingleRoundTab(BaseTab):
    def __init__(self, parent, status_callback=None, **kw):
        super().__init__(parent, status_callback, **kw)
        self.round_keys = None
        self.steps = []
        self.step_index = 0
        row = 0
        ttk.Label(self, text="Key (128 bits, hex):").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        self.key_entry = HexEntry(self, default=DEFAULT_KEY)
        self.key_entry.grid(row=row, column=1, padx=8, pady=6)
        add_tooltip(self.key_entry.entry, "32 hex chars (128 bits). Spaces allowed.")
        row += 1
        ttk.Label(self, text="Data block (128 bits, hex):").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        self.block_entry = HexEntry(self, default=DEFAULT_BLOCK)
        self.block_entry.grid(row=row, column=1, padx=8, pady=6)
        add_tooltip(self.block_entry.entry, "32 hex chars (128 bits).")
        row += 1
        ttk.Label(self, text="Round (0–10):").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        round_f = ttk.Frame(self)
        round_f.grid(row=row, column=1, sticky="w", padx=8, pady=6)
        self.round_var = tk.IntVar(value=1)
        for i in range(11):
            ttk.Radiobutton(round_f, text=str(i), variable=self.round_var, value=i).pack(side="left", padx=2)
        row += 1
        btn_f = ttk.Frame(self)
        btn_f.grid(row=row, column=0, columnspan=2, pady=12)
        ttk.Button(btn_f, text="Load round", command=self.load_round).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Next step", command=self.next_step).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Previous step", command=self.prev_step).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Reset", command=self.reset_step).pack(side="left", padx=4)
        row += 1
        self.step_label = ttk.Label(self, text="Load a round to see steps.", font=("TkDefaultFont", 10, "bold"))
        self.step_label.grid(row=row, column=0, columnspan=2, pady=6)
        row += 1
        self.state_frame = ttk.Frame(self)
        self.state_frame.grid(row=row, column=0, columnspan=2, pady=10)

    def load_round(self):
        try:
            key = self.key_entry.get_valid_bytes()
            block = self.block_entry.get_valid_bytes()
            r = self.round_var.get()
            if not (0 <= r <= 10):
                raise ValueError("Round must be 0–10")
        except Exception as e:
            messagebox.showerror("Input error", str(e))
            self.set_status("Error: " + str(e))
            return
        self.round_keys = key_expansion(key)
        self.steps = one_round_steps(block, self.round_keys, r)
        self.step_index = 0
        self.show_current_step()
        self.set_status(f"Round {r} loaded — {len(self.steps)} step(s)")

    def show_current_step(self):
        for w in self.state_frame.winfo_children():
            w.destroy()
        if not self.steps:
            self.step_label.config(text="Load a round to see steps.")
            return
        name, state = self.steps[self.step_index]
        self.step_label.config(text=f"Step {self.step_index + 1}/{len(self.steps)}: {name}")
        make_state_grid(self.state_frame, state, name).pack()

    def next_step(self):
        if not self.steps:
            messagebox.showinfo("Info", "Load a round first.")
            return
        self.step_index = (self.step_index + 1) % len(self.steps)
        self.show_current_step()

    def prev_step(self):
        if not self.steps:
            return
        self.step_index = (self.step_index - 1) % len(self.steps)
        self.show_current_step()

    def reset_step(self):
        if not self.steps:
            return
        self.step_index = 0
        self.show_current_step()


class FullAESTab(BaseTab):
    def __init__(self, parent, status_callback=None, **kw):
        super().__init__(parent, status_callback, **kw)
        row = 0
        ttk.Label(self, text="Key (128 bits, hex):").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        key_f = ttk.Frame(self)
        key_f.grid(row=row, column=1, sticky="ew", padx=8, pady=6)
        self.key_entry = HexEntry(key_f, default=DEFAULT_KEY)
        self.key_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(key_f, text="Random", width=8, command=lambda: self.key_entry.set(secrets.token_hex(16))).pack(side="right", padx=4)
        ttk.Button(key_f, text="Save…", width=6, command=self.save_key).pack(side="right", padx=2)
        ttk.Button(key_f, text="Load…", width=6, command=self.load_key).pack(side="right")
        add_tooltip(self.key_entry.entry, "32 hex chars. Use Random or Load from file.")
        row += 1
        ttk.Label(self, text="Block (128 bits, hex):").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        block_f = ttk.Frame(self)
        block_f.grid(row=row, column=1, sticky="ew", padx=8, pady=6)
        self.block_entry = HexEntry(block_f, default=DEFAULT_BLOCK)
        self.block_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(block_f, text="Random", width=8, command=lambda: self.block_entry.set(secrets.token_hex(16))).pack(side="right", padx=4)
        ttk.Button(block_f, text="Save…", width=6, command=self.save_block).pack(side="right", padx=2)
        ttk.Button(block_f, text="Load…", width=6, command=self.load_block).pack(side="right")
        row += 1
        btn_f = ttk.Frame(self)
        btn_f.grid(row=row, column=0, columnspan=2, pady=10)
        ttk.Button(btn_f, text="Encrypt", command=self.do_encrypt).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Decrypt", command=self.do_decrypt).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Copy output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Export…", command=self.export_output).pack(side="left", padx=4)
        row += 1
        self.output = scrolledtext.ScrolledText(self, height=26, width=72, font=("Consolas", 10))
        self.output.grid(row=row, column=0, columnspan=2, padx=8, pady=8)
        self.columnconfigure(1, weight=1)

    def load_key(self):
        path = filedialog.askopenfilename(filetypes=[("Hex/Text", "*.txt *.hex"), ("All", "*.*")])
        if path:
            try:
                with open(path) as f:
                    data = normalize_hex(f.read())
                if len(data) == KEY_BLOCK_LEN and all(c in "0123456789abcdef" for c in data):
                    self.key_entry.set(data)
                    self.set_status("Key loaded")
                else:
                    messagebox.showerror("Error", "File must contain exactly 32 hex characters.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def load_block(self):
        path = filedialog.askopenfilename(filetypes=[("Hex/Text", "*.txt *.hex"), ("All", "*.*")])
        if path:
            try:
                with open(path) as f:
                    data = normalize_hex(f.read())
                if len(data) == KEY_BLOCK_LEN and all(c in "0123456789abcdef" for c in data):
                    self.block_entry.set(data)
                    self.set_status("Block loaded")
                else:
                    messagebox.showerror("Error", "File must contain exactly 32 hex characters.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def save_key(self):
        if not is_valid_hex_block(self.key_entry.get()):
            messagebox.showwarning("Warning", "Enter a valid key first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            try:
                with open(path, "w") as f:
                    f.write(normalize_hex(self.key_entry.get()))
                self.set_status("Key saved")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def save_block(self):
        if not is_valid_hex_block(self.block_entry.get()):
            messagebox.showwarning("Warning", "Enter a valid block first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            try:
                with open(path, "w") as f:
                    f.write(normalize_hex(self.block_entry.get()))
                self.set_status("Block saved")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def copy_output(self):
        text = self.output.get("1.0", tk.END)
        if text.strip():
            self.master.winfo_toplevel().clipboard_clear()
            self.master.winfo_toplevel().clipboard_append(text)
            self.set_status("Output copied to clipboard")

    def export_output(self):
        text = self.output.get("1.0", tk.END)
        if not text.strip():
            messagebox.showinfo("Info", "No output to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("Markdown", "*.md"), ("All", "*.*")])
        if path:
            try:
                with open(path, "w") as f:
                    f.write(text)
                self.set_status("Exported to " + os.path.basename(path))
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def do_encrypt(self):
        try:
            key = self.key_entry.get_valid_bytes()
            block = self.block_entry.get_valid_bytes()
        except Exception as e:
            messagebox.showerror("Input error", str(e))
            return
        rks = key_expansion(key)
        ciphertext = encrypt_block(block, rks)
        states = encrypt_block_with_rounds(block, rks)
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, "=== Full AES Encryption ===\n\n")
        self.output.insert(tk.END, f"Plaintext:  {block.hex()}\n")
        self.output.insert(tk.END, f"Ciphertext: {ciphertext.hex()}\n\n")
        self.output.insert(tk.END, "State after each round:\n\n")
        for rnd in range(11):
            self.output.insert(tk.END, f"--- After Round {rnd} ---\n")
            self.output.insert(tk.END, state_to_hex_grid(states[rnd]) + "\n\n")
        self.set_status("Encryption done")

    def do_decrypt(self):
        try:
            key = self.key_entry.get_valid_bytes()
            block = self.block_entry.get_valid_bytes()
        except Exception as e:
            messagebox.showerror("Input error", str(e))
            return
        rks = key_expansion(key)
        plaintext = decrypt_block(block, rks)
        states = decrypt_block_with_rounds(block, rks)
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, "=== Full AES Decryption ===\n\n")
        self.output.insert(tk.END, f"Ciphertext: {block.hex()}\n")
        self.output.insert(tk.END, f"Plaintext:  {plaintext.hex()}\n\n")
        self.output.insert(tk.END, "State after each round:\n\n")
        for i, rnd in enumerate(range(10, -1, -1)):
            self.output.insert(tk.END, f"--- After round {rnd} ---\n")
            self.output.insert(tk.END, state_to_hex_grid(states[i]) + "\n\n")
        self.set_status("Decryption done")


class AvalancheTab(BaseTab):
    def __init__(self, parent, status_callback=None, **kw):
        super().__init__(parent, status_callback, **kw)
        row = 0
        ttk.Label(self, text="Key 1 (128 bits, hex):").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        k1_f = ttk.Frame(self)
        k1_f.grid(row=row, column=1, sticky="ew", padx=8, pady=6)
        self.key_entry = HexEntry(k1_f, default=DEFAULT_KEY)
        self.key_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(k1_f, text="Random", command=lambda: self.key_entry.set(secrets.token_hex(16))).pack(side="right", padx=4)
        row += 1
        ttk.Label(self, text="Block 1 (128 bits, hex):").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        b1_f = ttk.Frame(self)
        b1_f.grid(row=row, column=1, sticky="ew", padx=8, pady=6)
        self.block1_entry = HexEntry(b1_f, default=DEFAULT_BLOCK)
        self.block1_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(b1_f, text="Random", command=lambda: self.block1_entry.set(secrets.token_hex(16))).pack(side="right", padx=4)
        row += 1
        ttk.Label(self, text="Key 2 (for same-block mode):").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        self.key2_entry = HexEntry(self, default=DEFAULT_KEY)
        self.key2_entry.grid(row=row, column=1, sticky="ew", padx=8, pady=6)
        row += 1
        ttk.Label(self, text="Block 2 (for same-key mode):").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        self.block2_entry = HexEntry(self, default="00112233445566778899aabbccddee00")
        self.block2_entry.grid(row=row, column=1, sticky="ew", padx=8, pady=6)
        row += 1
        self.mode_var = tk.StringVar(value="same_key")
        mode_f = ttk.LabelFrame(self, text="Avalanche mode")
        mode_f.grid(row=row, column=0, columnspan=2, sticky="w", padx=8, pady=8)
        ttk.Radiobutton(mode_f, text="Same key, different block (compare Block1 vs Block2)", variable=self.mode_var, value="same_key").pack(anchor="w")
        ttk.Radiobutton(mode_f, text="Same block, different key (compare Key1 vs Key2)", variable=self.mode_var, value="same_block").pack(anchor="w")
        row += 1
        btn_f = ttk.Frame(self)
        btn_f.grid(row=row, column=0, columnspan=2, pady=8)
        ttk.Button(btn_f, text="Run Avalanche", command=self.run_avalanche).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Copy output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Export…", command=self.export_output).pack(side="left", padx=4)
        row += 1
        self.output = scrolledtext.ScrolledText(self, height=20, width=72, font=("Consolas", 10))
        self.output.grid(row=row, column=0, columnspan=2, padx=8, pady=8)
        self.columnconfigure(1, weight=1)

    def copy_output(self):
        text = self.output.get("1.0", tk.END)
        if text.strip():
            self.master.winfo_toplevel().clipboard_clear()
            self.master.winfo_toplevel().clipboard_append(text)
            self.set_status("Output copied")

    def export_output(self):
        text = self.output.get("1.0", tk.END)
        if not text.strip():
            messagebox.showinfo("Info", "No output to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            try:
                with open(path, "w") as f:
                    f.write(text)
                self.set_status("Exported")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def run_avalanche(self):
        try:
            key1 = self.key_entry.get_valid_bytes()
            block1 = self.block1_entry.get_valid_bytes()
            if self.mode_var.get() == "same_key":
                key2 = key1
                block2 = self.block2_entry.get_valid_bytes()
            else:
                key2 = self.key2_entry.get_valid_bytes()
                block2 = block1
        except Exception as e:
            messagebox.showerror("Input error", str(e))
            return
        rks1 = key_expansion(key1)
        rks2 = key_expansion(key2)
        states1 = encrypt_block_with_rounds(block1, rks1)
        states2 = encrypt_block_with_rounds(block2, rks2)
        self.output.delete("1.0", tk.END)
        if self.mode_var.get() == "same_key":
            self.output.insert(tk.END, "=== Avalanche: Same key, different block ===\n\n")
            self.output.insert(tk.END, f"Key:     {key1.hex()}\n")
            self.output.insert(tk.END, f"Block 1: {block1.hex()}\n")
            self.output.insert(tk.END, f"Block 2: {block2.hex()}\n\n")
        else:
            self.output.insert(tk.END, "=== Avalanche: Same block, different key ===\n\n")
            self.output.insert(tk.END, f"Key 1:   {key1.hex()}\n")
            self.output.insert(tk.END, f"Key 2:   {key2.hex()}\n")
            self.output.insert(tk.END, f"Block:   {block1.hex()}\n\n")
        self.output.insert(tk.END, "Bit mismatch after each round (out of 128 bits):\n\n")
        self.output.insert(tk.END, "Round | Bit mismatch\n")
        self.output.insert(tk.END, "------+-------------\n")
        for rnd in range(11):
            m = bit_mismatch(states1[rnd], states2[rnd])
            self.output.insert(tk.END, f"  {rnd:2d}   |     {m:3d}\n")
        self.set_status("Avalanche done")


class KeyExpansionTab(BaseTab):
    def __init__(self, parent, status_callback=None, **kw):
        super().__init__(parent, status_callback, **kw)
        row = 0
        ttk.Label(self, text="Key (128 bits, hex):").grid(row=row, column=0, sticky="w", padx=8, pady=6)
        k_f = ttk.Frame(self)
        k_f.grid(row=row, column=1, sticky="ew", padx=8, pady=6)
        self.key_entry = HexEntry(k_f, default=DEFAULT_KEY)
        self.key_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(k_f, text="Random", command=lambda: self.key_entry.set(secrets.token_hex(16))).pack(side="right", padx=4)
        row += 1
        btn_f = ttk.Frame(self)
        btn_f.grid(row=row, column=0, columnspan=2, pady=10)
        ttk.Button(btn_f, text="Generate key schedule", command=self.generate).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Copy output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(btn_f, text="Export…", command=self.export_output).pack(side="left", padx=4)
        row += 1
        self.output = scrolledtext.ScrolledText(self, height=28, width=72, font=("Consolas", 10))
        self.output.grid(row=row, column=0, columnspan=2, padx=8, pady=8)
        self.columnconfigure(1, weight=1)

    def generate(self):
        try:
            key = self.key_entry.get_valid_bytes()
        except Exception as e:
            messagebox.showerror("Input error", str(e))
            return
        round_keys = key_expansion(key)
        hex_groups = words_to_hex_words(round_keys)
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, "=== AES-128 Key Expansion (44 words, 11 groups of 4) ===\n\n")
        self.output.insert(tk.END, f"Key: {key.hex()}\n\n")
        for rnd in range(11):
            self.output.insert(tk.END, f"Round key {rnd:2d} (w[{rnd*4}]..w[{rnd*4+3}]):  ")
            self.output.insert(tk.END, "  ".join(hex_groups[rnd]) + "\n")
        self.set_status("Key schedule generated")

    def copy_output(self):
        text = self.output.get("1.0", tk.END)
        if text.strip():
            self.master.winfo_toplevel().clipboard_clear()
            self.master.winfo_toplevel().clipboard_append(text)
            self.set_status("Output copied")

    def export_output(self):
        text = self.output.get("1.0", tk.END)
        if not text.strip():
            messagebox.showinfo("Info", "Generate key schedule first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            try:
                with open(path, "w") as f:
                    f.write(text)
                self.set_status("Exported")
            except Exception as e:
                messagebox.showerror("Error", str(e))


class SBoxTab(BaseTab):
    def __init__(self, parent, status_callback=None, **kw):
        super().__init__(parent, status_callback, **kw)
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        sbox_f = ttk.Frame(nb)
        nb.add(sbox_f, text="S-box")
        ttk.Label(sbox_f, text="AES S-box (16×16, hex). Row = high nibble, Col = low nibble.", font=("TkDefaultFont", 9)).pack(pady=(0, 4))
        grid_f = ttk.Frame(sbox_f)
        grid_f.pack()
        for r in range(16):
            for c in range(16):
                val = SBOX[r * 16 + c]
                ttk.Label(grid_f, text=f"{val:02x}", width=3, font=("Consolas", 9)).grid(row=r, column=c, padx=1, pady=1)
        inv_f = ttk.Frame(nb)
        nb.add(inv_f, text="Inverse S-box")
        ttk.Label(inv_f, text="AES Inverse S-box (16×16, hex).", font=("TkDefaultFont", 9)).pack(pady=(0, 4))
        grid_inv = ttk.Frame(inv_f)
        grid_inv.pack()
        for r in range(16):
            for c in range(16):
                val = INV_SBOX[r * 16 + c]
                ttk.Label(grid_inv, text=f"{val:02x}", width=3, font=("Consolas", 9)).grid(row=r, column=c, padx=1, pady=1)
        rcon_f = ttk.Frame(nb)
        nb.add(rcon_f, text="Rcon")
        ttk.Label(rcon_f, text="Round constants Rcon[i] for key schedule (i = 0..10):", font=("TkDefaultFont", 9)).pack(pady=(0, 4))
        rcon_text = "  ".join(f"Rcon[{i}]={RCON[i]:02x}" for i in range(11))
        ttk.Label(rcon_f, text=rcon_text, font=("Consolas", 10)).pack(anchor="w")
        self.set_status("S-box / Rcon viewer")


class MainApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("EECE 455 Project 7 — AES Again")
        self.root.minsize(800, 640)
        self.root.geometry("920x680")
        self.dark_theme = tk.BooleanVar(value=False)
        self.status_msg = tk.StringVar(value="Ready")
        apply_theme(self.root, self.dark_theme.get())
        self._build_ui()
        self._bind_shortcuts()
        self.status_bar_update()

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        file_m = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_m)
        file_m.add_command(label="Run self-test (NIST)", command=self.run_self_test)
        file_m.add_separator()
        file_m.add_command(label="Exit", command=self.root.quit)
        view_m = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_m)
        view_m.add_checkbutton(label="Dark theme", variable=self.dark_theme, command=self.toggle_theme)
        help_m = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_m)
        help_m.add_command(label="About", command=self.show_about)
        help_m.add_command(label="Input format", command=self.show_help)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        status_cb = lambda msg: self.status_msg.set(msg)
        self.notebook.add(SingleRoundTab(self.notebook, status_cb), text="1. Single round")
        self.notebook.add(FullAESTab(self.notebook, status_cb), text="2. Full AES")
        self.notebook.add(AvalancheTab(self.notebook, status_cb), text="3. Avalanche")
        self.notebook.add(KeyExpansionTab(self.notebook, status_cb), text="4. Key expansion")
        self.notebook.add(SBoxTab(self.notebook, status_cb), text="5. S-box / Rcon")

        status_f = ttk.Frame(self.root)
        status_f.pack(side="bottom", fill="x", padx=10, pady=4)
        ttk.Label(status_f, textvariable=self.status_msg).pack(side="left")
        ttk.Button(status_f, text="Self-test", width=10, command=self.run_self_test).pack(side="right", padx=4)

    def _bind_shortcuts(self):
        self.root.bind("<Control-Return>", lambda e: self._trigger_current_action())
        self.root.bind("<Control-c>", lambda e: self._copy_focused_output())

    def _trigger_current_action(self):
        nb = getattr(self, "notebook", None)
        if not nb:
            return
        try:
            idx = nb.index(nb.select())
            tab = nb.nametowidget(nb.select())
            if idx == 0 and hasattr(tab, "load_round"):
                tab.load_round()
            elif idx == 1 and hasattr(tab, "do_encrypt"):
                tab.do_encrypt()
            elif idx == 2 and hasattr(tab, "run_avalanche"):
                tab.run_avalanche()
            elif idx == 3 and hasattr(tab, "generate"):
                tab.generate()
        except Exception:
            pass

    def _copy_focused_output(self):
        w = self.root.focus_get()
        while w:
            if isinstance(w, scrolledtext.ScrolledText):
                t = w.get("1.0", tk.END)
                if t.strip():
                    self.root.clipboard_clear()
                    self.root.clipboard_append(t)
                    self.status_msg.set("Output copied")
                return
            w = w.master if hasattr(w, "master") else None

    def toggle_theme(self):
        apply_theme(self.root, self.dark_theme.get())
        self.status_msg.set("Theme updated")

    def status_bar_update(self):
        self.root.after(500, self.status_bar_update)

    def run_self_test(self):
        try:
            key = parse_hex_key(NIST_KEY)
            block = parse_hex_block(NIST_PT)
            rks = key_expansion(key)
            ct = encrypt_block(block, rks)
            ok = ct.hex() == NIST_CT
            pt = decrypt_block(ct, rks)
            ok = ok and pt == block
            if ok:
                messagebox.showinfo("Self-test", "NIST vector passed.\nEncrypt & decrypt round-trip OK.")
                self.status_msg.set("Self-test: Passed")
            else:
                messagebox.showerror("Self-test", "NIST vector failed.")
                self.status_msg.set("Self-test: Failed")
        except Exception as e:
            messagebox.showerror("Self-test", str(e))
            self.status_msg.set("Self-test: Error")

    def show_about(self):
        messagebox.showinfo("About", "EECE 455/632 Project 7 — AES Again\n\n"
                                "AES-128 educational tool: single-round step-by-step,\n"
                                "full encrypt/decrypt, avalanche, key expansion,\n"
                                "S-box viewer. FIPS 197 reference.\n\n"
                                "Pure Python, no external crypto libraries.")

    def show_help(self):
        messagebox.showinfo("Input format", "Key and block: 32 hexadecimal characters (128 bits).\n\n"
                                  "Examples:\n"
                                  "Key:  000102030405060708090a0b0c0d0e0f\n"
                                  "Block: 00112233445566778899aabbccddeeff\n\n"
                                  "Spaces and newlines are ignored. Use Random or Load from file.")

    def run(self):
        self.root.mainloop()


def main():
    app = MainApp()
    app.run()


if __name__ == "__main__":
    main()
