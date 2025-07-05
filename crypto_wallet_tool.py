#!/usr/bin/env python3
"""
CryptoWalletTool.py
===================

A standalone GUI application that combines BIP-39 mnemonic phrase generation
with a multi-coin address viewer.

Features:
- Securely generate multiple BIP-39 seed phrases of 12, 15, 18, 21, or 24 words.
- Click a button next to any generated phrase to send it directly to the viewer.
- Save generated phrases or derived addresses to a .txt or .csv file.
- View derived addresses from a mnemonic, with optional BIP-39 passphrase support.
- Generate and view a sequence of addresses for a specific coin.
- Self-contained: all dependencies and data are bundled.
"""

import sys
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Try to import required packages; these will be bundled by PyInstaller.
try:
    from bip_utils import (
        Bip39Languages,
        Bip39MnemonicGenerator,
        Bip39MnemonicValidator,
        Bip39SeedGenerator,
        Bip39WordsNum,
        Bip44, Bip44Coins, Bip44Changes,
    )
    import pyperclip
except ImportError:
    # This message is for developers running the script directly without
    # installing dependencies. The final bundled .exe will not trigger this.
    print("ERROR: Missing required packages. Please run:")
    print(f"pip install --user bip-utils pyperclip")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# BIP-39 word length mapping
WORD_COUNTS = {12, 15, 18, 21, 24}

# Supported chains for address derivation
SUPPORTED_COINS = {
    "Bitcoin (BTC)": Bip44Coins.BITCOIN,
    "Ethereum (ETH)": Bip44Coins.ETHEREUM,
    "Litecoin (LTC)": Bip44Coins.LITECOIN,
    "Dogecoin (DOGE)": Bip44Coins.DOGECOIN,
    "Solana (SOL)": Bip44Coins.SOLANA,
}


# ---------------------------------------------------------------------------
# Core BIP-39 Logic
# ---------------------------------------------------------------------------

def generate_mnemonic(word_count: int) -> str:
    """Generates a single BIP-39 mnemonic phrase using the bip_utils library."""
    if word_count not in WORD_COUNTS:
        raise ValueError("Invalid word count specified.")
    
    # Map our integer word count to the bip_utils enum
    words_num_map = {
        12: Bip39WordsNum.WORDS_NUM_12,
        15: Bip39WordsNum.WORDS_NUM_15,
        18: Bip39WordsNum.WORDS_NUM_18,
        21: Bip39WordsNum.WORDS_NUM_21,
        24: Bip39WordsNum.WORDS_NUM_24,
    }
    
    # Generate mnemonic using the library's own generator for consistency
    mnemonic = Bip39MnemonicGenerator(Bip39Languages.ENGLISH).FromWordsNumber(words_num_map[word_count])
    return str(mnemonic)

# ---------------------------------------------------------------------------
# Core Address Derivation Logic
# ---------------------------------------------------------------------------

def validate_mnemonic(phrase: str) -> str:
    """Normalises and validates a BIP-39 mnemonic. Raises ValueError if invalid."""
    normalized_phrase = " ".join(phrase.strip().lower().split())
    try:
        Bip39MnemonicValidator(Bip39Languages.ENGLISH).Validate(normalized_phrase)
        return normalized_phrase
    except Exception as e:
        # Re-raise with a more user-friendly message
        raise ValueError(f"Invalid BIP-39 mnemonic: {e}")

def get_first_addresses(mnemonic: str, passphrase: str = "") -> dict[str, str]:
    """Return a dictionary of the first external address for each supported chain."""
    valid_mnemonic = validate_mnemonic(mnemonic)
    seed_bytes = Bip39SeedGenerator(valid_mnemonic).Generate(passphrase)
    
    addresses = {}
    for name, coin_type in SUPPORTED_COINS.items():
        bip44_mst = Bip44.FromSeed(seed_bytes, coin_type)
        bip44_acc = bip44_mst.Purpose().Coin().Account(0)
        bip44_chg = bip44_acc.Change(Bip44Changes.CHAIN_EXT)
        address = bip44_chg.AddressIndex(0).PublicKey().ToAddress()
        addresses[name] = address
    return addresses

def get_many_addresses(mnemonic: str, chain_name: str, count: int, passphrase: str = "") -> list[str]:
    """Return a list of the first 'n' external addresses for a single chain."""
    if chain_name not in SUPPORTED_COINS:
        raise ValueError(f"Unsupported chain: {chain_name}")

    valid_mnemonic = validate_mnemonic(mnemonic)
    seed_bytes = Bip39SeedGenerator(valid_mnemonic).Generate(passphrase)
    coin_type = SUPPORTED_COINS[chain_name]

    bip44_mst = Bip44.FromSeed(seed_bytes, coin_type)
    bip44_acc = bip44_mst.Purpose().Coin().Account(0)
    bip44_chg = bip44_acc.Change(Bip44Changes.CHAIN_EXT)

    return [bip44_chg.AddressIndex(i).PublicKey().ToAddress() for i in range(count)]


# ---------------------------------------------------------------------------
# GUI Application
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Crypto Wallet Tool")
        self.geometry("800x600")
        self.minsize(700, 500)

        # Data storage
        self.generated_phrases = []
        self.derived_addresses = []

        # Main notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, padx=10, fill="both", expand=True)

        # Create tabs
        self.generator_frame = self._create_generator_tab(self.notebook)
        self.viewer_frame = self._create_viewer_tab(self.notebook)
        
        self.notebook.add(self.generator_frame, text='Mnemonic Generator')
        self.notebook.add(self.viewer_frame, text='Address Viewer')
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w', padding=5)
        status_bar.pack(side="bottom", fill="x")

    def _create_generator_tab(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        
        # --- Controls ---
        controls_frame = ttk.Frame(frame)
        controls_frame.grid(row=0, column=0, sticky="ew", pady=5)
        
        ttk.Label(controls_frame, text="Words per phrase:").pack(side='left', padx=(0, 5))
        self.gen_words_var = tk.IntVar(value=24)
        words_combo = ttk.Combobox(
            controls_frame,
            textvariable=self.gen_words_var,
            values=sorted(list(WORD_COUNTS)),
            state="readonly",
            width=5
        )
        words_combo.pack(side='left', padx=5)

        ttk.Label(controls_frame, text="Number of phrases:").pack(side='left', padx=(20, 5))
        self.gen_num_var = tk.IntVar(value=5)
        num_spinbox = tk.Spinbox(
            controls_frame, from_=1, to=100, width=5, textvariable=self.gen_num_var
        )
        num_spinbox.pack(side='left', padx=5)
        
        generate_btn = ttk.Button(controls_frame, text="Generate", command=self.run_generate_phrases)
        generate_btn.pack(side='left', padx=(20, 5))
        
        clear_btn = ttk.Button(controls_frame, text="Clear", command=self.clear_generator)
        clear_btn.pack(side='left', padx=5)

        self.save_phrases_btn = ttk.Button(controls_frame, text="Save Phrases...", command=self.save_phrases_to_file, state="disabled")
        self.save_phrases_btn.pack(side='left', padx=5)

        # --- Output Scrollable Frame ---
        gen_results_frame = ttk.LabelFrame(frame, text="Generated Phrases", padding=10)
        gen_results_frame.grid(row=1, column=0, sticky="nsew", pady=(10,0))
        gen_results_frame.columnconfigure(0, weight=1)
        gen_results_frame.rowconfigure(0, weight=1)

        self.gen_canvas = tk.Canvas(gen_results_frame, highlightthickness=0)
        vscroll = ttk.Scrollbar(gen_results_frame, orient="vertical", command=self.gen_canvas.yview)
        self.gen_inner_frame = ttk.Frame(self.gen_canvas)
        
        self.gen_inner_frame.bind("<Configure>", lambda e: self.gen_canvas.configure(scrollregion=self.gen_canvas.bbox("all")))
        self.gen_canvas.create_window((0,0), window=self.gen_inner_frame, anchor="nw")
        self.gen_canvas.configure(yscrollcommand=vscroll.set)
        
        self.gen_canvas.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")

        return frame

    def _create_viewer_tab(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(2, weight=1)

        # --- Input Frame ---
        self.input_frame = ttk.LabelFrame(frame, text="Inputs", padding=10)
        self.input_frame.grid(row=0, column=0, sticky="ew")
        self.input_frame.columnconfigure(0, weight=1)

        # Mnemonic row
        mnemonic_frame = ttk.Frame(self.input_frame)
        mnemonic_frame.grid(row=0, column=0, sticky="ew")
        mnemonic_frame.columnconfigure(0, weight=1)
        
        self.mnemonic_label_frame = ttk.Frame(mnemonic_frame)
        self.mnemonic_label_frame.pack(side="top", fill="x", expand=True)
        ttk.Label(self.mnemonic_label_frame, text="Mnemonic Phrase:").pack(side="left")
        
        self.unlock_button = ttk.Button(self.mnemonic_label_frame, text="Unlock to Edit", command=self.unlock_mnemonic_box, state="disabled")
        self.unlock_button.pack(side="right")

        self.viewer_mnemonic_text = tk.Text(mnemonic_frame, height=4, wrap=tk.WORD, font=("Segoe UI", 10), relief=tk.SOLID, borderwidth=1)
        self.viewer_mnemonic_text.pack(side="top", fill="x", expand=True, pady=(2,0))

        # Passphrase row
        passphrase_frame = ttk.Frame(self.input_frame)
        passphrase_frame.grid(row=1, column=0, sticky="ew", pady=(5,0))
        passphrase_frame.columnconfigure(0, weight=1)

        ttk.Label(passphrase_frame, text="Optional Passphrase (Password):").pack(side="top", anchor="w")
        self.passphrase_var = tk.StringVar()
        self.passphrase_entry = ttk.Entry(passphrase_frame, textvariable=self.passphrase_var, font=("Segoe UI", 10), show="*")
        self.passphrase_entry.pack(side="top", fill="x", expand=True)


        # --- Controls Bar ---
        bar = ttk.Frame(frame, padding=(0, 10))
        bar.grid(row=1, column=0, sticky="ew", pady=10)
        
        ttk.Button(bar, text="Get First Address (All Chains)", command=self.run_get_first_addresses).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(bar, text="Get Addresses", command=self.run_get_many_addresses).pack(side=tk.LEFT, padx=5)

        ttk.Separator(bar, orient='vertical').pack(side=tk.LEFT, padx=10, fill='y')

        ttk.Label(bar, text="Chain:").pack(side=tk.LEFT, padx=(5,2))
        self.viewer_chain_var = tk.StringVar(value="Ethereum (ETH)")
        chain_cmb = ttk.Combobox(bar, textvariable=self.viewer_chain_var, state="readonly", values=list(SUPPORTED_COINS.keys()), width=15)
        chain_cmb.pack(side=tk.LEFT)
        
        ttk.Label(bar, text="Count:").pack(side=tk.LEFT, padx=(10,2))
        self.viewer_count_var = tk.IntVar(value=10)
        count_spin = ttk.Spinbox(bar, from_=1, to=200, width=5, textvariable=self.viewer_count_var)
        count_spin.pack(side=tk.LEFT)

        self.save_addresses_btn = ttk.Button(bar, text="Save Addresses...", command=self.save_addresses_to_file, state="disabled")
        self.save_addresses_btn.pack(side=tk.RIGHT, padx=5)
        ttk.Button(bar, text="Clear All", command=self.clear_viewer).pack(side=tk.RIGHT, padx=5)


        # --- Results Area (Scrollable Frame) ---
        results_frame = ttk.LabelFrame(frame, text="Derived Addresses", padding=10)
        results_frame.grid(row=2, column=0, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.viewer_canvas = tk.Canvas(results_frame, highlightthickness=0)
        vscroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.viewer_canvas.yview)
        self.viewer_results_inner_frame = ttk.Frame(self.viewer_canvas)
        
        self.viewer_results_inner_frame.bind("<Configure>", lambda e: self.viewer_canvas.configure(scrollregion=self.viewer_canvas.bbox("all")))
        self.viewer_canvas.create_window((0,0), window=self.viewer_results_inner_frame, anchor="nw")
        self.viewer_canvas.configure(yscrollcommand=vscroll.set)
        
        self.viewer_canvas.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")

        return frame

    # --- GUI Actions ---
    
    def set_status(self, msg, is_error=False):
        """Updates the status bar and shows a messagebox on error."""
        self.status_var.set(msg)
        if is_error:
            messagebox.showerror("Error", msg)

    def _copy_to_clipboard(self, text):
        """Copies text to the system clipboard."""
        try:
            pyperclip.copy(text)
            self.set_status(f"Copied to clipboard: {text[:30]}...")
        except Exception as e:
            self.set_status(f"Clipboard error: {e}", is_error=True)

    def clear_generator(self):
        """Clears the output on the generator tab."""
        for widget in self.gen_inner_frame.winfo_children():
            widget.destroy()
        self.gen_canvas.yview_moveto(0)
        self.generated_phrases = []
        self.save_phrases_btn.config(state="disabled")
        self.set_status("Generator cleared.")

    def run_generate_phrases(self):
        """Generates mnemonic phrases based on GUI inputs."""
        self.clear_generator()
        try:
            num = self.gen_num_var.get()
            words = self.gen_words_var.get()
            if num < 1 or words not in WORD_COUNTS:
                raise ValueError("Invalid input.")
        except (ValueError, tk.TclError):
            self.set_status("Please enter valid numbers for generation.", is_error=True)
            return

        self.generated_phrases = [generate_mnemonic(words) for _ in range(num)]
        for i, phrase in enumerate(self.generated_phrases):
            self._add_generated_phrase_row(i, phrase)

        self.save_phrases_btn.config(state="normal")
        self.set_status(f"Generated {num} phrase(s) of {words} words each.")
    
    def _add_generated_phrase_row(self, index, phrase):
        """Adds a row for a single generated phrase with a 'Use' button."""
        row_frame = ttk.Frame(self.gen_inner_frame)
        row_frame.grid(row=index, column=0, sticky="ew", pady=4, padx=5)
        row_frame.columnconfigure(1, weight=1)

        ttk.Label(row_frame, text=f"{index+1}.").grid(row=0, column=0, padx=(0,5), sticky='n')
        
        phrase_text = tk.Text(row_frame, height=3, wrap="word", font=("Courier New", 10), relief="sunken", borderwidth=1)
        phrase_text.insert("1.0", phrase)
        phrase_text.config(state="disabled")
        phrase_text.grid(row=0, column=1, sticky="ew")

        use_btn = ttk.Button(row_frame, text="Use this Phrase", command=lambda p=phrase: self.send_to_viewer(p))
        use_btn.grid(row=0, column=2, padx=5)

    def send_to_viewer(self, phrase_to_use):
        """Sends the selected phrase to the viewer tab and locks the input box."""
        self.clear_viewer()
        self.viewer_mnemonic_text.config(state="normal")
        self.viewer_mnemonic_text.delete("1.0", tk.END)
        self.viewer_mnemonic_text.insert("1.0", phrase_to_use)
        self.viewer_mnemonic_text.config(state="disabled") # Lock the box
        self.unlock_button.config(state="normal") # Enable the unlock button
        self.set_status(f"Loaded phrase starting with '{phrase_to_use.split()[0]}' into viewer. Input is locked.")
        self.notebook.select(self.viewer_frame)
    
    def unlock_mnemonic_box(self):
        """Makes the mnemonic text box in the viewer editable."""
        self.viewer_mnemonic_text.config(state="normal")
        self.unlock_button.config(state="disabled")
        self.set_status("Mnemonic input unlocked for manual entry.")

    def _clear_viewer_results_view(self):
        """Clears the visual results list and resets the scrollbar."""
        for widget in self.viewer_results_inner_frame.winfo_children():
            widget.destroy()
        self.viewer_canvas.yview_moveto(0)
        self.derived_addresses = []
        self.save_addresses_btn.config(state="disabled")

    def clear_viewer(self):
        """Clears all inputs and results on the viewer tab."""
        self.unlock_mnemonic_box() # Ensure box is unlocked before clearing
        self.viewer_mnemonic_text.delete("1.0", tk.END)
        self.passphrase_var.set("")
        self._clear_viewer_results_view()
        self.set_status("Viewer cleared.")

    def _add_viewer_result_row(self, index, label, address):
        """Adds a single address result row to the viewer's scrollable frame."""
        row_frame = ttk.Frame(self.viewer_results_inner_frame)
        row_frame.grid(row=index, column=0, sticky="ew", pady=3, padx=5)
        row_frame.columnconfigure(1, weight=1)

        ttk.Label(row_frame, text=label, width=18, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=0)
        
        entry = ttk.Entry(row_frame, font=("Consolas", 10))
        entry.insert(0, address)
        entry.config(state="readonly")
        entry.grid(row=0, column=1, sticky="ew", padx=5)
        
        ttk.Button(row_frame, text="Copy", command=lambda a=address: self._copy_to_clipboard(a)).grid(row=0, column=2)

    def _update_address_results(self, addresses_data):
        """Clears and repopulates the address results view."""
        self._clear_viewer_results_view()
        self.derived_addresses = addresses_data
        for i, addr_info in enumerate(self.derived_addresses):
            self._add_viewer_result_row(i, addr_info["label"], addr_info["address"])
        if self.derived_addresses:
            self.save_addresses_btn.config(state="normal")
        self.set_status(f"Derived {len(self.derived_addresses)} address(es).")

    def run_get_first_addresses(self):
        """Derives the first address for all supported chains."""
        mnemonic = self.viewer_mnemonic_text.get("1.0", tk.END).strip()
        passphrase = self.passphrase_var.get()
        if not mnemonic:
            self.set_status("Mnemonic phrase cannot be empty.", is_error=True)
            return
        
        try:
            addresses = get_first_addresses(mnemonic, passphrase)
            addresses_data = [{"label": f"{chain} (0):", "address": addr} for chain, addr in addresses.items()]
            self._update_address_results(addresses_data)
        except ValueError as e:
            self.set_status(str(e), is_error=True)

    def run_get_many_addresses(self):
        """Derives a sequence of addresses for a selected chain."""
        mnemonic = self.viewer_mnemonic_text.get("1.0", tk.END).strip()
        passphrase = self.passphrase_var.get()
        chain = self.viewer_chain_var.get()
        try:
            count = self.viewer_count_var.get()
            if not 1 <= count <= 200:
                raise ValueError("Count must be between 1 and 200.")
        except (ValueError, tk.TclError):
            self.set_status("Invalid count. Must be an integer between 1 and 200.", is_error=True)
            return
        
        if not mnemonic:
            self.set_status("Mnemonic phrase cannot be empty.", is_error=True)
            return
        
        try:
            addresses = get_many_addresses(mnemonic, chain, count, passphrase)
            addresses_data = [{"label": f"{chain.split()[0]} ({i}):", "address": addr} for i, addr in enumerate(addresses)]
            self._update_address_results(addresses_data)
        except ValueError as e:
            self.set_status(str(e), is_error=True)

    def save_phrases_to_file(self):
        """Saves the generated phrases to a text or CSV file."""
        if not self.generated_phrases:
            self.set_status("No phrases to save.", is_error=True)
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save Phrases",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")]
        )
        if not file_path:
            return

        try:
            if file_path.lower().endswith(".csv"):
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["#", "Mnemonic Phrase"])
                    for i, phrase in enumerate(self.generated_phrases, 1):
                        writer.writerow([i, phrase])
            else:
                with open(file_path, "w", encoding="utf-8") as f:
                    for i, phrase in enumerate(self.generated_phrases, 1):
                        f.write(f"{i}. {phrase}\n")
            self.set_status(f"Saved phrases to {file_path}")
        except Exception as e:
            self.set_status(f"Failed to save file: {e}", is_error=True)

    def save_addresses_to_file(self):
        """Saves the derived addresses to a text or CSV file."""
        if not self.derived_addresses:
            self.set_status("No addresses to save.", is_error=True)
            return

        file_path = filedialog.asksaveasfilename(
            title="Save Addresses",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt")]
        )
        if not file_path:
            return

        try:
            if file_path.lower().endswith(".csv"):
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Label", "Address"])
                    for item in self.derived_addresses:
                        writer.writerow([item["label"], item["address"]])
            else:
                with open(file_path, "w", encoding="utf-8") as f:
                    for item in self.derived_addresses:
                        f.write(f"{item['label']:<25} {item['address']}\n")
            self.set_status(f"Saved addresses to {file_path}")
        except Exception as e:
            self.set_status(f"Failed to save file: {e}", is_error=True)


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = App()
    app.mainloop()
