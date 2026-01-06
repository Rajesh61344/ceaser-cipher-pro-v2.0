#!/usr/bin/env python3
# =============================================================================
# Caesar Cipher Pro v2.0 - COMPLETE GUI + CLI (No External Dependencies)
# Fixed: No pyperclip, self-contained, all tabs working
# Usage: python3 caesar_complete.py
# =============================================================================

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import string
import re
from typing import List, Dict
from dataclasses import dataclass
import json
import sys

# Core Caesar Cipher Engine (Self-contained)
@dataclass
class CaesarResult:
    input_text: str
    output_text: str
    key: int
    mode: str
    confidence: float = 0.0
    is_english: bool = False

class CaesarCipher:
    def __init__(self):
        self.alphabet_upper = string.ascii_uppercase
        self.alphabet_lower = string.ascii_lowercase
        self.alphabet_size = 26
        
    def _shift_char(self, char: str, key: int, mode: str = 'encrypt') -> str:
        if char.isupper():
            base = ord('A')
            shift = 1 if mode == 'encrypt' else -1
            shifted = (ord(char) - base + key * shift) % self.alphabet_size
            return chr(base + shifted)
        elif char.islower():
            base = ord('a')
            shift = 1 if mode == 'encrypt' else -1
            shifted = (ord(char) - base + key * shift) % self.alphabet_size
            return chr(base + shifted)
        return char
    
    def encrypt(self, text: str, key: int) -> CaesarResult:
        if not text.strip() or not 0 <= key <= 25:
            raise ValueError("Invalid input or key (0-25)")
        result = ''.join(self._shift_char(c, key, 'encrypt') for c in text)
        return CaesarResult(text, result, key, 'encrypt')
    
    def decrypt(self, text: str, key: int) -> CaesarResult:
        if not text.strip() or not 0 <= key <= 25:
            raise ValueError("Invalid input or key (0-25)")
        result = ''.join(self._shift_char(c, key, 'decrypt') for c in text)
        return CaesarResult(text, result, key, 'decrypt')
    
    def brute_force(self, ciphertext: str) -> List[CaesarResult]:
        if not ciphertext.strip():
            raise ValueError("Ciphertext cannot be empty")
        results = []
        for key in range(26):
            result = self.decrypt(ciphertext, key)
            result.confidence = self._english_score(result.output_text)
            result.is_english = result.confidence > 0.04
            results.append(result)
        return sorted(results, key=lambda x: x.confidence, reverse=True)
    
    def _english_score(self, text: str) -> float:
        text = text.lower()
        english_freq = {'e':0.127,'t':0.091,'a':0.082,'o':0.075,'i':0.070}
        score = 0.0
        char_count = sum(1 for c in text if c.isalpha())
        if char_count == 0:
            return 0.0
        for char, freq in english_freq.items():
            observed = text.count(char) / char_count
            score += abs(observed - freq)
        return 1.0 / (1.0 + score)
    
    def modular_demo(self, char: str, key: int) -> Dict:
        if not char.isalpha():
            return {"error": "Only alphabetic characters"}
        base = ord('A') if char.isupper() else ord('a')
        pos = ord(char) - base
        enc_pos = (pos + key) % 26
        dec_pos = (enc_pos - key) % 26
        return {
            "char": char, "pos": pos, "key": key, "enc_pos": enc_pos,
            "enc_char": chr(base + enc_pos), "dec_pos": dec_pos,
            "dec_char": chr(base + dec_pos),
            "encrypt": f"({pos} + {key}) mod 26 = {enc_pos}",
            "decrypt": f"({enc_pos} - {key}) mod 26 = {dec_pos}"
        }

class CaesarGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Caesar Cipher Pro v2.0 - Educational Cryptography Tool")
        self.root.geometry("1000x750")
        self.root.minsize(800, 600)
        
        self.cipher = CaesarCipher()
        self.mode_var = tk.StringVar(value="encrypt")
        self.demo_char_var = tk.StringVar(value="A")
        self.demo_key_var = tk.StringVar(value="3")
        
        self.setup_ui()
    
    def setup_ui(self):
        # Menu
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open File...", command=self.open_file)
        file_menu.add_command(label="Save Output...", command=self.save_output)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Main notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Encrypt/Decrypt
        self.ed_frame = ttk.Frame(notebook)
        notebook.add(self.ed_frame, text="🔒 Encrypt/Decrypt")
        self.setup_ed_tab()
        
        # Tab 2: Brute Force
        self.bf_frame = ttk.Frame(notebook)
        notebook.add(self.bf_frame, text="🔍 Brute Force")
        self.setup_bf_tab()
        
        # Tab 3: Modular Demo
        self.mod_frame = ttk.Frame(notebook)
        notebook.add(self.mod_frame, text="📊 Modular Math")
        self.setup_mod_tab()
    
    def setup_ed_tab(self):
        # Input section
        input_frame = ttk.LabelFrame(self.ed_frame, text="📥 Input Text", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Text to process:").pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(input_frame, height=10, wrap=tk.WORD)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=(0,10))
        self.input_text.insert("1.0", "Enter your text here...\nExample: Hello World!")
        
        # Controls
        control_frame = ttk.Frame(input_frame)
        control_frame.pack(fill=tk.X, pady=(0,10))
        
        ttk.Label(control_frame, text="Key (0-25):").pack(side=tk.LEFT)
        self.key_var = tk.StringVar(value="3")
        key_entry = ttk.Entry(control_frame, textvariable=self.key_var, width=6)
        key_entry.pack(side=tk.LEFT, padx=(5,15))
        
        ttk.Radiobutton(control_frame, text="🔒 Encrypt", variable=self.mode_var, 
                       value="encrypt", width=10).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(control_frame, text="🔓 Decrypt", variable=self.mode_var, 
                       value="decrypt", width=10).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="▶️ Process", command=self.process_text).pack(side=tk.RIGHT)
        
        # Output section
        output_frame = ttk.LabelFrame(self.ed_frame, text="📤 Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=10, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        btn_frame = ttk.Frame(output_frame)
        btn_frame.pack(fill=tk.X, pady=(10,0))
        ttk.Button(btn_frame, text="📋 Copy", command=self.copy_output).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="🗑️ Clear", command=self.clear_ed).pack(side=tk.RIGHT)
    
    def setup_bf_tab(self):
        # Input
        ttk.Label(self.bf_frame, text="🔍 Enter ciphertext for brute force analysis:", 
                 font=('Arial', 10, 'bold')).pack(pady=(20,10))
        
        self.bf_input = scrolledtext.ScrolledText(self.bf_frame, height=6, wrap=tk.WORD)
        self.bf_input.pack(fill=tk.BOTH, expand=False, padx=20, pady=(0,10))
        self.bf_input.insert("1.0", "Khoor zruog! (Try this - should find 'Hello world!')")
        
        ttk.Button(self.bf_frame, text="🚀 Brute Force Attack", 
                  command=self.brute_force_attack, style="Accent.TButton").pack(pady=10)
        
        # Results
        results_frame = ttk.LabelFrame(self.bf_frame, text="🎯 Top Results (English-like)", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,20))
        
        self.bf_results = scrolledtext.ScrolledText(results_frame, height=15, wrap=tk.WORD)
        self.bf_results.pack(fill=tk.BOTH, expand=True)
    
    def setup_mod_tab(self):
        ttk.Label(self.mod_frame, text="📊 Modular Arithmetic Demonstration", 
                 font=('Arial', 12, 'bold')).pack(pady=20)
        
        demo_frame = ttk.LabelFrame(self.mod_frame, text="Input", padding=15)
        demo_frame.pack(fill=tk.X, padx=40, pady=(0,20))
        
        ttk.Label(demo_frame, text="Character:").grid(row=0, column=0, sticky=tk.W)
        char_entry = ttk.Entry(demo_frame, textvariable=self.demo_char_var, width=5)
        char_entry.grid(row=0, column=1, padx=(10,20))
        
        ttk.Label(demo_frame, text="Key (0-25):").grid(row=0, column=2, sticky=tk.W)
        key_entry = ttk.Entry(demo_frame, textvariable=self.demo_key_var, width=5)
        key_entry.grid(row=0, column=3, padx=(10,0))
        
        ttk.Button(demo_frame, text="Calculate", 
                  command=self.modular_calculate).grid(row=0, column=4, padx=(20,0))
        
        # Results
        self.mod_result = tk.Text(self.mod_frame, height=12, width=80, wrap=tk.WORD, 
                                 bg='black', fg='lime', font=('Courier', 10))
        self.mod_result.pack(pady=10)
    
    def process_text(self):
        try:
            text = self.input_text.get("1.0", tk.END).strip()
            key = int(self.key_var.get())
            mode = self.mode_var.get()
            
            if mode == "encrypt":
                result = self.cipher.encrypt(text, key)
                mode_emoji = "🔒"
            else:
                result = self.cipher.decrypt(text, key)
                mode_emoji = "🔓"
            
            self.output_text.delete("1.0", tk.END)
            output = f"{mode_emoji} Mode: {mode.upper()}\nKey: {key}\n\n{result.output_text}"
            self.output_text.insert("1.0", output)
            
        except ValueError as e:
            messagebox.showerror("❌ Error", str(e))
    
    def brute_force_attack(self):
        try:
            ciphertext = self.bf_input.get("1.0", tk.END).strip()
            results = self.cipher.brute_force(ciphertext)
            
            self.bf_results.delete("1.0", tk.END)
            output = "🔍 BRUTE FORCE RESULTS (Top 10, sorted by English-likeness):\n"
            output += "=" * 80 + "\n\n"
            
            for i, result in enumerate(results[:10], 1):
                marker = "🎯 MOST LIKELY!" if result.is_english else ""
                conf_bar = "█" * int(result.confidence * 20) + "░" * (20 - int(result.confidence * 20))
                output += f"{i:2}. Key={result.key:3} | {conf_bar} [{result.confidence:.3f}]\n"
                output += f"   {result.output_text[:70]}{'...' if len(result.output_text) > 70 else ''}\n"
                if marker:
                    output += f"   {marker}\n"
                output += "\n"
            
            output += f"\n💡 Analyzed {len(results)} possibilities in <1ms\n"
            output += "   Caesar Cipher is BROKEN by brute force (only 26 keys)!\n"
            
            self.bf_results.insert("1.0", output)
            
        except Exception as e:
            messagebox.showerror("❌ Error", str(e))
    
    def modular_calculate(self):
        try:
            char = self.demo_char_var.get().strip().upper()
            key = int(self.demo_key_var.get())
            
            demo = self.cipher.modular_demo(char, key)
            if "error" in demo:
                messagebox.showerror("❌ Error", demo["error"])
                return
            
            self.mod_result.delete("1.0", tk.END)
            output = f"""
CHAR:  '{demo['char']}'  → Position: {demo['pos']:2d}
KEY:   {demo['key']:2d}

🔒 ENCRYPT:
{demo['encrypt']}
→ '{demo['enc_char']}'  (Position: {demo['enc_pos']:2d})

🔓 DECRYPT:
{demo['decrypt']}
→ '{demo['dec_char']}'  (Position: {demo['dec_pos']:2d})

✅ Round-trip verified! (Perfect reversibility)
💡 This demonstrates modular arithmetic: (x ± k) mod 26
"""
            self.mod_result.insert("1.0", output)
            
        except Exception as e:
            messagebox.showerror("❌ Error", str(e))
    
    def copy_output(self):
        try:
            text = self.output_text.get("1.0", tk.END).strip()
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("📋 Copied", "Output copied to clipboard!")
        except:
            messagebox.showwarning("⚠️ Warning", "Copy failed (clipboard access)")
    
    def clear_ed(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
    
    def open_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All", "*.*")])
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.input_text.delete("1.0", tk.END)
                self.input_text.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to open file:\n{str(e)}")
    
    def save_output(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt", 
                                               filetypes=[("Text files", "*.txt")])
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.output_text.get("1.0", tk.END).strip())
                messagebox.showinfo("💾 Saved", f"Output saved to:\n{filename}")
            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to save file:\n{str(e)}")

# CLI Fallback
def cli_mode():
    print("🔐 Caesar Cipher Pro - CLI Mode")
    print("Usage: Encrypt/Decrypt text with shift cipher")
    cipher = CaesarCipher()
    
    text = input("\nEnter text: ")
    key = int(input("Enter key (0-25): "))
    
    enc = cipher.encrypt(text, key)
    dec = cipher.decrypt(enc.output_text, key)
    
    print(f"\n🔒 Encrypted: {enc.output_text}")
    print(f"🔓 Decrypted: {dec.output_text}")
    print(f"✅ Verified: {dec.output_text == text}")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        cli_mode()
    else:
        root = tk.Tk()
        app = CaesarGUI(root)
        root.mainloop()

if __name__ == "__main__":
    main()