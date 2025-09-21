#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading
import sys
import os

from getdevice_week_3_optimized import main, parse_args

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Device Scanner")

        # IP Range
        tk.Label(root, text="IP Range:").grid(row=0, column=0, sticky="w")
        self.ip_entry = tk.Entry(root, width=40)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        # Options
        self.debug_var = tk.BooleanVar()
        self.cve_var = tk.BooleanVar()
        self.nointeractive_var = tk.BooleanVar()

        tk.Checkbutton(root, text="Debug logging", variable=self.debug_var).grid(row=1, column=0, sticky="w")
        tk.Checkbutton(root, text="CVE-only mode", variable=self.cve_var).grid(row=1, column=1, sticky="w")
        tk.Checkbutton(root, text="Non-interactive CVE scan", variable=self.nointeractive_var).grid(row=2, column=0, sticky="w")

        # Output file selectors
        tk.Label(root, text="JSON Output:").grid(row=3, column=0, sticky="w")
        self.json_path = tk.Entry(root, width=30)
        self.json_path.grid(row=3, column=1)
        tk.Button(root, text="Browse", command=self.browse_json).grid(row=3, column=2)

        tk.Label(root, text="CSV Output:").grid(row=4, column=0, sticky="w")
        self.csv_path = tk.Entry(root, width=30)
        self.csv_path.grid(row=4, column=1)
        tk.Button(root, text="Browse", command=self.browse_csv).grid(row=4, column=2)

        # Log area
        tk.Label(root, text="Log Output:").grid(row=5, column=0, sticky="w")
        self.log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
        self.log_area.grid(row=6, column=0, columnspan=3, padx=5, pady=5)

        # Buttons
        tk.Button(root, text="Start Scan", command=self.start_scan).grid(row=7, column=0, pady=10)
        tk.Button(root, text="Exit", command=root.quit).grid(row=7, column=1, pady=10)

    def browse_json(self):
        file = filedialog.asksaveasfilename(defaultextension=".json")
        if file:
            self.json_path.delete(0, tk.END)
            self.json_path.insert(0, file)

    def browse_csv(self):
        file = filedialog.asksaveasfilename(defaultextension=".csv")
        if file:
            self.csv_path.delete(0, tk.END)
            self.csv_path.insert(0, file)

    def start_scan(self):
        ip_range = self.ip_entry.get().strip()
        if not ip_range:
            messagebox.showerror("Error", "Please enter an IP range")
            return

        args = [
            ip_range,
        ]
        if self.debug_var.get():
            args.append("--debug")
        if self.cve_var.get():
            args.append("--cve-only")
        if self.nointeractive_var.get():
            args.append("--no-interactive")
        if self.json_path.get():
            args.extend(["--output-json", self.json_path.get()])
        if self.csv_path.get():
            args.extend(["--output-csv", self.csv_path.get()])

        # Run in background thread
        thread = threading.Thread(target=self.run_scan, args=(args,))
        thread.start()

    def run_scan(self, args):
        # Redirect stdout/stderr to GUI
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self
        try:
            sys.argv = ["getdevice_week3_optimized.py"] + args
            main()
        except Exception as e:
            self.log_area.insert(tk.END, f"Error: {e}\n")
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def write(self, msg):
        self.log_area.insert(tk.END, msg)
        self.log_area.see(tk.END)

    def flush(self):
        pass  # required for file-like object

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()
