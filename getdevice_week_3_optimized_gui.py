#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading
import sys
import os
from datetime import datetime

from getdevice_week_3_optimized import main, parse_args

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Device Scanner")
        self.scanning = False

        # IP Range
        tk.Label(root, text="IP Range:").grid(row=0, column=0, sticky="w")
        self.ip_entry = tk.Entry(root, width=40)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        # Options
        self.debug_var = tk.BooleanVar()
        self.cve_var = tk.BooleanVar()
        self.nointeractive_var = tk.BooleanVar()
        self.webbruteforce_var = tk.BooleanVar()
        self.csv_var = tk.BooleanVar()

        tk.Checkbutton(root, text="Debug logging", variable=self.debug_var).grid(row=1, column=0, sticky="w")
        tk.Checkbutton(root, text="CVE-only mode", variable=self.cve_var).grid(row=1, column=1, sticky="w")
        tk.Checkbutton(root, text="Non-interactive CVE scan", variable=self.nointeractive_var).grid(row=2, column=0, sticky="w")
        tk.Checkbutton(root, text="Web brute force", variable=self.webbruteforce_var).grid(row=2, column=1, sticky="w")
        tk.Checkbutton(root, text="Also generate CSV", variable=self.csv_var).grid(row=3, column=0, sticky="w")

        # Output directory selector
        tk.Label(root, text="Output Directory:").grid(row=4, column=0, sticky="w")
        self.output_dir = tk.Entry(root, width=40)
        self.output_dir.grid(row=4, column=1, padx=5)
        self.output_dir.insert(0, "results")  # Default to results directory
        tk.Button(root, text="Browse", command=self.browse_directory).grid(row=4, column=2)

        # Log area
        tk.Label(root, text="Log Output:").grid(row=5, column=0, sticky="w")
        self.log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
        self.log_area.grid(row=6, column=0, columnspan=3, padx=5, pady=5)

        # Status label
        self.status_label = tk.Label(root, text="JSON output will be automatically saved with timestamp", fg="blue")
        self.status_label.grid(row=7, column=0, columnspan=3, pady=5)

        # Buttons
        self.scan_button = tk.Button(root, text="Start Scan", command=self.toggle_scan)
        self.scan_button.grid(row=8, column=0, pady=10)
        tk.Button(root, text="Exit", command=root.quit).grid(row=8, column=1, pady=10)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.output_dir.delete(0, tk.END)
            self.output_dir.insert(0, directory)

    def toggle_scan(self):
        if self.scanning:
            self.stop_scan()
        else:
            self.start_scan()

    def start_scan(self):
        ip_range = self.ip_entry.get().strip()
        if not ip_range:
            messagebox.showerror("Error", "Please enter an IP range")
            return

        self.scanning = True
        self.scan_button.config(text="Scanning...", state="disabled")
        
        output_dir = self.output_dir.get().strip()
        if not output_dir:
            output_dir = "results"

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = os.path.join(output_dir, f"scan_{timestamp}.json")
        
        self.status_label.config(text=f"Scanning... Output: {json_file}", fg="orange")
        
        args = [ip_range]
        if self.debug_var.get():
            args.append("--debug")
        if self.cve_var.get():
            args.append("--cve-only")
        if self.nointeractive_var.get():
            args.append("--no-interactive")
        if self.webbruteforce_var.get():
            args.append("--web-bruteforce")
        if self.csv_var.get():
            args.append("--output-csv")

        self.scan_thread = threading.Thread(target=self.run_scan, args=(args, output_dir))
        self.scan_thread.start()

    def stop_scan(self):
        self.scanning = False
        self.scan_button.config(text="Start Scan", state="normal")
        self.status_label.config(text="Scan stopped by user", fg="red")

    def run_scan(self, args, output_dir):
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        old_cwd = os.getcwd()
        sys.stdout = self
        sys.stderr = self
        try:
            sys.argv = ["getdevice_week3_optimized.py"] + args
            main()
            if self.scanning:  # Only update if not stopped
                self.status_label.config(text="Scan completed successfully!", fg="green")
        except Exception as e:
            self.log_area.insert(tk.END, f"Error: {e}\n")
            if self.scanning:
                self.status_label.config(text=f"Scan failed: {e}", fg="red")
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            os.chdir(old_cwd)
            self.scanning = False
            self.scan_button.config(text="Start Scan", state="normal")

    def write(self, msg):
        self.log_area.insert(tk.END, msg)
        self.log_area.see(tk.END)

    def flush(self):
        pass  # required for file-like object

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()
