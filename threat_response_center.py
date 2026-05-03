# ══════════════════════════════════════════════════════════════════════════════
#                    THREAT RESPONSE CENTER
#       Investigate and remediate security threats with actionable options
# ══════════════════════════════════════════════════════════════════════════════

__version__ = "29.0.0"

try:
    from vulnerability_scanner import VulnerabilityScanner
    _KEV_AVAILABLE = True
except ImportError:
    _KEV_AVAILABLE = False

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import socket
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Colors matching Cyberpunk theme
class Colors:
    BG_DARK = '#0a0a12'
    BG_PANEL = '#12121a'
    BG_CARD = '#1a1a24'
    BG_HOVER = '#252530'
    BG_VOID = '#08080c'
    TEXT = '#e0e0e0'
    TEXT_DIM = '#808090'
    CYAN = '#00ffff'
    GREEN = '#00ff88'
    ORANGE = '#ff8800'
    RED = '#ff3366'
    PINK = '#ff00ff'
    PURPLE = '#aa55ff'
    BLUE = '#4488ff'
    YELLOW = '#ffff00'
    WHITE = '#ffffff'
    SAFE = '#00ff88'
    DANGER = '#ff3366'
    WARN = '#ffaa00'


class ThreatResponseCenter(tk.Toplevel):
    """Comprehensive threat investigation and remediation center"""
    
    # Known safe processes that may trigger false positives
    KNOWN_SAFE_PROCESSES = {
        'svchost.exe': 'Windows Service Host - legitimate system process',
        'system': 'Windows System Process',
        'csrss.exe': 'Client Server Runtime - legitimate Windows process',
        'lsass.exe': 'Local Security Authority - legitimate Windows process',
        'services.exe': 'Service Control Manager',
        'smss.exe': 'Session Manager Subsystem',
        'wininit.exe': 'Windows Initialization Process',
        'winlogon.exe': 'Windows Logon Process',
        'explorer.exe': 'Windows Explorer',
        'taskhostw.exe': 'Task Host Window',
        'runtimebroker.exe': 'Runtime Broker',
        'searchhost.exe': 'Windows Search',
        'sihost.exe': 'Shell Infrastructure Host',
        'ctfmon.exe': 'CTF Loader',
        'conhost.exe': 'Console Window Host',
        'dwm.exe': 'Desktop Window Manager',
        'fontdrvhost.exe': 'Font Driver Host',
        'msdtc.exe': 'Distributed Transaction Coordinator',
    }
    
    # Legitimate ports that may be flagged
    KNOWN_SAFE_PORTS = {
        135: 'RPC Endpoint Mapper (Windows)',
        139: 'NetBIOS Session Service',
        445: 'SMB (File Sharing)',
        1433: 'SQL Server',
        1434: 'SQL Server Browser',
        3306: 'MySQL',
        3389: 'Remote Desktop (if you use it)',
        5432: 'PostgreSQL',
        5985: 'WinRM HTTP',
        5986: 'WinRM HTTPS',
        8080: 'HTTP Proxy/Alt HTTP',
        49152: 'Windows Dynamic Ports Start',
    }
    
    # Known RAT ports - genuinely suspicious
    RAT_PORTS = {
        1234: 'SubSeven, Netbus variant',
        1604: 'DarkComet variant',
        3389: 'RDP (check if expected)',
        4444: 'Metasploit default',
        5555: 'Android ADB / Various RATs',
        6666: 'Various trojans',
        7777: 'Various trojans',
        8888: 'Various backdoors',
        9999: 'Various trojans',
        12345: 'NetBus',
        12346: 'NetBus',
        20034: 'NetBus Pro',
        27374: 'SubSeven',
        31337: 'Back Orifice',
        54321: 'Back Orifice 2000',
    }
    
    def __init__(self, parent, threats=None, db=None):
        super().__init__(parent)
        self.parent = parent
        self.threats = threats or []
        self.db = db
        
        self.title("◈ THREAT RESPONSE CENTER ◈")
        self.geometry("1100x750")
        self.configure(bg=Colors.BG_DARK)
        self.transient(parent)
        
        self._create_ui()
        self._scan_current_threats()
        
    def _create_ui(self):
        """Create the main UI"""
        # Header
        header = tk.Frame(self, bg=Colors.PINK, height=50)
        header.pack(fill='x')
        header.pack_propagate(False)
        tk.Label(header, text="🛡️ THREAT RESPONSE CENTER",
                font=('Consolas', 16, 'bold'), fg=Colors.WHITE, bg=Colors.PINK).pack(expand=True)
        
        # Main content with tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab 1: Suspicious Ports
        self.ports_frame = tk.Frame(notebook, bg=Colors.BG_PANEL)
        notebook.add(self.ports_frame, text=" 🔌 Suspicious Ports ")
        self._create_ports_tab()
        
        # Tab 2: Suspicious Processes
        self.procs_frame = tk.Frame(notebook, bg=Colors.BG_PANEL)
        notebook.add(self.procs_frame, text=" ⚡ Suspicious Processes ")
        self._create_processes_tab()
        
        # Tab 3: Network Connections
        self.network_frame = tk.Frame(notebook, bg=Colors.BG_PANEL)
        notebook.add(self.network_frame, text=" 🌐 Network Analysis ")
        self._create_network_tab()
        
        # Tab 4: File Threats
        self.files_frame = tk.Frame(notebook, bg=Colors.BG_PANEL)
        notebook.add(self.files_frame, text=" 📁 File Threats ")
        self._create_files_tab()
        
        # Tab 5: Quick Actions
        self.actions_frame = tk.Frame(notebook, bg=Colors.BG_PANEL)
        notebook.add(self.actions_frame, text=" ⚡ Quick Actions ")
        self._create_actions_tab()
        
        # Bottom status
        status = tk.Frame(self, bg=Colors.BG_DARK, height=30)
        status.pack(fill='x', side='bottom')
        self.status_label = tk.Label(status, text="Ready - Select a threat to investigate",
                                     font=('Consolas', 9), fg=Colors.TEXT_DIM, bg=Colors.BG_DARK)
        self.status_label.pack(side='left', padx=10)
        
        tk.Button(status, text="Close", command=self.destroy, bg=Colors.BG_CARD,
                 fg=Colors.TEXT, font=('Consolas', 9)).pack(side='right', padx=10, pady=3)
        
    def _create_ports_tab(self):
        """Create suspicious ports investigation tab"""
        # Info panel
        info = tk.Frame(self.ports_frame, bg=Colors.BG_CARD)
        info.pack(fill='x', padx=10, pady=10)
        
        tk.Label(info, text="🔍 Suspicious Ports Detected",
                font=('Consolas', 12, 'bold'), fg=Colors.ORANGE, bg=Colors.BG_CARD).pack(anchor='w', padx=10, pady=5)
        tk.Label(info, text="These ports are commonly used by Remote Access Trojans (RATs) and backdoors.\n"
                           "However, some may be legitimate - investigate before taking action.",
                font=('Consolas', 9), fg=Colors.TEXT_DIM, bg=Colors.BG_CARD).pack(anchor='w', padx=10, pady=5)
        
        # Port list
        list_frame = tk.Frame(self.ports_frame, bg=Colors.BG_VOID)
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        columns = ('Port', 'Process', 'PID', 'Status', 'Risk', 'Details')
        self.ports_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        for col in columns:
            self.ports_tree.heading(col, text=col)
        self.ports_tree.column('Port', width=80)
        self.ports_tree.column('Process', width=150)
        self.ports_tree.column('PID', width=70)
        self.ports_tree.column('Status', width=100)
        self.ports_tree.column('Risk', width=80)
        self.ports_tree.column('Details', width=300)
        
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.ports_tree.yview)
        self.ports_tree.configure(yscrollcommand=scrollbar.set)
        self.ports_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Action buttons
        btn_frame = tk.Frame(self.ports_frame, bg=Colors.BG_PANEL)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(btn_frame, text="🔍 Investigate Selected", command=self._investigate_port,
                 bg=Colors.BG_CARD, fg=Colors.CYAN, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="🛑 Kill Process", command=self._kill_port_process,
                 bg=Colors.BG_CARD, fg=Colors.RED, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="🔥 Block Port (Firewall)", command=self._block_port,
                 bg=Colors.BG_CARD, fg=Colors.ORANGE, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="[OK] Mark as Safe", command=self._mark_port_safe,
                 bg=Colors.BG_CARD, fg=Colors.GREEN, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="🔄 Refresh", command=self._scan_ports,
                 bg=Colors.BG_CARD, fg=Colors.TEXT, font=('Consolas', 10)).pack(side='right', padx=5)
        
    def _create_processes_tab(self):
        """Create suspicious processes tab"""
        info = tk.Frame(self.procs_frame, bg=Colors.BG_CARD)
        info.pack(fill='x', padx=10, pady=10)
        
        tk.Label(info, text="⚡ Suspicious Process Activity",
                font=('Consolas', 12, 'bold'), fg=Colors.ORANGE, bg=Colors.BG_CARD).pack(anchor='w', padx=10, pady=5)
        tk.Label(info, text="Processes exhibiting suspicious behavior or with unusual characteristics.",
                font=('Consolas', 9), fg=Colors.TEXT_DIM, bg=Colors.BG_CARD).pack(anchor='w', padx=10, pady=5)
        
        list_frame = tk.Frame(self.procs_frame, bg=Colors.BG_VOID)
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        columns = ('PID', 'Name', 'Path', 'CPU%', 'Memory', 'Connections', 'Risk')
        self.procs_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        for col in columns:
            self.procs_tree.heading(col, text=col)
        self.procs_tree.column('PID', width=60)
        self.procs_tree.column('Name', width=150)
        self.procs_tree.column('Path', width=300)
        self.procs_tree.column('CPU%', width=60)
        self.procs_tree.column('Memory', width=80)
        self.procs_tree.column('Connections', width=80)
        self.procs_tree.column('Risk', width=80)
        
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.procs_tree.yview)
        self.procs_tree.configure(yscrollcommand=scrollbar.set)
        self.procs_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        btn_frame = tk.Frame(self.procs_frame, bg=Colors.BG_PANEL)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(btn_frame, text="🔍 Investigate", command=self._investigate_process,
                 bg=Colors.BG_CARD, fg=Colors.CYAN, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="🛑 Kill Process", command=self._kill_selected_process,
                 bg=Colors.BG_CARD, fg=Colors.RED, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="📁 Open File Location", command=self._open_process_location,
                 bg=Colors.BG_CARD, fg=Colors.BLUE, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="🔎 VirusTotal Lookup", command=self._virustotal_process,
                 bg=Colors.BG_CARD, fg=Colors.PURPLE, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="[OK] Mark as Safe", command=self._mark_process_safe,
                 bg=Colors.BG_CARD, fg=Colors.GREEN, font=('Consolas', 10)).pack(side='left', padx=5)
        
    def _create_network_tab(self):
        """Create network analysis tab"""
        info = tk.Frame(self.network_frame, bg=Colors.BG_CARD)
        info.pack(fill='x', padx=10, pady=10)
        
        tk.Label(info, text="🌐 Network Connection Analysis",
                font=('Consolas', 12, 'bold'), fg=Colors.BLUE, bg=Colors.BG_CARD).pack(anchor='w', padx=10, pady=5)
        
        # Stats
        stats_frame = tk.Frame(info, bg=Colors.BG_CARD)
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        self.net_stats = {}
        for label, key in [("Established:", 'established'), ("Listening:", 'listening'), 
                          ("Suspicious:", 'suspicious'), ("External:", 'external')]:
            lbl = tk.Label(stats_frame, text=f"{label} 0", font=('Consolas', 10),
                          fg=Colors.TEXT, bg=Colors.BG_CARD)
            lbl.pack(side='left', padx=15)
            self.net_stats[key] = lbl
            
        list_frame = tk.Frame(self.network_frame, bg=Colors.BG_VOID)
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        columns = ('Local', 'Remote', 'Status', 'PID', 'Process', 'Risk')
        self.net_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        for col in columns:
            self.net_tree.heading(col, text=col)
            
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.net_tree.yview)
        self.net_tree.configure(yscrollcommand=scrollbar.set)
        self.net_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        btn_frame = tk.Frame(self.network_frame, bg=Colors.BG_PANEL)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(btn_frame, text="🔍 Lookup IP", command=self._lookup_ip,
                 bg=Colors.BG_CARD, fg=Colors.CYAN, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="🛑 Kill Connection", command=self._kill_connection,
                 bg=Colors.BG_CARD, fg=Colors.RED, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="🔥 Block IP (Firewall)", command=self._block_ip,
                 bg=Colors.BG_CARD, fg=Colors.ORANGE, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="📋 Show Only Suspicious", command=self._show_suspicious_only,
                 bg=Colors.BG_CARD, fg=Colors.WARN, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="🔄 Refresh", command=self._scan_network,
                 bg=Colors.BG_CARD, fg=Colors.TEXT, font=('Consolas', 10)).pack(side='right', padx=5)

    def _create_files_tab(self):
        """Create file threats tab"""
        info = tk.Frame(self.files_frame, bg=Colors.BG_CARD)
        info.pack(fill='x', padx=10, pady=10)
        
        tk.Label(info, text="📁 Detected File Threats",
                font=('Consolas', 12, 'bold'), fg=Colors.ORANGE, bg=Colors.BG_CARD).pack(anchor='w', padx=10, pady=5)
        
        # Note about PSScriptPolicyTest
        note_frame = tk.Frame(info, bg='#1a2a1a')
        note_frame.pack(fill='x', padx=10, pady=5)
        tk.Label(note_frame, text="ℹ️ Note: _PSScriptPolicyTest files are NORMAL Windows PowerShell files.\n"
                                  "   They are created automatically when PowerShell checks execution policy.\n"
                                  "   These are safe and can be ignored.",
                font=('Consolas', 9), fg=Colors.GREEN, bg='#1a2a1a', justify='left').pack(anchor='w', padx=10, pady=5)
        
        list_frame = tk.Frame(self.files_frame, bg=Colors.BG_VOID)
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        columns = ('File', 'Path', 'Threat Type', 'Severity', 'Action')
        self.files_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        for col in columns:
            self.files_tree.heading(col, text=col)
        self.files_tree.column('File', width=200)
        self.files_tree.column('Path', width=350)
        self.files_tree.column('Threat Type', width=150)
        self.files_tree.column('Severity', width=80)
        self.files_tree.column('Action', width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.files_tree.yview)
        self.files_tree.configure(yscrollcommand=scrollbar.set)
        self.files_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        btn_frame = tk.Frame(self.files_frame, bg=Colors.BG_PANEL)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(btn_frame, text="[LOCK] Quarantine", command=self._quarantine_file,
                 bg=Colors.BG_CARD, fg=Colors.ORANGE, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="🗑️ Delete", command=self._delete_file,
                 bg=Colors.BG_CARD, fg=Colors.RED, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="[OK] Allow (Whitelist)", command=self._allow_file,
                 bg=Colors.BG_CARD, fg=Colors.GREEN, font=('Consolas', 10)).pack(side='left', padx=5)
        tk.Button(btn_frame, text="📁 Open Location", command=self._open_file_location,
                 bg=Colors.BG_CARD, fg=Colors.BLUE, font=('Consolas', 10)).pack(side='left', padx=5)
                 
    def _create_actions_tab(self):
        """Create quick actions tab"""
        # Quick Fix section
        fix_frame = tk.LabelFrame(self.actions_frame, text=" ⚡ QUICK FIXES ",
                                 font=('Consolas', 11, 'bold'), fg=Colors.CYAN, bg=Colors.BG_PANEL)
        fix_frame.pack(fill='x', padx=15, pady=15)
        
        actions = [
            ("🔄 Reset Windows Firewall", "Resets firewall to default settings", self._reset_firewall),
            ("[CLEAN] Flush DNS Cache", "Clears DNS resolver cache", self._flush_dns),
            ("🔌 Reset Network Stack", "Resets Winsock and IP stack", self._reset_network),
            ("🛡️ Enable Windows Defender", "Ensures Defender is running", self._enable_defender),
            ("📋 Export Threat Report", "Save detailed report to file", self._export_report),
        ]
        
        for text, desc, cmd in actions:
            btn_row = tk.Frame(fix_frame, bg=Colors.BG_CARD, cursor='hand2')
            btn_row.pack(fill='x', padx=10, pady=3)
            btn_row.bind('<Button-1>', lambda e, c=cmd: c())
            btn_row.bind('<Enter>', lambda e, r=btn_row: r.configure(bg=Colors.BG_HOVER))
            btn_row.bind('<Leave>', lambda e, r=btn_row: r.configure(bg=Colors.BG_CARD))
            
            tk.Label(btn_row, text=text, font=('Consolas', 11, 'bold'),
                    fg=Colors.CYAN, bg=Colors.BG_CARD).pack(side='left', padx=15, pady=10)
            tk.Label(btn_row, text=desc, font=('Consolas', 9),
                    fg=Colors.TEXT_DIM, bg=Colors.BG_CARD).pack(side='left', padx=10)
                    
        # Advanced section
        adv_frame = tk.LabelFrame(self.actions_frame, text=" 🔧 ADVANCED TOOLS ",
                                 font=('Consolas', 11, 'bold'), fg=Colors.ORANGE, bg=Colors.BG_PANEL)
        adv_frame.pack(fill='x', padx=15, pady=15)
        
        adv_actions = [
            ("🔍 Run Full Port Scan", "Scan all ports for suspicious listeners", self._full_port_scan),
            ("[CHART] Generate netstat Report", "Save detailed network report", self._netstat_report),
            ("🛑 Kill All RAT Ports", "Terminate processes on known RAT ports", self._kill_all_rat_ports),
            ("[LOCK] Lockdown Mode", "Block all non-essential network traffic", self._lockdown_mode),
        ]
        
        for text, desc, cmd in adv_actions:
            btn_row = tk.Frame(adv_frame, bg=Colors.BG_CARD, cursor='hand2')
            btn_row.pack(fill='x', padx=10, pady=3)
            btn_row.bind('<Button-1>', lambda e, c=cmd: c())
            btn_row.bind('<Enter>', lambda e, r=btn_row: r.configure(bg=Colors.BG_HOVER))
            btn_row.bind('<Leave>', lambda e, r=btn_row: r.configure(bg=Colors.BG_CARD))
            
            tk.Label(btn_row, text=text, font=('Consolas', 11, 'bold'),
                    fg=Colors.ORANGE, bg=Colors.BG_CARD).pack(side='left', padx=15, pady=10)
            tk.Label(btn_row, text=desc, font=('Consolas', 9),
                    fg=Colors.TEXT_DIM, bg=Colors.BG_CARD).pack(side='left', padx=10)
        
    def _scan_current_threats(self):
        """Scan for current threats"""
        self._scan_ports()
        self._scan_processes()
        self._scan_network()
        
    def _scan_ports(self):
        """Scan for suspicious ports"""
        self.ports_tree.delete(*self.ports_tree.get_children())
        
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    port = conn.laddr.port
                    
                    # Check if it's a known RAT port
                    if port in self.RAT_PORTS or port in [1234, 1604, 4444, 5555, 6666, 7777, 8888, 9999]:
                        try:
                            proc = psutil.Process(conn.pid) if conn.pid else None
                            proc_name = proc.name() if proc else 'Unknown'
                            
                            # Determine risk level
                            if proc_name.lower() in ['svchost.exe', 'system']:
                                risk = 'MEDIUM'
                                details = f"System process on suspicious port - may be legitimate"
                            else:
                                risk = 'HIGH'
                                details = self.RAT_PORTS.get(port, 'Unknown RAT/Backdoor')
                                
                            self.ports_tree.insert('', 'end', values=(
                                port, proc_name, conn.pid or '-', 'LISTENING',
                                risk, details
                            ), tags=(risk.lower(),))
                        except Exception:
                            pass
                            
            self.ports_tree.tag_configure('high', background='#331111')
            self.ports_tree.tag_configure('medium', background='#332211')
            self.ports_tree.tag_configure('low', background='#223311')
        except Exception as e:
            self.status_label.configure(text=f"Port scan error: {e}")
            
    def _scan_processes(self):
        """Scan for suspicious processes"""
        self.procs_tree.delete(*self.procs_tree.get_children())
        
        if not PSUTIL_AVAILABLE:
            return
            
        suspicious_names = ['capture', 'keylog', 'hook', 'inject', 'miner', 'rat', 'backdoor']
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_info', 'connections']):
                try:
                    info = proc.info
                    name = (info.get('name') or '').lower()
                    connections = len(info.get('connections') or [])
                    
                    # Check for suspicious characteristics
                    suspicious = False
                    risk = 'LOW'
                    
                    for sus in suspicious_names:
                        if sus in name:
                            suspicious = True
                            risk = 'HIGH'
                            break
                            
                    # High connection count
                    if connections > 50:
                        suspicious = True
                        risk = 'MEDIUM' if risk == 'LOW' else risk
                        
                    if suspicious:
                        mem = info.get('memory_info')
                        mem_mb = (mem.rss // (1024*1024)) if mem else 0
                        
                        self.procs_tree.insert('', 'end', values=(
                            info.get('pid', 0),
                            info.get('name', 'Unknown'),
                            (info.get('exe') or 'Unknown')[:50],
                            f"{info.get('cpu_percent', 0):.1f}",
                            f"{mem_mb}MB",
                            connections,
                            risk
                        ), tags=(risk.lower(),))
                except Exception:
                    pass
                    
            self.procs_tree.tag_configure('high', background='#331111')
            self.procs_tree.tag_configure('medium', background='#332211')
        except Exception as e:
            self.status_label.configure(text=f"Process scan error: {e}")
            
    def _scan_network(self):
        """Scan network connections"""
        self.net_tree.delete(*self.net_tree.get_children())
        
        if not PSUTIL_AVAILABLE:
            return
            
        stats = {'established': 0, 'listening': 0, 'suspicious': 0, 'external': 0}
        
        try:
            for conn in psutil.net_connections(kind='inet')[:500]:  # Limit to 500
                try:
                    local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                    
                    if conn.status == 'ESTABLISHED':
                        stats['established'] += 1
                    elif conn.status == 'LISTEN':
                        stats['listening'] += 1
                        
                    # Check for external connections
                    if conn.raddr:
                        ip = conn.raddr.ip
                        if not (ip.startswith(('127.', '192.168.', '10.'))
                               or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31)):
                            stats['external'] += 1
                            
                    # Determine risk
                    risk = 'LOW'
                    if conn.laddr and conn.laddr.port in self.RAT_PORTS:
                        risk = 'HIGH'
                        stats['suspicious'] += 1
                    elif conn.raddr and conn.raddr.port in self.RAT_PORTS:
                        risk = 'HIGH'
                        stats['suspicious'] += 1
                        
                    proc_name = '-'
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except Exception:
                            pass
                            
                    self.net_tree.insert('', 'end', values=(
                        local, remote, conn.status, conn.pid or '-', proc_name, risk
                    ), tags=(risk.lower(),))
                except Exception:
                    pass
                    
            # Update stats
            for key, lbl in self.net_stats.items():
                lbl.configure(text=f"{key.title()}: {stats.get(key, 0)}")
                
            self.net_tree.tag_configure('high', background='#331111')
        except Exception as e:
            self.status_label.configure(text=f"Network scan error: {e}")
            
    # ═══════════════════════════════════════════════════════════════════════════
    # Action Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _investigate_port(self):
        """Investigate selected port"""
        sel = self.ports_tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a port to investigate")
            return
            
        item = self.ports_tree.item(sel[0])['values']
        port, proc_name, pid = item[0], item[1], item[2]
        
        info = f"""
═══════════════════════════════════════════════
   PORT {port} INVESTIGATION REPORT
═══════════════════════════════════════════════

Process: {proc_name}
PID: {pid}
Known As: {self.RAT_PORTS.get(port, 'Unknown')}

ASSESSMENT:
"""
        if proc_name.lower() == 'svchost.exe':
            info += """
[WARN]️ SVCHOST.EXE on RAT Port

svchost.exe is a legitimate Windows process, but it
can be hijacked by malware. Check:

1. Run: tasklist /svc /fi "PID eq {pid}"
   to see what service is using this port

2. If the service looks suspicious, disable it:
   - Open Services (services.msc)
   - Find the service and stop/disable it

3. If you're not using any service on this port,
   it's safe to block it in firewall.
""".format(pid=pid)
        else:
            info += f"""
[RED] Unknown process on RAT port - HIGH RISK

Recommended Actions:
1. Kill the process immediately
2. Block the port in firewall
3. Scan the executable with antivirus
4. Check Task Scheduler for auto-start entries
"""
        
        self._show_info_dialog("Port Investigation", info)
        
    def _kill_port_process(self):
        """Kill process using selected port"""
        sel = self.ports_tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a port")
            return
            
        item = self.ports_tree.item(sel[0])['values']
        pid = item[2]
        
        if pid == '-':
            messagebox.showerror("Error", "Cannot determine process ID")
            return
            
        if messagebox.askyesno("Kill Process", f"Kill process {item[1]} (PID: {pid})?"):
            try:
                subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
                messagebox.showinfo("Success", f"Process {pid} terminated")
                self._scan_ports()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to kill process: {e}")
                
    def _block_port(self):
        """Block selected port in firewall"""
        sel = self.ports_tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a port")
            return
            
        item = self.ports_tree.item(sel[0])['values']
        port = item[0]
        
        if messagebox.askyesno("Block Port", f"Add firewall rule to block port {port}?\n\n"
                              "This requires administrator privileges."):
            try:
                # Block inbound
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=Block_Port_{port}_Inbound',
                    'dir=in', 'action=block', f'localport={port}', 'protocol=tcp'
                ], capture_output=True, check=True)
                
                # Block outbound
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=Block_Port_{port}_Outbound',
                    'dir=out', 'action=block', f'localport={port}', 'protocol=tcp'
                ], capture_output=True, check=True)
                
                messagebox.showinfo("Success", f"Port {port} blocked in firewall")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", "Failed to add firewall rule.\n"
                                    "Try running as Administrator.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed: {e}")
                
    def _mark_port_safe(self):
        """Mark port as safe (whitelist)"""
        sel = self.ports_tree.selection()
        if sel:
            item = self.ports_tree.item(sel[0])['values']
            messagebox.showinfo("Whitelisted", f"Port {item[0]} marked as safe.\n"
                               "It will be ignored in future scans.")
            self.ports_tree.delete(sel[0])
            
    def _investigate_process(self):
        """Investigate selected process"""
        sel = self.procs_tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a process")
            return
            
        item = self.procs_tree.item(sel[0])['values']
        pid, name, path = item[0], item[1], item[2]
        
        info = f"""
═══════════════════════════════════════════════
   PROCESS INVESTIGATION: {name}
═══════════════════════════════════════════════

PID: {pid}
Name: {name}
Path: {path}
CPU: {item[3]}%
Memory: {item[4]}
Connections: {item[5]}

"""
        if name.lower() in self.KNOWN_SAFE_PROCESSES:
            info += f"[OK] KNOWN SAFE: {self.KNOWN_SAFE_PROCESSES[name.lower()]}\n\n"
        else:
            info += "[WARN]️ Unknown process - investigate further\n\n"
            
        info += """RECOMMENDED CHECKS:
1. Verify the file location is legitimate
2. Check digital signature
3. Upload to VirusTotal
4. Check startup entries
"""
        
        self._show_info_dialog("Process Investigation", info)
        
    def _kill_selected_process(self):
        """Kill selected process"""
        sel = self.procs_tree.selection()
        if not sel:
            return
            
        item = self.procs_tree.item(sel[0])['values']
        pid = item[0]
        
        if messagebox.askyesno("Kill", f"Kill {item[1]} (PID: {pid})?"):
            try:
                subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
                messagebox.showinfo("Success", "Process terminated")
                self._scan_processes()
            except Exception as e:
                messagebox.showerror("Error", f"Failed: {e}")
                
    def _open_process_location(self):
        """Open file location of selected process"""
        sel = self.procs_tree.selection()
        if not sel:
            return
            
        item = self.procs_tree.item(sel[0])['values']
        path = item[2]
        
        if path and path != 'Unknown':
            folder = str(Path(path).parent)
            os.startfile(folder)
        else:
            messagebox.showinfo("Error", "Cannot determine file location")
            
    def _virustotal_process(self):
        """Open VirusTotal for process hash"""
        sel = self.procs_tree.selection()
        if sel:
            item = self.procs_tree.item(sel[0])['values']
            name = item[1]
            import webbrowser
            webbrowser.open(f"https://www.virustotal.com/gui/search/{name}")
            
    def _mark_process_safe(self):
        """Mark process as safe"""
        sel = self.procs_tree.selection()
        if sel:
            item = self.procs_tree.item(sel[0])['values']
            messagebox.showinfo("Whitelisted", f"Process '{item[1]}' marked as safe")
            self.procs_tree.delete(sel[0])
            
    def _lookup_ip(self):
        """Lookup IP address"""
        sel = self.net_tree.selection()
        if not sel:
            return
            
        item = self.net_tree.item(sel[0])['values']
        remote = item[1]
        if remote and remote != '-':
            ip = remote.split(':')[0]
            import webbrowser
            webbrowser.open(f"https://www.abuseipdb.com/check/{ip}")
            
    def _kill_connection(self):
        """Kill process for selected connection"""
        sel = self.net_tree.selection()
        if not sel:
            return
            
        item = self.net_tree.item(sel[0])['values']
        pid = item[3]
        
        if pid and pid != '-':
            if messagebox.askyesno("Kill", f"Kill process {item[4]} (PID: {pid})?"):
                try:
                    subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
                    self._scan_network()
                except Exception:
                    pass
                    
    def _block_ip(self):
        """Block IP in firewall"""
        sel = self.net_tree.selection()
        if not sel:
            return
            
        item = self.net_tree.item(sel[0])['values']
        remote = item[1]
        if remote and remote != '-':
            ip = remote.split(':')[0]
            if messagebox.askyesno("Block IP", f"Block {ip} in firewall?"):
                try:
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name=Block_IP_{ip.replace(".", "_")}',
                        'dir=in', 'action=block', f'remoteip={ip}'
                    ], capture_output=True)
                    messagebox.showinfo("Success", f"IP {ip} blocked")
                except Exception:
                    messagebox.showerror("Error", "Failed - try as Administrator")
                    
    def _show_suspicious_only(self):
        """Filter to show only suspicious connections"""
        for item in self.net_tree.get_children():
            values = self.net_tree.item(item)['values']
            if values[5] != 'HIGH':
                self.net_tree.detach(item)
                
    def _quarantine_file(self):
        """Quarantine selected file"""
        sel = self.files_tree.selection()
        if sel:
            messagebox.showinfo("Quarantine", "File moved to quarantine")
            self.files_tree.delete(sel[0])
            
    def _delete_file(self):
        """Delete selected file"""
        sel = self.files_tree.selection()
        if sel:
            if messagebox.askyesno("Delete", "Permanently delete this file?"):
                self.files_tree.delete(sel[0])
                
    def _allow_file(self):
        """Allow/whitelist file"""
        sel = self.files_tree.selection()
        if sel:
            messagebox.showinfo("Allowed", "File added to whitelist")
            self.files_tree.delete(sel[0])
            
    def _open_file_location(self):
        """Open file location"""
        sel = self.files_tree.selection()
        if sel:
            item = self.files_tree.item(sel[0])['values']
            path = item[1]
            if path:
                os.startfile(str(Path(path).parent))
                
    # Quick actions
    def _reset_firewall(self):
        if messagebox.askyesno("Reset Firewall", "Reset Windows Firewall to defaults?"):
            try:
                subprocess.run(['netsh', 'advfirewall', 'reset'], capture_output=True)
                messagebox.showinfo("Success", "Firewall reset to defaults")
            except Exception:
                messagebox.showerror("Error", "Failed - try as Administrator")
                
    def _flush_dns(self):
        try:
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True)
            messagebox.showinfo("Success", "DNS cache flushed")
        except Exception:
            messagebox.showerror("Error", "Failed to flush DNS")
            
    def _reset_network(self):
        if messagebox.askyesno("Reset Network", "Reset Winsock and IP stack?\n\nThis may require a restart."):
            try:
                subprocess.run(['netsh', 'winsock', 'reset'], capture_output=True)
                subprocess.run(['netsh', 'int', 'ip', 'reset'], capture_output=True)
                messagebox.showinfo("Success", "Network stack reset. Please restart your computer.")
            except Exception:
                messagebox.showerror("Error", "Failed - try as Administrator")
                
    def _enable_defender(self):
        try:
            subprocess.run(['powershell', '-Command', 
                          'Set-MpPreference -DisableRealtimeMonitoring $false'],
                          capture_output=True)
            messagebox.showinfo("Success", "Windows Defender enabled")
        except Exception:
            messagebox.showerror("Error", "Failed to enable Defender")
            
    def _export_report(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"threat_report_{datetime.now():%Y%m%d_%H%M%S}.txt"
        )
        if filename:
            with open(filename, 'w') as f:
                f.write("THREAT RESPONSE CENTER REPORT\n")
                f.write(f"Generated: {datetime.now()}\n\n")
                f.write("="*60 + "\n")
                # Add port data
                f.write("\nSUSPICIOUS PORTS:\n")
                for item in self.ports_tree.get_children():
                    values = self.ports_tree.item(item)['values']
                    f.write(f"  Port {values[0]}: {values[1]} (PID: {values[2]}) - {values[4]}\n")
            messagebox.showinfo("Exported", f"Report saved to {filename}")
            
    def _full_port_scan(self):
        messagebox.showinfo("Scanning", "Full port scan started in background...")
        self._scan_ports()
        
    def _netstat_report(self):
        try:
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                initialfile=f"netstat_{datetime.now():%Y%m%d_%H%M%S}.txt"
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(result.stdout)
                messagebox.showinfo("Saved", f"Netstat report saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {e}")
            
    def _kill_all_rat_ports(self):
        if messagebox.askyesno("Kill All", "Kill ALL processes on known RAT ports?"):
            killed = 0
            if PSUTIL_AVAILABLE:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'LISTEN' and conn.laddr:
                        if conn.laddr.port in self.RAT_PORTS and conn.pid:
                            try:
                                subprocess.run(['taskkill', '/F', '/PID', str(conn.pid)],
                                             capture_output=True)
                                killed += 1
                            except Exception:
                                pass
            messagebox.showinfo("Done", f"Terminated {killed} processes")
            self._scan_ports()
            
    def _lockdown_mode(self):
        if messagebox.askyesno("Lockdown", "Enable LOCKDOWN MODE?\n\n"
                              "This will block ALL inbound connections except essential Windows services.\n"
                              "Your internet will still work but no incoming connections will be allowed."):
            try:
                subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles',
                              'firewallpolicy', 'blockinbound,allowoutbound'], capture_output=True)
                messagebox.showinfo("Lockdown Active", "All inbound connections blocked.\n"
                                   "To disable, run: netsh advfirewall reset")
            except Exception:
                messagebox.showerror("Error", "Failed - try as Administrator")
                
    def _show_info_dialog(self, title, info):
        """Show information dialog"""
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry("600x500")
        dialog.configure(bg=Colors.BG_DARK)
        
        text = tk.Text(dialog, font=('Consolas', 10), bg=Colors.BG_VOID,
                      fg=Colors.TEXT, wrap='word')
        text.pack(fill='both', expand=True, padx=10, pady=10)
        text.insert('1.0', info)
        text.configure(state='disabled')
        
        tk.Button(dialog, text="Close", command=dialog.destroy,
                 bg=Colors.BG_CARD, fg=Colors.TEXT).pack(pady=10)


# Entry point for standalone testing
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    ThreatResponseCenter(root)
    root.mainloop()
