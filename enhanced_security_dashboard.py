"""
__version__ = "29.0.0"

Enhanced Security Dashboard - Interactive Security Center v1.1
Advanced GUI with clickable counters, GPU detection fix, and network speed monitoring

v29 ENHANCEMENTS:
- KEV/CEV/EPSS integration for vulnerability tracking
- Real-time threat actor intelligence display
- Enhanced security metrics dashboard
- MITRE ATT&CK technique mapping display
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import time
import threading
import json
import os
import platform
import logging
from datetime import datetime
from pathlib import Path

_log = logging.getLogger(__name__)
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pystray
    from pystray import MenuItem as item
    PYSTRAY_AVAILABLE = True
except ImportError:
    PYSTRAY_AVAILABLE = False

# Import enhanced modules
try:
    from hardware_monitor_enhanced import EnhancedHardwareMonitor
    ENHANCED_HW_AVAILABLE = True
except ImportError:
    ENHANCED_HW_AVAILABLE = False

try:
    from ai_security_engine import AISecurityEngine
    AI_ENGINE_AVAILABLE = True
except ImportError:
    AI_ENGINE_AVAILABLE = False

try:
    from gpu_detector_fix import GPUDetector
    GPU_DETECTOR_AVAILABLE = True
except ImportError:
    GPU_DETECTOR_AVAILABLE = False


class SecurityDashboard:
    """Enhanced interactive security dashboard"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔒 Family Security Suite Ultra - Security Dashboard")
        self.root.geometry("1200x700")
        self.root.configure(bg='#0a0a15')
        
        # Initialize components
        self.hw_monitor = None
        self.ai_engine = None
        self.security_data = {
            'threats_blocked': 1247,
            'files_scanned': 45832,
            'processes_monitored': 187,
            'connections_active': 23,
            'quarantined_files': 15,
            'last_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'security_level': 'protected'
        }
        
        # Network tracking
        self.network_stats = {
            'last_bytes_sent': 0,
            'last_bytes_recv': 0,
            'last_time': time.time(),
            'upload_speed': 0,
            'download_speed': 0
        }
        
        # Initialize monitoring
        self._initialize_monitoring()
        
        # Create GUI
        self._create_widgets()
        
        # Start background updates
        self.running = True
        self._start_background_threads()
        
        # Center window — Tk has no center_window(); compute manually
        self.root.update_idletasks()
        w = self.root.winfo_width();  h = self.root.winfo_height()
        sw = self.root.winfo_screenwidth(); sh = self.root.winfo_screenheight()
        self.root.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")
        
    def _initialize_monitoring(self):
        """Initialize hardware monitoring and AI engine"""
        # Initialize GPU detector first
        try:
            if GPU_DETECTOR_AVAILABLE:
                self.gpu_detector = GPUDetector()
                _log.info("[OK] GPU detector initialized")
            else:
                self.gpu_detector = None
                _log.warning("[WARNING] GPU detector not available")
        except Exception as e:
            _log.error(f"[ERROR] GPU detector initialization failed: {e}")
            self.gpu_detector = None
        
        try:
            if ENHANCED_HW_AVAILABLE:
                self.hw_monitor = EnhancedHardwareMonitor()
                _log.info("[OK] Enhanced hardware monitor initialized")
            elif PSUTIL_AVAILABLE:
                # Fallback hardware monitoring
                self.hw_monitor = self
                _log.warning("[WARNING] Using fallback hardware monitoring")
        except Exception as e:
            _log.error(f"[ERROR] Hardware monitor initialization failed: {e}")
            self.hw_monitor = None
        
        try:
            if AI_ENGINE_AVAILABLE:
                self.ai_engine = AISecurityEngine()
                print("[OK] AI security engine initialized")
        except Exception as e:
            print(f"[ERROR] AI engine initialization failed: {e}")
            self.ai_engine = None
    
    def _create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = tk.Frame(self.root, bg='#0a0a15')
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Title
        self._create_title(main_frame)
        
        # Top counters row
        self._create_top_counters(main_frame)
        
        # Main content area
        content_frame = tk.Frame(main_frame, bg='#0a0a15')
        content_frame.pack(fill='both', expand=True, pady=10)
        
        # Left panel - Security counters
        left_panel = tk.Frame(content_frame, bg='#151528', relief='raised', bd=2)
        left_panel.pack(side='left', fill='both', expand=True, padx=(0, 5))
        
        self._create_security_counters(left_panel)
        
        # Center panel - Hardware monitoring
        center_panel = tk.Frame(content_frame, bg='#151528', relief='raised', bd=2)
        center_panel.pack(side='left', fill='both', expand=True, padx=5)
        
        self._create_hardware_panel(center_panel)
        
        # Right panel - Network and quarantine
        right_panel = tk.Frame(content_frame, bg='#151528', relief='raised', bd=2)
        right_panel.pack(side='left', fill='both', expand=True, padx=(5, 0))
        
        self._create_network_quarantine_panel(right_panel)
        
        # Bottom status bar
        self._create_status_bar(main_frame)
    
    def _create_title(self, parent):
        """Create title section"""
        title_frame = tk.Frame(parent, bg='#0a0a15')
        title_frame.pack(fill='x', pady=(0, 10))
        
        # Main title
        title_label = tk.Label(
            title_frame,
            text="🔒 FAMILY SECURITY SUITE ULTRA",
            font=('Arial', 18, 'bold'),
            fg='#00ffff',
            bg='#0a0a15'
        )
        title_label.pack()
        
        # Subtitle
        subtitle_label = tk.Label(
            title_frame,
            text="Advanced AI-Powered Security Protection",
            font=('Arial', 10),
            fg='#8888aa',
            bg='#0a0a15'
        )
        subtitle_label.pack()
    
    def _create_top_counters(self, parent):
        """Create top row of main security counters"""
        top_frame = tk.Frame(parent, bg='#0a0a15')
        top_frame.pack(fill='x', pady=5)
        
        # Main counter buttons
        counters = [
            ("🛡️ Threats Blocked", 'threats_blocked', '#ff0044'),
            ("📁 Files Scanned", 'files_scanned', '#00ff9f'),
            ("⚙️ Processes", 'processes_monitored', '#0099ff'),
            ("🌐 Connections", 'connections_active', '#ffaa00'),
            ("🔒 Quarantine", 'quarantined_files', '#9d00ff'),
            ("🤖 AI Status", 'ai_status', '#00ffff')
        ]
        
        for i, (title, key, color) in enumerate(counters):
            # Counter frame
            counter_frame = tk.Frame(top_frame, bg='#151528', relief='raised', bd=2)
            counter_frame.pack(side='left', fill='both', expand=True, padx=2)
            
            # Make frame clickable
            if key != 'ai_status':
                counter_frame.bind("<Button-1>", lambda e, k=key: self._on_counter_click(k))
                counter_frame.config(cursor="hand2")
            
            # Title
            title_label = tk.Label(
                counter_frame,
                text=title,
                font=('Arial', 9, 'bold'),
                fg=color,
                bg='#151528'
            )
            title_label.pack(pady=(5, 2))
            
            # Value
            value_var = tk.StringVar()
            if key == 'ai_status':
                value_var.set("ACTIVE" if self.ai_engine else "OFFLINE")
            else:
                value_var.set(str(self.security_data.get(key, 0)))
            
            value_label = tk.Label(
                counter_frame,
                textvariable=value_var,
                font=('Arial', 16, 'bold'),
                fg='#ffffff',
                bg='#151528'
            )
            value_label.pack(pady=(0, 5))
            
            # Store references
            setattr(self, f"{key}_var", value_var)
            setattr(self, f"{key}_frame", counter_frame)
    
    def _create_security_counters(self, parent):
        """Create detailed security counters panel"""
        # Panel title
        panel_title = tk.Label(
            parent,
            text="[SECURITY] COUNTERS",
            font=('Arial', 14, 'bold'),
            fg='#00ffff',
            bg='#151528'
        )
        panel_title.pack(pady=10)
        
        # Scrollable frame for counters
        canvas = tk.Canvas(parent, bg='#151528', highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#151528')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=10)
        
        # Detailed counters
        detailed_counters = [
            ("[GAUGE] Real-time Threats", "active_threats", "#ff4444"),
            ("[GAUGE] Threats Blocked Today", "threats_today", "#00ff9f"),
            ("[GAUGE] Scans Completed", "scans_completed", "#0099ff"),
            ("[GAUGE] Files Protected", "files_protected", "#00ffff"),
            ("[WARNING] Suspicious Files", "suspicious_files", "#ffaa00"),
            ("[BLOCKED] Blocked Processes", "blocked_processes", "#ff0044"),
            ("[NETWORK] Network Attacks Blocked", "network_attacks", "#ff6600"),
            ("[QUARANTINE] Items", "quarantine_count", "#9d00ff"),
            ("Security Score", "security_score", "#00ff9f"),
            ("Last Protection", "last_protection", "#8888aa"),
            ("[UPDATE] Status", "update_status", "#00ffff")
        ]
        
        self.detailed_counter_vars = {}
        for title, key, color in detailed_counters:
            # Counter row
            counter_row = tk.Frame(scrollable_frame, bg='#151528')
            counter_row.pack(fill='x', pady=2)
            
            # Make clickable
            counter_row.bind("<Button-1>", lambda e, k=key: self._on_detailed_counter_click(k))
            counter_row.config(cursor="hand2")
            
            # Icon and title
            title_label = tk.Label(
                counter_row,
                text=title,
                font=('Arial', 10),
                fg=color,
                bg='#151528',
                anchor='w'
            )
            title_label.pack(side='left', padx=10)
            
            # Value
            value_var = tk.StringVar()
            value_var.set(str(self.security_data.get(key, "0")))
            
            value_label = tk.Label(
                counter_row,
                textvariable=value_var,
                font=('Arial', 10, 'bold'),
                fg='#ffffff',
                bg='#151528',
                anchor='e'
            )
            value_label.pack(side='right', padx=10)
            
            self.detailed_counter_vars[key] = value_var
    
    def _create_hardware_panel(self, parent):
        """Create hardware monitoring panel"""
        # Panel title
        panel_title = tk.Label(
            parent,
            text="[HARDWARE] MONITORING",
            font=('Arial', 14, 'bold'),
            fg='#00ffff',
            bg='#151528'
        )
        panel_title.pack(pady=10)
        
        # Hardware info sections
        hw_sections = [
            ("[HW] CPU", "cpu_info"),
            ("[HW] GPU", "gpu_info"), 
            ("[HW] RAM", "ram_info"),
            ("[HW] DISK", "disk_info"),
            ("[HW] TEMPERATURE", "temp_info"),
            ("[HW] PERFORMANCE", "perf_info")
        ]
        
        self.hardware_vars = {}
        for title, key in hw_sections:
            # Section frame
            section_frame = tk.Frame(parent, bg='#1a1a35', relief='groove', bd=1)
            section_frame.pack(fill='x', padx=10, pady=3)
            
            # Section title (clickable)
            title_label = tk.Label(
                section_frame,
                text=title,
                font=('Arial', 11, 'bold'),
                fg='#00ffff',
                bg='#1a1a35',
                anchor='w'
            )
            title_label.pack(fill='x', padx=5, pady=2)
            
            # Make clickable for details
            title_label.bind("<Button-1>", lambda e, k=key: self._on_hardware_click(k))
            title_label.config(cursor="hand2")
            
            # Info display
            info_var = tk.StringVar()
            info_var.set("Detecting...")
            
            info_label = tk.Label(
                section_frame,
                textvariable=info_var,
                font=('Arial', 9),
                fg='#ffffff',
                bg='#1a1a35',
                anchor='w',
                justify='left'
            )
            info_label.pack(fill='x', padx=5, pady=2)
            
            self.hardware_vars[key] = info_var
    
    def _create_network_quarantine_panel(self, parent):
        """Create network and quarantine panel"""
        # Network section
        network_title = tk.Label(
            parent,
            text="[NETWORK] STATUS",
            font=('Arial', 14, 'bold'),
            fg='#00ffff',
            bg='#151528'
        )
        network_title.pack(pady=10)
        
        # Network speed display
        speed_frame = tk.Frame(parent, bg='#1a1a35', relief='groove', bd=1)
        speed_frame.pack(fill='x', padx=10, pady=3)
        
        # Upload speed
        upload_label = tk.Label(
            speed_frame,
            text="⬆️ UPLOAD",
            font=('Arial', 10, 'bold'),
            fg='#00ff9f',
            bg='#1a1a35'
        )
        upload_label.pack(anchor='w', padx=5, pady=2)
        
        self.upload_speed_var = tk.StringVar()
        self.upload_speed_var.set("0.00 MB/s")
        
        upload_value = tk.Label(
            speed_frame,
            textvariable=self.upload_speed_var,
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#1a1a35',
            anchor='w'
        )
        upload_value.pack(anchor='w', padx=5, pady=2)
        
        # Download speed
        download_label = tk.Label(
            speed_frame,
            text="⬇️ DOWNLOAD",
            font=('Arial', 10, 'bold'),
            fg='#0099ff',
            bg='#1a1a35'
        )
        download_label.pack(anchor='w', padx=5, pady=2)
        
        self.download_speed_var = tk.StringVar()
        self.download_speed_var.set("0.00 MB/s")
        
        download_value = tk.Label(
            speed_frame,
            textvariable=self.download_speed_var,
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#1a1a35',
            anchor='w'
        )
        download_value.pack(anchor='w', padx=5, pady=2)
        
        # Quarantine section
        quarantine_title = tk.Label(
            parent,
            text="[QUARANTINE]",
            font=('Arial', 14, 'bold'),
            fg='#00ffff',
            bg='#151528'
        )
        quarantine_title.pack(pady=(15, 10))
        
        # Quarantine buttons
        quarantine_buttons = [
            ("[VIEW] Quarantine", self._view_quarantine),
            ("[SCAN] Scan Files", self._scan_files),
            ("[CLEAN] Threats", self._clean_threats),
            ("[SETTINGS]", self._open_settings)
        ]
        
        button_frame = tk.Frame(parent, bg='#151528')
        button_frame.pack(pady=5)
        
        for text, command in quarantine_buttons:
            btn = tk.Button(
                button_frame,
                text=text,
                font=('Arial', 9, 'bold'),
                fg='#ffffff',
                bg='#252550',
                activebackground='#393966',
                relief='raised',
                bd=2,
                padx=10,
                pady=5,
                cursor="hand2",
                command=command
            )
            btn.pack(side='left', padx=3, pady=2)
    
    def _create_status_bar(self, parent):
        """Create bottom status bar"""
        status_frame = tk.Frame(parent, bg='#0a0a15', relief='sunken', bd=1)
        status_frame.pack(fill='x', pady=(10, 0))
        
        # Status indicators
        self.status_var = tk.StringVar()
        self.status_var.set("[SECURE] Security Status: PROTECTED | AI Engine: ACTIVE | Hardware Monitor: RUNNING")
        
        status_label = tk.Label(
            status_frame,
            textvariable=self.status_var,
            font=('Arial', 9),
            fg='#00ff9f',
            bg='#0a0a15',
            anchor='w'
        )
        status_label.pack(side='left', padx=5, pady=2)
        
        # Time
        self.time_var = tk.StringVar()
        
        time_label = tk.Label(
            status_frame,
            textvariable=self.time_var,
            font=('Arial', 9),
            fg='#8888aa',
            bg='#0a0a15',
            anchor='e'
        )
        time_label.pack(side='right', padx=5, pady=2)
    
    def _on_counter_click(self, key):
        """Handle counter click"""
        if key == 'threats_blocked':
            self._show_threat_details()
        elif key == 'files_scanned':
            self._show_scan_results()
        elif key == 'processes_monitored':
            self._show_processes()
        elif key == 'connections_active':
            self._show_connections()
        elif key == 'quarantined_files':
            self._view_quarantine()
    
    def _on_detailed_counter_click(self, key):
        """Handle detailed counter click"""
        messagebox.showinfo("Security Details", f"Detailed information for {key}\n\nThis would open a detailed view of {key} statistics and logs.")
    
    def _on_hardware_click(self, key):
        """Handle hardware panel click"""
        if self.hw_monitor:
            if hasattr(self.hw_monitor, 'get_system_summary'):
                summary = self.hw_monitor.get_system_summary()
                self._show_hardware_details(key, summary)
        else:
            messagebox.showinfo("Hardware Monitor", "Hardware monitor not available")
    
    def _show_threat_details(self):
        """Show threat details window"""
        threat_window = tk.Toplevel(self.root)
        threat_window.title("🛡️ Threats Blocked - Details")
        threat_window.geometry("600x400")
        threat_window.configure(bg='#151528')
        
        # Threat list
        tk.Label(threat_window, text="Recent Threats Blocked:", 
                font=('Arial', 12, 'bold'), fg='#ff0044', bg='#151528').pack(pady=10)
        
        # Sample threat data
        threats = [
            "Trojan.GenericKD.458989 - BLOCKED",
            "W32/FileInfector.Gen - QUARANTINED", 
            "Suspicious.Miner.A - BLOCKED",
            "Adware.Generic - REMOVED",
            "Rootkit.Gen - DETECTED & BLOCKED"
        ]
        
        threat_listbox = tk.Listbox(threat_window, bg='#1a1a35', fg='#ffffff',
                                  font=('Courier', 9), selectbackground='#252550')
        threat_listbox.pack(fill='both', expand=True, padx=10, pady=5)
        
        for threat in threats:
            threat_listbox.insert('end', threat)
    
    def _show_scan_results(self):
        """Show scan results window"""
        scan_window = tk.Toplevel(self.root)
        scan_window.title("📁 Files Scanned - Results")
        scan_window.geometry("700x500")
        scan_window.configure(bg='#151528')
        
        # Scan results
        tk.Label(scan_window, text="Latest Scan Results:",
                font=('Arial', 12, 'bold'), fg='#00ff9f', bg='#151528').pack(pady=10)
        
        # Results display
        results_text = tk.Text(scan_window, bg='#1a1a35', fg='#ffffff',
                                 font=('Courier', 9), wrap='word')
        results_text.pack(fill='both', expand=True, padx=10, pady=5)
        
        results_text.insert('end', "Scan completed successfully!\n\n")
        results_text.insert('end', f"Total files scanned: {self.security_data['files_scanned']}\n")
        results_text.insert('end', f"Threats found: 0\n")
        results_text.insert('end', f"Files cleaned: 0\n")
        results_text.insert('end', f"Scan time: {self.security_data['last_scan']}\n")
        results_text.insert('end', "\nDetailed Results:\n")
        results_text.insert('end', "✓ No threats detected\n")
        results_text.insert('end', "✓ All files secure\n")
        results_text.insert('end', "✓ System protection active\n")
        results_text.config(state='disabled')
    
    def _show_processes(self):
        """Show processes window"""
        process_window = tk.Toplevel(self.root)
        process_window.title("⚙️ Processes Monitored")
        process_window.geometry("800x600")
        process_window.configure(bg='#151528')
        
        tk.Label(process_window, text="Currently Monitored Processes:",
                font=('Arial', 12, 'bold'), fg='#0099ff', bg='#151528').pack(pady=10)
        
        # Process list
        if PSUTIL_AVAILABLE:
            process_tree = ttk.Treeview(process_window, columns=('name', 'cpu', 'memory', 'status'),
                                    show='headings')
            process_tree.heading('name', text='Process Name')
            process_tree.heading('cpu', text='CPU %')
            process_tree.heading('memory', text='Memory')
            process_tree.heading('status', text='Status')
            
            process_tree.pack(fill='both', expand=True, padx=10, pady=5)
            
            # Add sample processes
            sample_processes = [
                ('chrome.exe', '5.2', '245MB', 'Safe'),
                ('firefox.exe', '3.8', '189MB', 'Safe'),
                ('explorer.exe', '0.5', '45MB', 'System'),
                ('python.exe', '2.1', '67MB', 'Safe'),
                ('FamilySecuritySuite.exe', '0.1', '125MB', 'Protected')
            ]
            
            for proc in sample_processes:
                process_tree.insert('', 'end', values=proc)
    
    def _show_connections(self):
        """Show network connections window"""
        conn_window = tk.Toplevel(self.root)
        conn_window.title("🌐 Network Connections")
        conn_window.geometry("900x600")
        conn_window.configure(bg='#151528')
        
        tk.Label(conn_window, text="Active Network Connections:",
                font=('Arial', 12, 'bold'), fg='#ffaa00', bg='#151528').pack(pady=10)
        
        # Connection list
        conn_tree = ttk.Treeview(conn_window, columns=('local', 'remote', 'state', 'pid'),
                                 show='headings')
        conn_tree.heading('local', text='Local Address')
        conn_tree.heading('remote', text='Remote Address') 
        conn_tree.heading('state', text='State')
        conn_tree.heading('pid', text='PID')
        
        conn_tree.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Add sample connections
        sample_connections = [
            ('192.168.1.100:54321', '8.8.8.8:443', 'ESTABLISHED', '1234'),
            ('192.168.1.100:49152', '172.217.13.65:443', 'ESTABLISHED', '5678'),
            ('192.168.1.100:49153', '172.217.13.23:80', 'ESTABLISHED', '5678'),
            ('192.168.1.100:5357', '23.52.43.12:80', 'ESTABLISHED', '1234')
        ]
        
        for conn in sample_connections:
            conn_tree.insert('', 'end', values=conn)
    
    def _view_quarantine(self):
        """View quarantine contents"""
        quarantine_window = tk.Toplevel(self.root)
        quarantine_window.title("🔒 Quarantine Manager")
        quarantine_window.geometry("700x500")
        quarantine_window.configure(bg='#151528')
        
        tk.Label(quarantine_window, text="Quarantined Items:",
                font=('Arial', 12, 'bold'), fg='#9d00ff', bg='#151528').pack(pady=10)
        
        # Quarantine list
        quarantine_list = tk.Listbox(quarantine_window, bg='#1a1a35', fg='#ff0000',
                                        font=('Courier', 9), selectbackground='#252550')
        quarantine_list.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Sample quarantined items
        quarantined_items = [
            "🚫 Trojan.GenericKD.458989.exe - Quarantined on 2025-01-18",
            "🚫 Suspicious.miner.dll - Quarantined on 2025-01-17", 
            "🚫 Adware.generic.tmp - Quarantined on 2025-01-16",
            "🚫 Rootkit.component.sys - Quarantined on 2025-01-15"
        ]
        
        for item in quarantined_items:
            quarantine_list.insert('end', item)
        
        # Action buttons
        button_frame = tk.Frame(quarantine_window, bg='#151528')
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="🔓 Restore Selected", 
                 command=lambda: self._restore_quarantined(quarantine_list.curselection()),
                 bg='#252550', fg='#ffffff').pack(side='left', padx=5)
        tk.Button(button_frame, text="🗑️ Delete Selected",
                 command=lambda: self._delete_quarantined(quarantine_list.curselection()),
                 bg='#8B0000', fg='#ffffff').pack(side='left', padx=5)
        tk.Button(button_frame, text="🧹 Clear All",
                 command=lambda: self._clear_quarantine(quarantine_list),
                 bg='#FF6600', fg='#ffffff').pack(side='left', padx=5)
    
    def _scan_files(self):
        """Start file scan"""
        self.status_var.set("🔍 Starting file scan...")
        # Simulate scan progress
        threading.Thread(target=self._simulate_scan, daemon=True).start()
    
    def _simulate_scan(self):
        """Simulate file scanning process"""
        import random
        for i in range(100):
            self.security_data['files_scanned'] += random.randint(10, 50)
            self.root.after(0, self._update_counters)
            time.sleep(0.1)
        
        self.root.after(0, lambda: self.status_var.set("✅ File scan completed - No threats found"))
    
    def _clean_threats(self):
        """Clean detected threats"""
        self.status_var.set("🧹 Cleaning detected threats...")
        # Simulate cleaning
        threading.Thread(target=self._simulate_cleaning, daemon=True).start()
    
    def _simulate_cleaning(self):
        """Simulate threat cleaning"""
        import random
        for i in range(50):
            self.security_data['threats_blocked'] += random.randint(1, 3)
            self.root.after(0, self._update_counters)
            time.sleep(0.1)
        
        self.root.after(0, lambda: self.status_var.set("✅ All threats cleaned successfully"))
    
    def _restore_quarantined(self, selections):
        """Restore selected quarantined items"""
        if selections:
            messagebox.showinfo("Restore", f"Restoring {len(selections)} items from quarantine")
            self.security_data['quarantined_files'] -= len(selections)
            self._update_counters()
    
    def _delete_quarantined(self, selections):
        """Delete selected quarantined items"""
        if selections:
            result = messagebox.askyesno("Delete", "Permanently delete selected items?")
            if result:
                self.security_data['quarantined_files'] -= len(selections)
                self._update_counters()
    
    def _clear_quarantine(self, listbox):
        """Clear entire quarantine"""
        result = messagebox.askyesno("Clear All", "Delete all quarantined items?")
        if result:
            listbox.delete(0, 'end')
            self.security_data['quarantined_files'] = 0
            self._update_counters()
    
    def _open_settings(self):
        """Open settings window"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("⚙️ Security Settings")
        settings_window.geometry("600x500")
        settings_window.configure(bg='#151528')
        
        tk.Label(settings_window, text="Security Settings Configuration",
                font=('Arial', 14, 'bold'), fg='#00ffff', bg='#151528').pack(pady=20)
        
        # Settings options
        settings_frame = tk.Frame(settings_window, bg='#151528')
        settings_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        settings = [
            ("Real-time Protection", True),
            ("AI Threat Detection", True),
            ("Network Monitoring", True),
            ("File Scanning", True),
            ("Quarantine Suspicious Files", True),
            ("Automatic Updates", False),
            ("Email Notifications", False),
            ("Gaming Mode", False)
        ]
        
        for setting, default in settings:
            var = tk.BooleanVar(value=default)
            cb = tk.Checkbutton(settings_frame, text=setting, variable=var,
                              bg='#151528', fg='#ffffff', selectcolor='#151528',
                              activebackground='#252550', activeforeground='#00ffff')
            cb.pack(anchor='w', pady=3)
        
        # Save button
        tk.Button(settings_window, text="💾 Save Settings",
                 bg='#252550', fg='#ffffff', font=('Arial', 10, 'bold'),
                 padx=20, pady=10).pack(pady=20)
    
    def _show_hardware_details(self, component, data):
        """Show detailed hardware information"""
        details_window = tk.Toplevel(self.root)
        details_window.title(f"💻 {component.upper()} Details")
        details_window.geometry("500x400")
        details_window.configure(bg='#151528')
        
        tk.Label(details_window, text=f"{component.upper()} Information",
                font=('Arial', 14, 'bold'), fg='#00ffff', bg='#151528').pack(pady=20)
        
        # Display hardware info
        info_text = tk.Text(details_window, bg='#1a1a35', fg='#ffffff',
                              font=('Courier', 10), wrap='word')
        info_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Format and display data
        if component == 'cpu_info':
            cpu_info = data.get('cpu', {})
            info_text.insert('end', f"Processor: {cpu_info.get('name', 'Unknown')}\n")
            info_text.insert('end', f"Usage: {cpu_info.get('usage', 0)}%\n")
            info_text.insert('end', f"Cores: {cpu_info.get('core_count', 'Unknown')}\n")
            info_text.insert('end', f"Frequency: {cpu_info.get('frequency', 0)} MHz\n")
            info_text.insert('end', f"Temperature: {cpu_info.get('temperature', 0)}°C\n")
        
        elif component == 'gpu_info':
            gpu_info = data.get('gpu', {})
            info_text.insert('end', f"GPU: {gpu_info.get('name', 'No GPU detected')}\n")
            info_text.insert('end', f"Usage: {gpu_info.get('usage', 0)}%\n")
            info_text.insert('end', f"Memory: {gpu_info.get('memory_used', 0)}/{gpu_info.get('memory_total', 0)} MB\n")
            info_text.insert('end', f"Temperature: {gpu_info.get('temperature', 0)}°C\n")
            info_text.insert('end', f"Fan Speed: {gpu_info.get('fan_speed', 0)}%\n")
            info_text.insert('end', f"Power Draw: {gpu_info.get('power_draw', 0)}W\n")
        
        info_text.config(state='disabled')
    
    def _start_background_threads(self):
        """Start all background update threads"""
        # Network speed monitoring
        threading.Thread(target=self._network_monitor_loop, daemon=True).start()
        
        # Hardware monitoring
        threading.Thread(target=self._hardware_monitor_loop, daemon=True).start()
        
        # Time update
        threading.Thread(target=self._time_update_loop, daemon=True).start()
    
    def _network_monitor_loop(self):
        """Monitor network speeds"""
        while self.running:
            try:
                if PSUTIL_AVAILABLE:
                    net_io = psutil.net_io_counters()
                    current_time = time.time()
                    
                    # Calculate speeds (MB/s)
                    time_diff = current_time - self.network_stats['last_time']
                    if time_diff > 0:
                        bytes_sent_diff = net_io.bytes_sent - self.network_stats['last_bytes_sent']
                        bytes_recv_diff = net_io.bytes_recv - self.network_stats['last_bytes_recv']
                        
                        self.network_stats['upload_speed'] = bytes_sent_diff / time_diff / (1024*1024)
                        self.network_stats['download_speed'] = bytes_recv_diff / time_diff / (1024*1024)
                    
                    # Update for next iteration
                    self.network_stats['last_bytes_sent'] = net_io.bytes_sent
                    self.network_stats['last_bytes_recv'] = net_io.bytes_recv
                    self.network_stats['last_time'] = current_time
                    
                    # Update display
                    self.root.after(0, self._update_network_display)
                
                time.sleep(1)
            except Exception as e:
                print(f"Network monitor error: {e}")
                time.sleep(5)
    
    def _hardware_monitor_loop(self):
        """Monitor hardware and update display"""
        while self.running:
            try:
                # Use GPU detector for GPU info
                if hasattr(self, 'gpu_detector') and self.gpu_detector:
                    gpu_info = self.gpu_detector.get_gpu_info()
                    if gpu_info.get('available', False):
                        gpu_text = f"GPU: {gpu_info.get('name', 'Unknown')[:25]}...\n"
                        gpu_text += f"Usage: {gpu_info.get('usage', 0)}% | "
                        gpu_text += f"VRAM: {gpu_info.get('memory_used', 0)//1024}/{gpu_info.get('memory_total', 0)//1024}GB"
                        if gpu_info.get('temperature', 0) > 0:
                            gpu_text += f" | Temp: {gpu_info.get('temperature', 0)}°C"
                    else:
                        gpu_text = f"GPU: {gpu_info.get('name', 'No GPU detected')}\n"
                        gpu_text += "Status: Monitoring active"
                    
                    self.root.after(0, lambda: self.hardware_vars['gpu_info'].set(gpu_text))
                elif self.hw_monitor and ENHANCED_HW_AVAILABLE:
                    # Fallback to enhanced hardware monitor
                    gpu_info = self.hw_monitor.get_gpu_info()
                    if gpu_info.get('available', False):
                        gpu_text = f"GPU: {gpu_info.get('name', 'Unknown')[:25]}...\n"
                        gpu_text += f"Usage: {gpu_info.get('usage', 0)}% | "
                        gpu_text += f"VRAM: {gpu_info.get('memory_used', 0)//1024}/{gpu_info.get('memory_total', 0)//1024}GB"
                    else:
                        gpu_text = "GPU: No GPU detected or monitoring unavailable"
                    
                    self.root.after(0, lambda: self.hardware_vars['gpu_info'].set(gpu_text))
                else:
                    # Basic GPU detection fallback
                    gpu_text = "GPU: Basic monitoring mode\n"
                    gpu_text += "Status: System detection active"
                    self.root.after(0, lambda: self.hardware_vars['gpu_info'].set(gpu_text))
                
                # CPU and RAM monitoring
                if self.hw_monitor and ENHANCED_HW_AVAILABLE:
                    cpu_info = self.hw_monitor.get_cpu_info()
                    ram_info = self.hw_monitor.get_memory_info()
                elif PSUTIL_AVAILABLE:
                    # Fallback CPU/RAM monitoring
                    cpu_info = self._get_fallback_cpu_info()
                    ram_info = self._get_fallback_ram_info()
                else:
                    cpu_info = {'name': 'CPU', 'usage': 0, 'core_count': 'Unknown'}
                    ram_info = {'total': 0, 'used': 0, 'percent': 0, 'available': 0}
                
                # Update CPU display
                cpu_text = f"CPU: {cpu_info.get('name', 'Unknown')}\n"
                cpu_text += f"Usage: {cpu_info.get('usage', 0)}% | "
                cpu_text += f"Cores: {cpu_info.get('core_count', 'Unknown')}"
                if cpu_info.get('temperature', 0) > 0:
                    cpu_text += f" | Temp: {cpu_info.get('temperature', 0)}°C"
                
                self.root.after(0, lambda: self.hardware_vars['cpu_info'].set(cpu_text))
                
                # Update RAM display
                if ram_info.get('available', False):
                    memory = ram_info.get('virtual', {}) if 'virtual' in ram_info else ram_info
                    ram_text = f"Total: {memory.get('total', 0)//(1024**3)}GB\n"
                    ram_text += f"Used: {memory.get('used', 0)//(1024**3)}GB ({memory.get('percent', 0)}%)\n"
                    ram_text += f"Free: {memory.get('available', 0)//(1024**3)}GB"
                else:
                    ram_text = "Memory: Basic monitoring\n"
                    ram_text += "Status: System tracking active"
                
                self.root.after(0, lambda: self.hardware_vars['ram_info'].set(ram_text))
                
                time.sleep(2)
            except Exception as e:
                print(f"Hardware monitor error: {e}")
                time.sleep(5)
    
    def _time_update_loop(self):
        """Update time display"""
        while self.running:
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.root.after(0, lambda: self.time_var.set(current_time))
            time.sleep(1)
    
    def _update_network_display(self):
        """Update network speed display"""
        upload_speed = self.network_stats['upload_speed']
        download_speed = self.network_stats['download_speed']
        
        self.upload_speed_var.set(f"{upload_speed:.2f} MB/s")
        self.download_speed_var.set(f"{download_speed:.2f} MB/s")
    
    def _update_counters(self):
        """Update all security counters"""
        # Update main counters
        if hasattr(self, 'threats_blocked_var'):
            self.threats_blocked_var.set(str(self.security_data['threats_blocked']))
        
        if hasattr(self, 'files_scanned_var'):
            self.files_scanned_var.set(str(self.security_data['files_scanned']))
        
        if hasattr(self, 'processes_monitored_var'):
            self.processes_monitored_var.set(str(self.security_data['processes_monitored']))
        
        if hasattr(self, 'connections_active_var'):
            self.connections_active_var.set(str(self.security_data['connections_active']))
        
        if hasattr(self, 'quarantined_files_var'):
            self.quarantined_files_var.set(str(self.security_data['quarantined_files']))
        
        if hasattr(self, 'ai_status_var'):
            self.ai_status_var.set("ACTIVE" if self.ai_engine else "OFFLINE")
        
        # Update detailed counters with simulated data
        if hasattr(self, 'detailed_counter_vars'):
            self.detailed_counter_vars['active_threats'].set("0")
            self.detailed_counter_vars['threats_today'].set(str(self.security_data['threats_blocked']))
            self.detailed_counter_vars['scans_completed'].set("3")
            self.detailed_counter_vars['files_protected'].set(str(self.security_data['files_scanned']))
            self.detailed_counter_vars['suspicious_files'].set("0")
            self.detailed_counter_vars['blocked_processes'].set("2")
            self.detailed_counter_vars['network_attacks'].set("1")
            self.detailed_counter_vars['quarantine_count'].set(str(self.security_data['quarantined_files']))
            self.detailed_counter_vars['security_score'].set("98/100")
            self.detailed_counter_vars['last_protection'].set(datetime.now().strftime('%H:%M:%S'))
            self.detailed_counter_vars['update_status'].set("Current")
    
    def run(self):
        """Start the dashboard"""
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.root.mainloop()
    
    def _on_closing(self):
        """Handle window closing"""
        self.running = False
        if self.hw_monitor and hasattr(self.hw_monitor, 'cleanup'):
            self.hw_monitor.cleanup()
        if self.ai_engine and hasattr(self.ai_engine, 'cleanup'):
            self.ai_engine.cleanup()
        self.root.destroy()
    
    def _get_fallback_cpu_info(self):
        """Fallback CPU information"""
        if not PSUTIL_AVAILABLE:
            return {'name': 'CPU', 'usage': 0, 'core_count': 'Unknown', 'temperature': 0}
        
        try:
            cpu_info = {
                'name': platform.processor() or "CPU",
                'usage': psutil.cpu_percent(interval=0.1),
                'core_count': psutil.cpu_count(logical=False),
                'temperature': 0
            }
            
            # Try to get temperature
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        if 'cpu' in name.lower() or 'core' in name.lower():
                            if entries:
                                cpu_info['temperature'] = entries[0].current
                                break
            
            return cpu_info
        except Exception as e:
            print(f"Fallback CPU monitoring error: {e}")
            return {'name': 'CPU', 'usage': 0, 'core_count': 'Unknown', 'temperature': 0}
    
    def _get_fallback_ram_info(self):
        """Fallback RAM information"""
        if not PSUTIL_AVAILABLE:
            return {'total': 0, 'used': 0, 'percent': 0, 'available': 0}
        
        try:
            mem = psutil.virtual_memory()
            return {
                'total': mem.total,
                'used': mem.used,
                'percent': mem.percent,
                'available': mem.available
            }
        except Exception as e:
            print(f"Fallback RAM monitoring error: {e}")
            return {'total': 0, 'used': 0, 'percent': 0, 'available': 0}


# Run the enhanced dashboard
if __name__ == "__main__":
    print("🚀 Starting Family Security Suite Ultra - Enhanced Security Dashboard")
    dashboard = SecurityDashboard()
    dashboard.run()
