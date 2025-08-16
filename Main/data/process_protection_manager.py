# process_protection_manager.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import os
import json
import threading
import time
import subprocess
import platform
from datetime import datetime


class ProcessProtectionManager:
    """Advanced Process Protection and Management System"""
    
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🛡️ KeySentinel Process Protection Manager")
        self.window.geometry("1000x700")
        self.window.configure(bg="#0a0a0a")
        
        # Protection state
        self.protection_active = False
        self.monitoring_thread = None
        
        # Configuration
        self.config_file = "process_protection_config.json"
        self.whitelist = set()
        self.blacklist = set()
        self.quarantined_processes = {}
        self.protection_rules = []
        
        # Process monitoring
        self.process_history = {}
        self.suspicious_behavior = {}
        
        self.load_configuration()
        self.setup_ui()

    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.window, bg="#1a1a1a", relief="raised", bd=2)
        header_frame.pack(fill="x", padx=5, pady=5)
        
        title = tk.Label(header_frame, text="🛡️ Process Protection Manager", 
                        font=("Helvetica", 18, "bold"), fg="#00ff41", bg="#1a1a1a")
        title.pack(side="left", padx=10, pady=10)
        
        # Protection status
        self.protection_status = tk.Label(header_frame, text="🔴 PROTECTION OFF", 
                                        font=("Helvetica", 12, "bold"), 
                                        fg="#ff4444", bg="#1a1a1a")
        self.protection_status.pack(side="right", padx=10, pady=10)
        
        # Control panel
        control_frame = tk.Frame(self.window, bg="#1a1a1a", relief="raised", bd=2)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        self.protection_btn = tk.Button(control_frame, text="🟢 Enable Protection", 
                                      font=("Helvetica", 11, "bold"), bg="#00aa00", fg="white",
                                      command=self.toggle_protection, width=18)
        self.protection_btn.pack(side="left", padx=10, pady=5)
        
        tk.Button(control_frame, text="🔄 Refresh Processes", 
                 font=("Helvetica", 11), bg="#0066aa", fg="white",
                 command=self.refresh_processes, width=16).pack(side="left", padx=5, pady=5)
        
        tk.Button(control_frame, text="🚫 Terminate Process", 
                 font=("Helvetica", 11), bg="#aa0000", fg="white",
                 command=self.terminate_selected, width=16).pack(side="left", padx=5, pady=5)
        
        tk.Button(control_frame, text="⚙️ Settings", 
                 font=("Helvetica", 11), bg="#666", fg="white",
                 command=self.open_settings, width=10).pack(side="left", padx=5, pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Configure dark theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#1a1a1a', borderwidth=0)
        style.configure('TNotebook.Tab', background='#333', foreground='white', 
                       padding=[12, 8], font=('Helvetica', 10))
        style.map('TNotebook.Tab', background=[('selected', '#00aa00')])
        
        self.setup_processes_tab()
        self.setup_whitelist_tab()
        self.setup_quarantine_tab()
        self.setup_rules_tab()
        self.setup_monitoring_tab()

    def setup_processes_tab(self):
        """Active processes monitoring tab"""
        proc_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(proc_frame, text="🔍 Processes")
        
        # Process table
        columns = ("PID", "Name", "CPU%", "Memory%", "Status", "Path", "Risk", "Action")
        self.process_tree = ttk.Treeview(proc_frame, columns=columns, show="headings")
        
        # Configure columns
        column_widths = {"PID": 60, "Name": 120, "CPU%": 60, "Memory%": 70, 
                        "Status": 80, "Path": 200, "Risk": 70, "Action": 80}
        
        for col in columns:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        proc_v_scroll = tk.Scrollbar(proc_frame, orient="vertical", command=self.process_tree.yview)
        proc_h_scroll = tk.Scrollbar(proc_frame, orient="horizontal", command=self.process_tree.xview)
        
        self.process_tree.configure(yscrollcommand=proc_v_scroll.set, 
                                  xscrollcommand=proc_h_scroll.set)
        
        # Pack
        self.process_tree.pack(side="left", fill="both", expand=True)
        proc_v_scroll.pack(side="right", fill="y")
        proc_h_scroll.pack(side="bottom", fill="x")
        
        # Context menu
        self.process_menu = tk.Menu(self.window, tearoff=0, bg="#1a1a1a", fg="white")
        self.process_menu.add_command(label="Terminate Process", command=self.terminate_selected)
        self.process_menu.add_command(label="Add to Whitelist", command=self.add_to_whitelist)
        self.process_menu.add_command(label="Add to Blacklist", command=self.add_to_blacklist)
        self.process_menu.add_command(label="Quarantine", command=self.quarantine_selected)
        self.process_menu.add_command(label="Process Details", command=self.show_process_details)
        
        self.process_tree.bind("<Button-3>", self.show_context_menu)
        
        # Configure treeview style
        style = ttk.Style()
        style.configure("Treeview", background="#1a1a1a", foreground="white", 
                       fieldbackground="#1a1a1a", rowheight=25)
        style.map("Treeview", background=[("selected", "#00aa00")])

    def setup_whitelist_tab(self):
        """Whitelist management tab"""
        whitelist_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(whitelist_frame, text="✅ Whitelist")
        
        # Controls
        control_frame = tk.Frame(whitelist_frame, bg="#0a0a0a")
        control_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Button(control_frame, text="➕ Add Process", font=("Helvetica", 10), 
                 bg="#00aa00", fg="white", command=self.add_whitelist_dialog, width=12).pack(side="left", padx=5)
        
        tk.Button(control_frame, text="➖ Remove Selected", font=("Helvetica", 10), 
                 bg="#aa0000", fg="white", command=self.remove_whitelist_selected, width=15).pack(side="left", padx=5)
        
        tk.Button(control_frame, text="📂 Import List", font=("Helvetica", 10), 
                 bg="#0066aa", fg="white", command=self.import_whitelist, width=12).pack(side="left", padx=5)
        
        tk.Button(control_frame, text="💾 Export List", font=("Helvetica", 10), 
                 bg="#aa6600", fg="white", command=self.export_whitelist, width=12).pack(side="left", padx=5)
        
        # Whitelist display
        self.whitelist_listbox = tk.Listbox(whitelist_frame, bg="#1a1a1a", fg="white", 
                                          font=("Consolas", 10), selectmode=tk.EXTENDED)
        whitelist_scroll = tk.Scrollbar(whitelist_frame, command=self.whitelist_listbox.yview)
        self.whitelist_listbox.config(yscrollcommand=whitelist_scroll.set)
        
        self.whitelist_listbox.pack(side="left", fill="both", expand=True, padx=10, pady=5)
        whitelist_scroll.pack(side="right", fill="y")

    def setup_quarantine_tab(self):
        """Quarantine management tab"""
        quarantine_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(quarantine_frame, text="🔒 Quarantine")
        
        # Quarantine info
        info_frame = tk.LabelFrame(quarantine_frame, text="Quarantine Information", 
                                 font=("Helvetica", 12, "bold"),
                                 fg="#00ff41", bg="#1a1a1a", bd=2)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        info_text = """Quarantined processes are suspended and isolated from the system.
They cannot access network resources or file system operations.
Use this feature for suspicious processes that need investigation."""
        
        tk.Label(info_frame, text=info_text, font=("Helvetica", 10), 
                fg="#888", bg="#1a1a1a", justify="left").pack(padx=10, pady=10)
        
        # Quarantine controls
        q_control_frame = tk.Frame(quarantine_frame, bg="#0a0a0a")
        q_control_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Button(q_control_frame, text="🔓 Release Selected", font=("Helvetica", 10), 
                 bg="#00aa00", fg="white", command=self.release_quarantined, width=15).pack(side="left", padx=5)
        
        tk.Button(q_control_frame, text="🗑️ Delete Quarantined", font=("Helvetica", 10), 
                 bg="#aa0000", fg="white", command=self.delete_quarantined, width=16).pack(side="left", padx=5)
        
        tk.Button(q_control_frame, text="📋 Quarantine Report", font=("Helvetica", 10), 
                 bg="#0066aa", fg="white", command=self.generate_quarantine_report, width=16).pack(side="left", padx=5)
        
        # Quarantined processes table
        q_columns = ("PID", "Process Name", "Quarantine Time", "Reason", "Original Path")
        self.quarantine_tree = ttk.Treeview(quarantine_frame, columns=q_columns, show="headings")
        
        for col in q_columns:
            self.quarantine_tree.heading(col, text=col)
            self.quarantine_tree.column(col, width=120)
        
        q_scroll = tk.Scrollbar(quarantine_frame, orient="vertical", command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscrollcommand=q_scroll.set)
        
        self.quarantine_tree.pack(side="left", fill="both", expand=True, padx=10, pady=5)
        q_scroll.pack(side="right", fill="y")

    def setup_rules_tab(self):
        """Protection rules configuration tab"""
        rules_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(rules_frame, text="⚖️ Rules")
        
        # Rules explanation
        explanation_frame = tk.LabelFrame(rules_frame, text="Protection Rules", 
                                        font=("Helvetica", 12, "bold"),
                                        fg="#00ff41", bg="#1a1a1a", bd=2)
        explanation_frame.pack(fill="x", padx=10, pady=5)
        
        explanation = """Configure automatic protection rules for process behavior:
• Memory usage thresholds
• CPU usage limits  
• Network access restrictions
• File system access controls
• Process injection detection"""
        
        tk.Label(explanation_frame, text=explanation, font=("Helvetica", 10), 
                fg="#888", bg="#1a1a1a", justify="left").pack(padx=10, pady=10)
        
        # Rule creation
        create_frame = tk.LabelFrame(rules_frame, text="Create New Rule", 
                                   font=("Helvetica", 12, "bold"),
                                   fg="#00ff41", bg="#1a1a1a", bd=2)
        create_frame.pack(fill="x", padx=10, pady=5)
        
        # Rule type selection
        rule_type_frame = tk.Frame(create_frame, bg="#1a1a1a")
        rule_type_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(rule_type_frame, text="Rule Type:", font=("Helvetica", 10), 
                fg="white", bg="#1a1a1a").pack(side="left")
        
        self.rule_type_var = tk.StringVar(value="CPU Limit")
        rule_types = ["CPU Limit", "Memory Limit", "Process Name", "File Access", "Network Access"]
        rule_type_menu = tk.OptionMenu(rule_type_frame, self.rule_type_var, *rule_types)
        rule_type_menu.config(bg="#333", fg="white", font=("Helvetica", 9))
        rule_type_menu.pack(side="left", padx=10)
        
        # Rule parameters
        param_frame = tk.Frame(create_frame, bg="#1a1a1a")
        param_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(param_frame, text="Parameter:", font=("Helvetica", 10), 
                fg="white", bg="#1a1a1a").pack(side="left")
        
        self.rule_param_var = tk.StringVar()
        param_entry = tk.Entry(param_frame, textvariable=self.rule_param_var, 
                             bg="#333", fg="white", font=("Helvetica", 10), width=20)
        param_entry.pack(side="left", padx=10)
        
        # Action selection
        action_frame = tk.Frame(create_frame, bg="#1a1a1a")
        action_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(action_frame, text="Action:", font=("Helvetica", 10), 
                fg="white", bg="#1a1a1a").pack(side="left")
        
        self.rule_action_var = tk.StringVar(value="Alert")
        actions = ["Alert", "Terminate", "Quarantine", "Suspend"]
        action_menu = tk.OptionMenu(action_frame, self.rule_action_var, *actions)
        action_menu.config(bg="#333", fg="white", font=("Helvetica", 9))
        action_menu.pack(side="left", padx=10)
        
        tk.Button(action_frame, text="➕ Add Rule", font=("Helvetica", 10), 
                 bg="#00aa00", fg="white", command=self.add_protection_rule, width=12).pack(side="left", padx=20)
        
        # Existing rules display
        rules_display_frame = tk.LabelFrame(rules_frame, text="Active Protection Rules", 
                                          font=("Helvetica", 12, "bold"),
                                          fg="#00ff41", bg="#1a1a1a", bd=2)
        rules_display_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        rules_columns = ("Type", "Parameter", "Action", "Enabled", "Triggered")
        self.rules_tree = ttk.Treeview(rules_display_frame, columns=rules_columns, show="headings")
        
        for col in rules_columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=100)
        
        rules_scroll = tk.Scrollbar(rules_display_frame, orient="vertical", command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=rules_scroll.set)
        
        self.rules_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        rules_scroll.pack(side="right", fill="y")

    def setup_monitoring_tab(self):
        """Real-time monitoring and alerts tab"""
        monitor_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(monitor_frame, text="📡 Monitoring")
        
        # Real-time stats
        stats_frame = tk.LabelFrame(monitor_frame, text="System Statistics", 
                                  font=("Helvetica", 12, "bold"),
                                  fg="#00ff41", bg="#1a1a1a", bd=2)
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        self.stats_label = tk.Label(stats_frame, text="Loading statistics...", 
                                  font=("Consolas", 10), fg="white", bg="#1a1a1a")
        self.stats_label.pack(padx=10, pady=10)
        
        # Activity log
        log_frame = tk.LabelFrame(monitor_frame, text="Activity Log", 
                                font=("Helvetica", 12, "bold"),
                                fg="#00ff41", bg="#1a1a1a", bd=2)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.activity_log = tk.Text(log_frame, bg="#0a0a0a", fg="#00ff41", 
                                  font=("Consolas", 9), insertbackground="white")
        log_scroll = tk.Scrollbar(log_frame, command=self.activity_log.yview)
        self.activity_log.config(yscrollcommand=log_scroll.set)
        
        self.activity_log.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        log_scroll.pack(side="right", fill="y")

    def load_configuration(self):
        """Load protection configuration"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.whitelist = set(config.get('whitelist', []))
                    self.blacklist = set(config.get('blacklist', []))
                    self.protection_rules = config.get('rules', [])
        except Exception as e:
            self.log_activity(f"Error loading configuration: {str(e)}")

    def save_configuration(self):
        """Save protection configuration"""
        try:
            config = {
                'whitelist': list(self.whitelist),
                'blacklist': list(self.blacklist),
                'rules': self.protection_rules
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            self.log_activity(f"Error saving configuration: {str(e)}")

    def toggle_protection(self):
        """Toggle process protection"""
        if not self.protection_active:
            self.protection_active = True
            self.protection_btn.config(text="🔴 Disable Protection", bg="#aa0000")
            self.protection_status.config(text="🟢 PROTECTION ON", fg="#00aa00")
            self.log_activity("Process protection enabled")
            
            # Start monitoring thread
            self.monitoring_thread = threading.Thread(target=self.monitor_processes, daemon=True)
            self.monitoring_thread.start()
        else:
            self.protection_active = False
            self.protection_btn.config(text="🟢 Enable Protection", bg="#00aa00")
            self.protection_status.config(text="🔴 PROTECTION OFF", fg="#ff4444")
            self.log_activity("Process protection disabled")

    def monitor_processes(self):
        """Monitor processes in background"""
        while self.protection_active:
            try:
                self.check_protection_rules()
                self.update_system_stats()
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                self.log_activity(f"Monitoring error: {str(e)}")
                time.sleep(5)

    def refresh_processes(self):
        """Refresh the process list"""
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        try:
            for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'exe']):
                try:
                    pid = process.info['pid']
                    name = process.info['name']
                    cpu = f"{process.info['cpu_percent']:.1f}%"
                    memory = f"{process.info['memory_percent']:.1f}%"
                    status = process.info['status']
                    path = process.info['exe'] or "N/A"
                    
                    # Assess risk
                    risk_level = self.assess_process_risk(process.info)
                    
                    # Determine action status
                    action = "None"
                    if name in self.whitelist:
                        action = "Whitelisted"
                    elif name in self.blacklist:
                        action = "Blacklisted"
                    elif pid in self.quarantined_processes:
                        action = "Quarantined"
                    
                    # Insert into tree
                    item = self.process_tree.insert("", tk.END, values=(
                        pid, name, cpu, memory, status, path, risk_level, action
                    ))
                    
                    # Color code by risk
                    if risk_level == "High":
                        self.process_tree.set(item, "Risk", "🔴 High")
                    elif risk_level == "Medium":
                        self.process_tree.set(item, "Risk", "🟡 Medium")
                    else:
                        self.process_tree.set(item, "Risk", "🟢 Low")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.log_activity(f"Error refreshing processes: {str(e)}")

    def assess_process_risk(self, process_info):
        """Assess the risk level of a process"""
        risk_score = 0
        name = process_info['name'].lower()
        
        # Check against blacklist
        if name in self.blacklist:
            return "High"
        
        # Check against whitelist
        if name in self.whitelist:
            return "Low"
        
        # Suspicious names
        suspicious_keywords = ['keylog', 'logger', 'spy', 'stealth', 'hidden', 'rat', 'trojan']
        if any(keyword in name for keyword in suspicious_keywords):
            risk_score += 3
        
        # High resource usage
        try:
            if process_info['cpu_percent'] > 80:
                risk_score += 2
            if process_info['memory_percent'] > 50:
                risk_score += 1
        except:
            pass
        
        # Determine risk level
        if risk_score >= 3:
            return "High"
        elif risk_score >= 1:
            return "Medium"
        else:
            return "Low"

    def check_protection_rules(self):
        """Check active protection rules"""
        for rule in self.protection_rules:
            if not rule.get('enabled', True):
                continue
            
            try:
                self.evaluate_rule(rule)
            except Exception as e:
                self.log_activity(f"Error evaluating rule {rule['type']}: {str(e)}")

    def evaluate_rule(self, rule):
        """Evaluate a specific protection rule"""
        rule_type = rule['type']
        parameter = rule['parameter']
        action = rule['action']
        
        for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                triggered = False
                
                if rule_type == "CPU Limit":
                    if process.info['cpu_percent'] > float(parameter):
                        triggered = True
                
                elif rule_type == "Memory Limit":
                    if process.info['memory_percent'] > float(parameter):
                        triggered = True
                
                elif rule_type == "Process Name":
                    if parameter.lower() in process.info['name'].lower():
                        triggered = True
                
                if triggered:
                    self.execute_rule_action(process, rule, action)
                    rule['triggered'] = rule.get('triggered', 0) + 1
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def execute_rule_action(self, process, rule, action):
        """Execute the action specified by a protection rule"""
        process_name = process.info['name']
        pid = process.info['pid']
        
        if action == "Alert":
            self.log_activity(f"ALERT: Rule '{rule['type']}' triggered by {process_name} (PID: {pid})")
        
        elif action == "Terminate":
            try:
                psutil.Process(pid).terminate()
                self.log_activity(f"TERMINATED: {process_name} (PID: {pid}) due to rule violation")
            except Exception as e:
                self.log_activity(f"Failed to terminate {process_name}: {str(e)}")
        
        elif action == "Quarantine":
            self.quarantine_process(pid, f"Rule violation: {rule['type']}")
        
        elif action == "Suspend":
            try:
                psutil.Process(pid).suspend()
                self.log_activity(f"SUSPENDED: {process_name} (PID: {pid}) due to rule violation")
            except Exception as e:
                self.log_activity(f"Failed to suspend {process_name}: {str(e)}")

    def show_context_menu(self, event):
        """Show context menu for process tree"""
        try:
            self.process_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.process_menu.grab_release()

    def terminate_selected(self):
        """Terminate selected process"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to terminate.")
            return
        
        item = selection[0]
        pid = int(self.process_tree.item(item)['values'][0])
        name = self.process_tree.item(item)['values'][1]
        
        if messagebox.askyesno("Confirm Termination", f"Terminate process '{name}' (PID: {pid})?"):
            try:
                psutil.Process(pid).terminate()
                self.log_activity(f"Process {name} (PID: {pid}) terminated")
                self.refresh_processes()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to terminate process: {str(e)}")

    def add_to_whitelist(self):
        """Add selected process to whitelist"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process.")
            return
        
        item = selection[0]
        name = self.process_tree.item(item)['values'][1]
        
        self.whitelist.add(name)
        self.whitelist_listbox.insert(tk.END, name)
        self.save_configuration()
        self.log_activity(f"Added {name} to whitelist")

    def add_to_blacklist(self):
        """Add selected process to blacklist"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process.")
            return
        
        item = selection[0]
        name = self.process_tree.item(item)['values'][1]
        
        self.blacklist.add(name)
        self.save_configuration()
        self.log_activity(f"Added {name} to blacklist")

    def quarantine_selected(self):
        """Quarantine selected process"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to quarantine.")
            return
        
        item = selection[0]
        pid = int(self.process_tree.item(item)['values'][0])
        name = self.process_tree.item(item)['values'][1]
        
        reason = tk.simpledialog.askstring("Quarantine Reason", "Enter reason for quarantine:")
        if reason:
            self.quarantine_process(pid, reason)

    def quarantine_process(self, pid, reason):
        """Quarantine a process"""
        try:
            process = psutil.Process(pid)
            name = process.name()
            
            # Suspend the process
            process.suspend()
            
            # Add to quarantine list
            self.quarantined_processes[pid] = {
                'name': name,
                'quarantine_time': datetime.now().isoformat(),
                'reason': reason,
                'original_path': process.exe()
            }
            
            # Update quarantine display
            self.update_quarantine_display()
            
            self.log_activity(f"Process {name} (PID: {pid}) quarantined - Reason: {reason}")
            
        except Exception as e:
            self.log_activity(f"Failed to quarantine process {pid}: {str(e)}")

    def update_quarantine_display(self):
        """Update the quarantine display"""
        # Clear existing items
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        
        # Add quarantined processes
        for pid, info in self.quarantined_processes.items():
            self.quarantine_tree.insert("", tk.END, values=(
                pid, info['name'], info['quarantine_time'], 
                info['reason'], info['original_path']
            ))

    def show_process_details(self):
        """Show detailed information about selected process"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process.")
            return
        
        item = selection[0]
        pid = int(self.process_tree.item(item)['values'][0])
        
        try:
            process = psutil.Process(pid)
            
            details_window = tk.Toplevel(self.window)
            details_window.title(f"Process Details - {process.name()}")
            details_window.geometry("600x500")
            details_window.configure(bg="#0a0a0a")
            
            details_text = tk.Text(details_window, bg="#0a0a0a", fg="#00ff41", 
                                 font=("Consolas", 10))
            details_scroll = tk.Scrollbar(details_window, command=details_text.yview)
            details_text.config(yscrollcommand=details_scroll.set)
            
            # Gather process information
            info = f"""Process Information:
            
PID: {pid}
Name: {process.name()}
Status: {process.status()}
CPU Percent: {process.cpu_percent():.2f}%
Memory Percent: {process.memory_percent():.2f}%
Create Time: {datetime.fromtimestamp(process.create_time())}
Executable: {process.exe()}
Command Line: {' '.join(process.cmdline())}
Working Directory: {process.cwd()}
Parent PID: {process.ppid()}

Memory Info:
{process.memory_info()}

CPU Times:
{process.cpu_times()}

Open Files:
"""
            
            # Add open files
            try:
                for file in process.open_files():
                    info += f"  {file.path}\n"
            except:
                info += "  Access denied\n"
            
            # Add network connections
            info += "\nNetwork Connections:\n"
            try:
                for conn in process.connections():
                    info += f"  {conn}\n"
            except:
                info += "  Access denied\n"
            
            details_text.insert("1.0", info)
            details_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
            details_scroll.pack(side="right", fill="y")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get process details: {str(e)}")

    def add_whitelist_dialog(self):
        """Show dialog to add process to whitelist"""
        process_name = tk.simpledialog.askstring("Add to Whitelist", "Enter process name:")
        if process_name:
            self.whitelist.add(process_name)
            self.whitelist_listbox.insert(tk.END, process_name)
            self.save_configuration()
            self.log_activity(f"Added {process_name} to whitelist")

    def remove_whitelist_selected(self):
        """Remove selected items from whitelist"""
        selection = self.whitelist_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select items to remove.")
            return
        
        for index in reversed(selection):
            process_name = self.whitelist_listbox.get(index)
            self.whitelist.discard(process_name)
            self.whitelist_listbox.delete(index)
        
        self.save_configuration()
        self.log_activity("Removed selected items from whitelist")

    def import_whitelist(self):
        """Import whitelist from file"""
        filename = filedialog.askopenfilename(
            title="Import Whitelist",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    if filename.endswith('.json'):
                        data = json.load(f)
                        new_items = data if isinstance(data, list) else data.get('whitelist', [])
                    else:
                        new_items = f.read().strip().split('\n')
                
                for item in new_items:
                    if item.strip():
                        self.whitelist.add(item.strip())
                        self.whitelist_listbox.insert(tk.END, item.strip())
                
                self.save_configuration()
                self.log_activity(f"Imported whitelist from {filename}")
                
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import whitelist: {str(e)}")

    def export_whitelist(self):
        """Export whitelist to file"""
        filename = filedialog.asksaveasfilename(
            title="Export Whitelist",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    if filename.endswith('.json'):
                        json.dump(list(self.whitelist), f, indent=2)
                    else:
                        for item in sorted(self.whitelist):
                            f.write(f"{item}\n")
                
                self.log_activity(f"Exported whitelist to {filename}")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export whitelist: {str(e)}")

    def add_protection_rule(self):
        """Add a new protection rule"""
        rule_type = self.rule_type_var.get()
        parameter = self.rule_param_var.get()
        action = self.rule_action_var.get()
        
        if not parameter:
            messagebox.showwarning("Invalid Input", "Please enter a parameter value.")
            return
        
        rule = {
            'type': rule_type,
            'parameter': parameter,
            'action': action,
            'enabled': True,
            'triggered': 0
        }
        
        self.protection_rules.append(rule)
        self.save_configuration()
        self.update_rules_display()
        self.log_activity(f"Added protection rule: {rule_type} -> {action}")
        
        # Clear input fields
        self.rule_param_var.set("")

    def update_rules_display(self):
        """Update the rules display"""
        # Clear existing items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        # Add rules
        for rule in self.protection_rules:
            self.rules_tree.insert("", tk.END, values=(
                rule['type'], rule['parameter'], rule['action'],
                "✅" if rule['enabled'] else "❌", rule.get('triggered', 0)
            ))

    def release_quarantined(self):
        """Release selected quarantined processes"""
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select processes to release.")
            return
        
        for item in selection:
            pid = int(self.quarantine_tree.item(item)['values'][0])
            
            try:
                process = psutil.Process(pid)
                process.resume()
                
                del self.quarantined_processes[pid]
                self.log_activity(f"Released process PID {pid} from quarantine")
                
            except Exception as e:
                self.log_activity(f"Failed to release process PID {pid}: {str(e)}")
        
        self.update_quarantine_display()

    def delete_quarantined(self):
        """Delete selected quarantined processes"""
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select processes to delete.")
            return
        
        if messagebox.askyesno("Confirm Deletion", "This will permanently terminate the selected processes. Continue?"):
            for item in selection:
                pid = int(self.quarantine_tree.item(item)['values'][0])
                
                try:
                    process = psutil.Process(pid)
                    process.terminate()
                    
                    del self.quarantined_processes[pid]
                    self.log_activity(f"Deleted quarantined process PID {pid}")
                    
                except Exception as e:
                    self.log_activity(f"Failed to delete process PID {pid}: {str(e)}")
            
            self.update_quarantine_display()

    def generate_quarantine_report(self):
        """Generate a quarantine activity report"""
        report = f"""KeySentinel Process Quarantine Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Currently Quarantined Processes: {len(self.quarantined_processes)}

Quarantine Details:
"""
        
        for pid, info in self.quarantined_processes.items():
            report += f"""
PID: {pid}
Process: {info['name']}
Quarantined: {info['quarantine_time']}
Reason: {info['reason']}
Original Path: {info['original_path']}
{'-'*50}"""
        
        # Show report in new window
        report_window = tk.Toplevel(self.window)
        report_window.title("Quarantine Report")
        report_window.geometry("700x500")
        report_window.configure(bg="#0a0a0a")
        
        report_text = tk.Text(report_window, bg="#0a0a0a", fg="#00ff41", 
                            font=("Consolas", 10))
        report_scroll = tk.Scrollbar(report_window, command=report_text.yview)
        report_text.config(yscrollcommand=report_scroll.set)
        
        report_text.insert("1.0", report)
        report_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        report_scroll.pack(side="right", fill="y")

    def update_system_stats(self):
        """Update system statistics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            processes = len(psutil.pids())
            
            stats = f"""System Resources:
CPU Usage: {cpu_percent:.1f}%
Memory Usage: {memory.percent:.1f}% ({memory.used // (1024**3):.1f}GB / {memory.total // (1024**3):.1f}GB)
Disk Usage: {disk.percent:.1f}%
Active Processes: {processes}
Protected Processes: {len(self.whitelist)}
Quarantined: {len(self.quarantined_processes)}
Protection Rules: {len(self.protection_rules)}"""
            
            self.stats_label.config(text=stats)
            
        except Exception as e:
            self.stats_label.config(text=f"Error retrieving stats: {str(e)}")

    def open_settings(self):
        """Open settings window"""
        settings_window = tk.Toplevel(self.window)
        settings_window.title("Protection Settings")
        settings_window.geometry("400x300")
        settings_window.configure(bg="#0a0a0a")
        
        # Settings content would go here
        tk.Label(settings_window, text="Protection Settings", 
                font=("Helvetica", 16, "bold"), fg="#00ff41", bg="#0a0a0a").pack(pady=20)
        
        tk.Label(settings_window, text="Settings panel coming soon...", 
                font=("Helvetica", 12), fg="#888", bg="#0a0a0a").pack(pady=20)

    def log_activity(self, message):
        """Log activity to the monitoring tab"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.activity_log.insert(tk.END, formatted_message)
        self.activity_log.see(tk.END)

    def run(self):
        """Start the process protection manager"""
        self.refresh_processes()
        self.update_quarantine_display()
        self.update_rules_display()
        
        # Load whitelist into display
        for item in sorted(self.whitelist):
            self.whitelist_listbox.insert(tk.END, item)
        
        # Start periodic updates
        def periodic_update():
            if self.protection_active:
                self.refresh_processes()
                self.update_system_stats()
            self.window.after(5000, periodic_update)  # Update every 5 seconds
        
        periodic_update()
        self.window.mainloop()


# Run as standalone
if __name__ == "__main__":
    manager = ProcessProtectionManager()
    manager.run()
