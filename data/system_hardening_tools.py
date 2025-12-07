# system_hardening_tools.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import platform
import os
import winreg
import sys
from datetime import datetime
import json


class SystemHardeningTools:
    """Advanced System Hardening and Security Configuration Tools"""
    
    def __init__(self):
        self.window = tk.Tk()
        try:
            import os
            icon_path = os.path.join(os.path.dirname(__file__), "KeySentinel_logo.ico")
            if os.path.exists(icon_path):
                self.window.iconbitmap(icon_path)
            else:
                self.window.iconbitmap("KeySentinel_logo.ico")
        except Exception:
            try:
                self.window.iconbitmap(default="KeySentinel_logo.ico")
            except Exception:
                pass
        self.window.title("🔒 KeySentinel System Hardening Tools")
        self.window.geometry("1100x800")
        self.window.configure(bg="#0a0a0a")
        
        # Hardening status tracking
        self.hardening_status = {}
        self.backup_registry = {}
        
        self.setup_ui()
        self.check_admin_privileges()

    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.window, bg="#1a1a1a", relief="raised", bd=2)
        header_frame.pack(fill="x", padx=5, pady=5)
        
        title = tk.Label(header_frame, text="🔒 System Hardening Tools", 
                        font=("Helvetica", 18, "bold"), fg="#00ff41", bg="#1a1a1a")
        title.pack(side="left", padx=10, pady=10)
        
        # Admin status
        self.admin_status = tk.Label(header_frame, text="⚠️ ADMIN REQUIRED", 
                                   font=("Helvetica", 12, "bold"), 
                                   fg="#ffaa00", bg="#1a1a1a")
        self.admin_status.pack(side="right", padx=10, pady=10)
        
        # Warning frame
        warning_frame = tk.Frame(self.window, bg="#2a1a1a", relief="raised", bd=2)
        warning_frame.pack(fill="x", padx=5, pady=5)
        
        warning_text = """⚠️  WARNING: These tools modify system security settings. Create a system restore point before proceeding.
Some changes may require a system restart to take effect. Use with caution on production systems."""
        
        tk.Label(warning_frame, text=warning_text, font=("Helvetica", 10), 
                fg="#ffaa00", bg="#2a1a1a", justify="left").pack(padx=10, pady=10)
        
        # Create notebook for categories
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Configure dark theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#1a1a1a', borderwidth=0)
        style.configure('TNotebook.Tab', background='#333', foreground='white', 
                       padding=[12, 8], font=('Helvetica', 10))
        style.map('TNotebook.Tab', background=[('selected', '#00aa00')])
        
        self.setup_registry_hardening_tab()
        self.setup_firewall_tab()
        self.setup_services_tab()
        self.setup_policies_tab()
        self.setup_audit_tab()
        self.setup_backup_restore_tab()

    def setup_registry_hardening_tab(self):
        """Registry security hardening tab"""
        reg_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(reg_frame, text="🔧 Registry Hardening")
        
        # Description
        desc_frame = tk.LabelFrame(reg_frame, text="Registry Security Hardening", 
                                 font=("Helvetica", 12, "bold"),
                                 fg="#00ff41", bg="#1a1a1a", bd=2)
        desc_frame.pack(fill="x", padx=10, pady=5)
        
        desc_text = """Configure Windows Registry settings to enhance security against keyloggers and malware:
• Disable autorun functionality
• Restrict process creation
• Enhance logging and monitoring
• Block common attack vectors"""
        
        tk.Label(desc_frame, text=desc_text, font=("Helvetica", 10), 
                fg="#888", bg="#1a1a1a", justify="left").pack(padx=10, pady=10)
        
        # Registry hardening options
        options_frame = tk.LabelFrame(reg_frame, text="Hardening Options", 
                                    font=("Helvetica", 12, "bold"),
                                    fg="#00ff41", bg="#1a1a1a", bd=2)
        options_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create two columns
        left_column = tk.Frame(options_frame, bg="#1a1a1a")
        left_column.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        right_column = tk.Frame(options_frame, bg="#1a1a1a")
        right_column.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # Left column options
        self.reg_options = {}
        
        reg_settings = [
            ("Disable AutoRun", "disable_autorun", "Prevents automatic execution of removable media"),
            ("Block USB Storage", "block_usb", "Restricts USB storage device access"),
            ("Disable Windows Script Host", "disable_wsh", "Blocks Windows Script Host execution"),
            ("Enhanced Process Logging", "enhanced_logging", "Enables detailed process creation logging"),
            ("Disable Remote Registry", "disable_remote_reg", "Prevents remote registry access"),
            ("Block Macro Execution", "block_macros", "Restricts Office macro execution"),
            ("Disable PowerShell v2", "disable_ps2", "Blocks legacy PowerShell version"),
            ("Enhanced UAC", "enhanced_uac", "Strengthens User Account Control"),
        ]
        
        for i, (name, key, desc) in enumerate(reg_settings):
            frame = left_column if i < 4 else right_column
            
            option_frame = tk.Frame(frame, bg="#2a2a2a", relief="raised", bd=1)
            option_frame.pack(fill="x", pady=5)
            
            var = tk.BooleanVar()
            self.reg_options[key] = var
            
            chk = tk.Checkbutton(option_frame, text=name, variable=var, 
                               font=("Helvetica", 11, "bold"), fg="white", bg="#2a2a2a",
                               selectcolor="#333", activebackground="#2a2a2a")
            chk.pack(anchor="w", padx=10, pady=5)
            
            desc_label = tk.Label(option_frame, text=desc, font=("Helvetica", 9), 
                                 fg="#888", bg="#2a2a2a", wraplength=250)
            desc_label.pack(anchor="w", padx=20, pady=(0, 5))
        
        # Control buttons
        control_frame = tk.Frame(reg_frame, bg="#0a0a0a")
        control_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Button(control_frame, text="✅ Apply Selected", font=("Helvetica", 12, "bold"), 
                 bg="#00aa00", fg="white", command=self.apply_registry_hardening, 
                 width=15).pack(side="left", padx=10)
        
        tk.Button(control_frame, text="🔍 Check Status", font=("Helvetica", 12), 
                 bg="#0066aa", fg="white", command=self.check_registry_status, 
                 width=12).pack(side="left", padx=5)
        
        tk.Button(control_frame, text="🔄 Restore Defaults", font=("Helvetica", 12), 
                 bg="#aa6600", fg="white", command=self.restore_registry_defaults, 
                 width=15).pack(side="left", padx=5)

    def setup_firewall_tab(self):
        """Windows Firewall configuration tab"""
        fw_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(fw_frame, text="🔥 Firewall Config")
        
        # Firewall status
        status_frame = tk.LabelFrame(fw_frame, text="Firewall Status", 
                                   font=("Helvetica", 12, "bold"),
                                   fg="#00ff41", bg="#1a1a1a", bd=2)
        status_frame.pack(fill="x", padx=10, pady=5)
        
        self.firewall_status_text = tk.Text(status_frame, height=6, bg="#0a0a0a", fg="#00ff41", 
                                          font=("Consolas", 10))
        self.firewall_status_text.pack(padx=10, pady=10, fill="x")
        
        # Firewall rules
        rules_frame = tk.LabelFrame(fw_frame, text="Advanced Firewall Rules", 
                                  font=("Helvetica", 12, "bold"),
                                  fg="#00ff41", bg="#1a1a1a", bd=2)
        rules_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Predefined security rules
        self.fw_rules = [
            ("Block Suspicious Ports", "block_ports", "Block common malware ports"),
            ("Restrict Outbound Connections", "restrict_outbound", "Whitelist-based outbound filtering"),
            ("Block P2P Protocols", "block_p2p", "Block peer-to-peer communication"),
            ("Enhanced Logging", "fw_logging", "Enable detailed firewall logging"),
            ("Block Remote Admin Tools", "block_remote_admin", "Block RDP, VNC, TeamViewer"),
            ("Restrict File Sharing", "restrict_sharing", "Block SMB/CIFS protocols"),
        ]
        
        for name, key, desc in self.fw_rules:
            rule_frame = tk.Frame(rules_frame, bg="#2a2a2a", relief="raised", bd=1)
            rule_frame.pack(fill="x", padx=10, pady=5)
            
            var = tk.BooleanVar()
            setattr(self, f"fw_{key}", var)
            
            chk = tk.Checkbutton(rule_frame, text=name, variable=var, 
                               font=("Helvetica", 11), fg="white", bg="#2a2a2a",
                               selectcolor="#333")
            chk.pack(side="left", padx=10, pady=5)
            
            tk.Label(rule_frame, text=desc, font=("Helvetica", 9), 
                    fg="#888", bg="#2a2a2a").pack(side="left", padx=20)
        
        # Control buttons
        fw_control_frame = tk.Frame(fw_frame, bg="#0a0a0a")
        fw_control_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Button(fw_control_frame, text="🔥 Configure Firewall", font=("Helvetica", 12, "bold"), 
                 bg="#ff4444", fg="white", command=self.configure_firewall, 
                 width=17).pack(side="left", padx=10)
        
        tk.Button(fw_control_frame, text="📊 Check Status", font=("Helvetica", 12), 
                 bg="#0066aa", fg="white", command=self.check_firewall_status, 
                 width=12).pack(side="left", padx=5)

    def setup_services_tab(self):
        """Windows Services hardening tab"""
        services_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(services_frame, text="⚙️ Services")
        
        # Services description
        desc_frame = tk.LabelFrame(services_frame, text="Windows Services Hardening", 
                                 font=("Helvetica", 12, "bold"),
                                 fg="#00ff41", bg="#1a1a1a", bd=2)
        desc_frame.pack(fill="x", padx=10, pady=5)
        
        desc_text = """Disable unnecessary Windows services that could be exploited by malware.
Only services that are commonly targeted or unnecessary for security are shown."""
        
        tk.Label(desc_frame, text=desc_text, font=("Helvetica", 10), 
                fg="#888", bg="#1a1a1a").pack(padx=10, pady=10)
        
        # Services list
        services_list_frame = tk.LabelFrame(services_frame, text="Services to Harden", 
                                          font=("Helvetica", 12, "bold"),
                                          fg="#00ff41", bg="#1a1a1a", bd=2)
        services_list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Services table
        columns = ("Service Name", "Display Name", "Current Status", "Recommended", "Action")
        self.services_tree = ttk.Treeview(services_list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.services_tree.heading(col, text=col)
            self.services_tree.column(col, width=120)
        
        services_scroll = tk.Scrollbar(services_list_frame, orient="vertical", 
                                     command=self.services_tree.yview)
        self.services_tree.configure(yscrollcommand=services_scroll.set)
        
        self.services_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        services_scroll.pack(side="right", fill="y")
        
        # Control buttons
        services_control = tk.Frame(services_frame, bg="#0a0a0a")
        services_control.pack(fill="x", padx=10, pady=10)
        
        tk.Button(services_control, text="🔄 Refresh Services", font=("Helvetica", 11), 
                 bg="#0066aa", fg="white", command=self.refresh_services, 
                 width=15).pack(side="left", padx=10)
        
        tk.Button(services_control, text="⚙️ Apply Recommendations", font=("Helvetica", 11, "bold"), 
                 bg="#aa6600", fg="white", command=self.apply_service_hardening, 
                 width=20).pack(side="left", padx=5)

    def setup_policies_tab(self):
        """Security policies configuration tab"""
        policies_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(policies_frame, text="📋 Security Policies")
        
        # Local security policies
        policies_desc = tk.LabelFrame(policies_frame, text="Local Security Policies", 
                                    font=("Helvetica", 12, "bold"),
                                    fg="#00ff41", bg="#1a1a1a", bd=2)
        policies_desc.pack(fill="x", padx=10, pady=5)
        
        desc = """Configure Windows Local Security Policy settings for enhanced protection:
• Account lockout policies
• Password policies  
• Audit policies
• User rights assignments"""
        
        tk.Label(policies_desc, text=desc, font=("Helvetica", 10), 
                fg="#888", bg="#1a1a1a").pack(padx=10, pady=10)
        
        # Policy configuration
        policy_config = tk.LabelFrame(policies_frame, text="Policy Configuration", 
                                    font=("Helvetica", 12, "bold"),
                                    fg="#00ff41", bg="#1a1a1a", bd=2)
        policy_config.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Policy options
        policy_notebook = ttk.Notebook(policy_config)
        policy_notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Account policies
        account_frame = tk.Frame(policy_notebook, bg="#1a1a1a")
        policy_notebook.add(account_frame, text="Account Policies")
        
        # Password policies
        password_frame = tk.Frame(policy_notebook, bg="#1a1a1a")
        policy_notebook.add(password_frame, text="Password Policies")
        
        # Audit policies
        audit_frame = tk.Frame(policy_notebook, bg="#1a1a1a")
        policy_notebook.add(audit_frame, text="Audit Policies")

    def setup_audit_tab(self):
        """System audit and monitoring tab"""
        audit_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(audit_frame, text="🔍 System Audit")
        
        # Current security status
        status_frame = tk.LabelFrame(audit_frame, text="Security Status Assessment", 
                                   font=("Helvetica", 12, "bold"),
                                   fg="#00ff41", bg="#1a1a1a", bd=2)
        status_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.audit_text = scrolledtext.ScrolledText(status_frame, bg="#0a0a0a", fg="#00ff41", 
                                                  font=("Consolas", 10))
        self.audit_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Control buttons
        audit_control = tk.Frame(audit_frame, bg="#0a0a0a")
        audit_control.pack(fill="x", padx=10, pady=10)
        
        tk.Button(audit_control, text="🔍 Run Security Audit", font=("Helvetica", 12, "bold"), 
                 bg="#00aa00", fg="white", command=self.run_security_audit, 
                 width=18).pack(side="left", padx=10)
        
        tk.Button(audit_control, text="📊 Generate Report", font=("Helvetica", 12), 
                 bg="#0066aa", fg="white", command=self.generate_audit_report, 
                 width=15).pack(side="left", padx=5)
        
        tk.Button(audit_control, text="🧹 Clear Log", font=("Helvetica", 12), 
                 bg="#666", fg="white", command=self.clear_audit_log, 
                 width=10).pack(side="left", padx=5)

    def setup_backup_restore_tab(self):
        """Backup and restore tab"""
        backup_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(backup_frame, text="💾 Backup/Restore")
        
        # Backup information
        backup_info = tk.LabelFrame(backup_frame, text="Configuration Backup", 
                                  font=("Helvetica", 12, "bold"),
                                  fg="#00ff41", bg="#1a1a1a", bd=2)
        backup_info.pack(fill="x", padx=10, pady=5)
        
        info_text = """Create backups of your system configuration before applying hardening measures.
This allows you to restore original settings if needed."""
        
        tk.Label(backup_info, text=info_text, font=("Helvetica", 10), 
                fg="#888", bg="#1a1a1a").pack(padx=10, pady=10)
        
        # Backup controls
        backup_controls = tk.Frame(backup_frame, bg="#0a0a0a")
        backup_controls.pack(fill="x", padx=10, pady=10)
        
        tk.Button(backup_controls, text="💾 Create Backup", font=("Helvetica", 12, "bold"), 
                 bg="#00aa00", fg="white", command=self.create_system_backup, 
                 width=15).pack(side="left", padx=10)
        
        tk.Button(backup_controls, text="🔄 Restore Backup", font=("Helvetica", 12), 
                 bg="#aa6600", fg="white", command=self.restore_system_backup, 
                 width=15).pack(side="left", padx=5)
        
        tk.Button(backup_controls, text="📂 Manage Backups", font=("Helvetica", 12), 
                 bg="#0066aa", fg="white", command=self.manage_backups, 
                 width=15).pack(side="left", padx=5)
        
        # Backup status
        backup_status = tk.LabelFrame(backup_frame, text="Backup Status", 
                                    font=("Helvetica", 12, "bold"),
                                    fg="#00ff41", bg="#1a1a1a", bd=2)
        backup_status.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.backup_status_text = tk.Text(backup_status, bg="#0a0a0a", fg="#888", 
                                        font=("Consolas", 10))
        self.backup_status_text.pack(fill="both", expand=True, padx=10, pady=10)

    def check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            if platform.system() == "Windows":
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if is_admin:
                    self.admin_status.config(text="✅ ADMIN MODE", fg="#00aa00")
                else:
                    self.admin_status.config(text="⚠️ ADMIN REQUIRED", fg="#ffaa00")
                    messagebox.showwarning(
                        "Administrator Required", 
                        "This application requires administrator privileges to modify system settings.\n"
                        "Please run as administrator for full functionality."
                    )
            else:
                self.admin_status.config(text="❌ WINDOWS ONLY", fg="#ff4444")
        except Exception as e:
            self.admin_status.config(text="❓ UNKNOWN", fg="#ffaa00")

    def apply_registry_hardening(self):
        """Apply selected registry hardening measures"""
        if not self.confirm_action("Registry Hardening", 
                                 "This will modify Windows Registry settings. Continue?"):
            return
        
        results = []
        
        try:
            # Backup current settings first
            self.backup_registry_settings()
            
            for setting, var in self.reg_options.items():
                if var.get():
                    result = self.apply_registry_setting(setting)
                    results.append(f"{setting}: {result}")
            
            self.show_results("Registry Hardening Results", results)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply registry hardening: {str(e)}")

    def apply_registry_setting(self, setting):
        """Apply a specific registry setting"""
        try:
            if setting == "disable_autorun":
                # Disable AutoRun for all drives
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                self.set_registry_value(winreg.HKEY_LOCAL_MACHINE, key_path, "NoDriveTypeAutoRun", 255)
                return "Success"
            
            elif setting == "block_usb":
                # Block USB storage devices
                key_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
                self.set_registry_value(winreg.HKEY_LOCAL_MACHINE, key_path, "Start", 4)
                return "Success"
            
            elif setting == "disable_wsh":
                # Disable Windows Script Host
                key_path = r"SOFTWARE\Microsoft\Windows Script Host\Settings"
                self.set_registry_value(winreg.HKEY_LOCAL_MACHINE, key_path, "Enabled", 0)
                return "Success"
            
            elif setting == "enhanced_logging":
                # Enable process creation logging
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
                self.set_registry_value(winreg.HKEY_LOCAL_MACHINE, key_path, "ProcessCreationIncludeCmdLine_Enabled", 1)
                return "Success"
            
            elif setting == "disable_remote_reg":
                # Disable Remote Registry service
                subprocess.run(["sc", "config", "RemoteRegistry", "start=", "disabled"], 
                             check=True, capture_output=True)
                return "Success"
            
            elif setting == "block_macros":
                # Block Office macros
                office_versions = ["16.0", "15.0", "14.0"]  # Office 2016, 2013, 2010
                for version in office_versions:
                    try:
                        for app in ["Excel", "Word", "PowerPoint"]:
                            key_path = f"SOFTWARE\\Microsoft\\Office\\{version}\\{app}\\Security"
                            self.set_registry_value(winreg.HKEY_CURRENT_USER, key_path, "VBAWarnings", 4)
                    except:
                        pass
                return "Success"
            
            elif setting == "disable_ps2":
                # Disable PowerShell v2
                subprocess.run(["dism", "/online", "/disable-feature", "/featurename:MicrosoftWindowsPowerShellV2Root"], 
                             check=True, capture_output=True)
                return "Success"
            
            elif setting == "enhanced_uac":
                # Enhanced UAC settings
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                self.set_registry_value(winreg.HKEY_LOCAL_MACHINE, key_path, "ConsentPromptBehaviorAdmin", 2)
                self.set_registry_value(winreg.HKEY_LOCAL_MACHINE, key_path, "EnableLUA", 1)
                self.set_registry_value(winreg.HKEY_LOCAL_MACHINE, key_path, "PromptOnSecureDesktop", 1)
                return "Success"
            
            else:
                return "Unknown setting"
                
        except Exception as e:
            return f"Failed: {str(e)}"

    def set_registry_value(self, hive, key_path, value_name, value_data):
        """Set a registry value"""
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, value_data)
            winreg.CloseKey(key)
        except FileNotFoundError:
            # Create the key if it doesn't exist
            key = winreg.CreateKey(hive, key_path)
            winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, value_data)
            winreg.CloseKey(key)

    def backup_registry_settings(self):
        """Backup current registry settings"""
        backup_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"registry_backup_{backup_time}.reg"
        
        try:
            # Export specific registry keys
            subprocess.run([
                "reg", "export", 
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies", 
                backup_file
            ], check=True)
            
            self.log_audit(f"Registry backup created: {backup_file}")
            
        except Exception as e:
            self.log_audit(f"Registry backup failed: {str(e)}")

    def check_registry_status(self):
        """Check current status of registry hardening settings"""
        status_results = []
        
        for setting, var in self.reg_options.items():
            try:
                status = self.check_registry_setting(setting)
                status_results.append(f"{setting}: {status}")
            except Exception as e:
                status_results.append(f"{setting}: Error - {str(e)}")
        
        self.show_results("Registry Status Check", status_results)

    def check_registry_setting(self, setting):
        """Check the current status of a registry setting"""
        # Implementation for checking specific registry settings
        # This would be similar to apply_registry_setting but for reading
        return "Not implemented"

    def restore_registry_defaults(self):
        """Restore registry settings to defaults"""
        if not self.confirm_action("Restore Defaults", 
                                 "This will restore registry settings to Windows defaults. Continue?"):
            return
        
        # Implementation for restoring registry defaults
        messagebox.showinfo("Restore", "Registry defaults restoration not yet implemented.")

    def configure_firewall(self):
        """Configure Windows Firewall with advanced rules"""
        if not self.confirm_action("Firewall Configuration", 
                                 "This will modify Windows Firewall settings. Continue?"):
            return
        
        results = []
        
        # Apply selected firewall rules
        if self.fw_block_ports.get():
            result = self.block_suspicious_ports()
            results.append(f"Block Suspicious Ports: {result}")
        
        if self.fw_restrict_outbound.get():
            result = self.restrict_outbound_connections()
            results.append(f"Restrict Outbound: {result}")
        
        # Add more firewall configurations...
        
        self.show_results("Firewall Configuration Results", results)

    def block_suspicious_ports(self):
        """Block commonly used malware ports"""
        suspicious_ports = [1337, 31337, 12345, 54321, 666, 4444, 5555, 9999]
        
        try:
            for port in suspicious_ports:
                # Block inbound
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=KeySentinel Block Inbound {port}",
                    "dir=in", "action=block", f"localport={port}", "protocol=TCP"
                ], check=True, capture_output=True)
                
                # Block outbound
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=KeySentinel Block Outbound {port}",
                    "dir=out", "action=block", f"remoteport={port}", "protocol=TCP"
                ], check=True, capture_output=True)
            
            return "Success"
        except Exception as e:
            return f"Failed: {str(e)}"

    def restrict_outbound_connections(self):
        """Configure restrictive outbound firewall rules"""
        try:
            # Set default outbound action to block
            subprocess.run([
                "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", 
                "blockinbound,blockoutbound"
            ], check=True, capture_output=True)
            
            # Allow essential outbound connections
            essential_rules = [
                ("HTTP", "80", "tcp"),
                ("HTTPS", "443", "tcp"),
                ("DNS", "53", "udp"),
                ("NTP", "123", "udp"),
            ]
            
            for name, port, protocol in essential_rules:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=KeySentinel Allow {name}",
                    "dir=out", "action=allow", f"remoteport={port}", f"protocol={protocol}"
                ], check=True, capture_output=True)
            
            return "Success"
        except Exception as e:
            return f"Failed: {str(e)}"

    def check_firewall_status(self):
        """Check current Windows Firewall status"""
        try:
            result = subprocess.run([
                "netsh", "advfirewall", "show", "allprofiles", "state"
            ], capture_output=True, text=True, check=True)
            
            self.firewall_status_text.delete("1.0", tk.END)
            self.firewall_status_text.insert("1.0", result.stdout)
            
        except Exception as e:
            self.firewall_status_text.delete("1.0", tk.END)
            self.firewall_status_text.insert("1.0", f"Error checking firewall status: {str(e)}")

    def refresh_services(self):
        """Refresh the services list"""
        # Clear existing items
        for item in self.services_tree.get_children():
            self.services_tree.delete(item)
        
        # Services that are commonly targeted or unnecessary
        target_services = [
            ("RemoteRegistry", "Remote Registry", "Disabled"),
            ("TelnetD", "Telnet", "Disabled"),
            ("FTPSVC", "Microsoft FTP Service", "Disabled"),
            ("SNMP", "SNMP Service", "Disabled"),
            ("RasMan", "Remote Access Connection Manager", "Manual"),
            ("SharedAccess", "Internet Connection Sharing", "Disabled"),
            ("Browser", "Computer Browser", "Disabled"),
            ("NetBT", "NetBIOS over TCP/IP", "Disabled"),
        ]
        
        for service_name, display_name, recommended in target_services:
            try:
                # Get current service status
                result = subprocess.run([
                    "sc", "query", service_name
                ], capture_output=True, text=True)
                
                if "does not exist" in result.stderr:
                    status = "Not Installed"
                elif "RUNNING" in result.stdout:
                    status = "Running"
                elif "STOPPED" in result.stdout:
                    status = "Stopped"
                else:
                    status = "Unknown"
                
                action = "✅" if status == recommended or status == "Not Installed" else "⚠️"
                
                self.services_tree.insert("", tk.END, values=(
                    service_name, display_name, status, recommended, action
                ))
                
            except Exception:
                self.services_tree.insert("", tk.END, values=(
                    service_name, display_name, "Error", recommended, "❌"
                ))

    def apply_service_hardening(self):
        """Apply service hardening recommendations"""
        if not self.confirm_action("Service Hardening", 
                                 "This will modify Windows service configurations. Continue?"):
            return
        
        results = []
        
        # Get all services from the tree
        for item in self.services_tree.get_children():
            values = self.services_tree.item(item)['values']
            service_name, display_name, current_status, recommended, action = values
            
            if action == "⚠️":  # Only modify services that need changes
                try:
                    if recommended == "Disabled":
                        subprocess.run([
                            "sc", "config", service_name, "start=", "disabled"
                        ], check=True, capture_output=True)
                        
                        subprocess.run([
                            "sc", "stop", service_name
                        ], capture_output=True)  # Don't fail if already stopped
                        
                        results.append(f"{service_name}: Disabled")
                    
                    elif recommended == "Manual":
                        subprocess.run([
                            "sc", "config", service_name, "start=", "demand"
                        ], check=True, capture_output=True)
                        
                        results.append(f"{service_name}: Set to Manual")
                        
                except Exception as e:
                    results.append(f"{service_name}: Failed - {str(e)}")
        
        self.show_results("Service Hardening Results", results)
        self.refresh_services()  # Refresh to show new status

    def run_security_audit(self):
        """Run comprehensive security audit"""
        self.audit_text.delete("1.0", tk.END)
        self.log_audit("Starting comprehensive security audit...")
        
        # Check various security aspects
        self.audit_windows_updates()
        self.audit_firewall_status()
        self.audit_antivirus_status()
        self.audit_user_accounts()
        self.audit_system_configuration()
        self.audit_network_configuration()
        
        self.log_audit("Security audit completed.")

    def audit_windows_updates(self):
        """Audit Windows Update status"""
        try:
            self.log_audit("\n=== Windows Updates ===")
            
            # Check for pending updates (simplified)
            result = subprocess.run([
                "powershell", "-Command", 
                "Get-WUList | Format-Table Title, Size -AutoSize"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                if result.stdout.strip():
                    self.log_audit("⚠️ Pending updates found:")
                    self.log_audit(result.stdout)
                else:
                    self.log_audit("✅ No pending updates")
            else:
                self.log_audit("❌ Unable to check Windows Updates (PowerShell required)")
                
        except Exception as e:
            self.log_audit(f"❌ Windows Update check failed: {str(e)}")

    def audit_firewall_status(self):
        """Audit firewall status"""
        try:
            self.log_audit("\n=== Firewall Status ===")
            
            result = subprocess.run([
                "netsh", "advfirewall", "show", "allprofiles", "state"
            ], capture_output=True, text=True, check=True)
            
            if "ON" in result.stdout:
                self.log_audit("✅ Windows Firewall is enabled")
            else:
                self.log_audit("⚠️ Windows Firewall may be disabled")
                
            self.log_audit(result.stdout)
            
        except Exception as e:
            self.log_audit(f"❌ Firewall check failed: {str(e)}")

    def audit_antivirus_status(self):
        """Audit antivirus status"""
        try:
            self.log_audit("\n=== Antivirus Status ===")
            
            # Check Windows Defender status
            result = subprocess.run([
                "powershell", "-Command",
                "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled"
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.log_audit("Windows Defender Status:")
                self.log_audit(result.stdout)
            else:
                self.log_audit("❌ Unable to check Windows Defender status")
                
        except Exception as e:
            self.log_audit(f"❌ Antivirus check failed: {str(e)}")

    def audit_user_accounts(self):
        """Audit user accounts"""
        try:
            self.log_audit("\n=== User Accounts ===")
            
            result = subprocess.run([
                "net", "user"
            ], capture_output=True, text=True, check=True)
            
            self.log_audit("Local user accounts:")
            self.log_audit(result.stdout)
            
            # Check for administrator accounts
            result = subprocess.run([
                "net", "localgroup", "administrators"
            ], capture_output=True, text=True, check=True)
            
            self.log_audit("\nAdministrator group members:")
            self.log_audit(result.stdout)
            
        except Exception as e:
            self.log_audit(f"❌ User account audit failed: {str(e)}")

    def audit_system_configuration(self):
        """Audit system configuration"""
        try:
            self.log_audit("\n=== System Configuration ===")
            
            # Check UAC status
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
                uac_enabled = winreg.QueryValueEx(key, "EnableLUA")[0]
                winreg.CloseKey(key)
                
                if uac_enabled:
                    self.log_audit("✅ User Account Control (UAC) is enabled")
                else:
                    self.log_audit("⚠️ User Account Control (UAC) is disabled")
            except:
                self.log_audit("❌ Unable to check UAC status")
            
            # Check AutoRun status
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")
                autorun_disabled = winreg.QueryValueEx(key, "NoDriveTypeAutoRun")[0]
                winreg.CloseKey(key)
                
                if autorun_disabled == 255:
                    self.log_audit("✅ AutoRun is disabled for all drives")
                else:
                    self.log_audit("⚠️ AutoRun is not fully disabled")
            except:
                self.log_audit("⚠️ AutoRun policy not configured")
                
        except Exception as e:
            self.log_audit(f"❌ System configuration audit failed: {str(e)}")

    def audit_network_configuration(self):
        """Audit network configuration"""
        try:
            self.log_audit("\n=== Network Configuration ===")
            
            # Check for open ports
            import psutil
            
            connections = psutil.net_connections(kind='inet')
            listening_ports = [conn.laddr.port for conn in connections if conn.status == 'LISTEN']
            
            if listening_ports:
                self.log_audit(f"Open ports: {sorted(set(listening_ports))}")
                
                # Check for suspicious ports
                suspicious_ports = [1337, 31337, 12345, 54321, 666, 4444, 5555, 9999]
                found_suspicious = [port for port in listening_ports if port in suspicious_ports]
                
                if found_suspicious:
                    self.log_audit(f"⚠️ Suspicious ports found: {found_suspicious}")
                else:
                    self.log_audit("✅ No known suspicious ports detected")
            else:
                self.log_audit("No listening ports detected")
                
        except Exception as e:
            self.log_audit(f"❌ Network configuration audit failed: {str(e)}")

    def generate_audit_report(self):
        """Generate a comprehensive audit report"""
        report_content = self.audit_text.get("1.0", tk.END)
        
        if not report_content.strip():
            messagebox.showwarning("No Data", "Please run a security audit first.")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"KeySentinel_Security_Audit_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write(f"KeySentinel Security Audit Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*50 + "\n\n")
                f.write(report_content)
            
            messagebox.showinfo("Report Generated", f"Audit report saved as: {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")

    def clear_audit_log(self):
        """Clear the audit log"""
        self.audit_text.delete("1.0", tk.END)

    def log_audit(self, message):
        """Log a message to the audit text area"""
        self.audit_text.insert(tk.END, message + "\n")
        self.audit_text.see(tk.END)
        self.window.update_idletasks()

    def create_system_backup(self):
        """Create a system configuration backup"""
        if not self.confirm_action("Create Backup", 
                                 "This will create a backup of current system configuration. Continue?"):
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = f"KeySentinel_Backup_{timestamp}"
        
        try:
            os.makedirs(backup_dir, exist_ok=True)
            
            self.log_backup(f"Creating system backup in {backup_dir}...")
            
            # Backup registry keys
            registry_backup = os.path.join(backup_dir, "registry_policies.reg")
            subprocess.run([
                "reg", "export",
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
                registry_backup
            ], check=True)
            
            # Backup firewall rules
            firewall_backup = os.path.join(backup_dir, "firewall_rules.wfw")
            subprocess.run([
                "netsh", "advfirewall", "export", firewall_backup
            ], check=True)
            
            # Backup service configurations
            services_backup = os.path.join(backup_dir, "services_config.txt")
            result = subprocess.run([
                "sc", "query", "type=", "service", "state=", "all"
            ], capture_output=True, text=True)
            
            with open(services_backup, 'w') as f:
                f.write(result.stdout)
            
            # Create backup manifest
            manifest = {
                "timestamp": timestamp,
                "platform": platform.platform(),
                "backup_type": "KeySentinel System Hardening",
                "files": [
                    "registry_policies.reg",
                    "firewall_rules.wfw", 
                    "services_config.txt"
                ]
            }
            
            manifest_file = os.path.join(backup_dir, "backup_manifest.json")
            with open(manifest_file, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            self.log_backup(f"✅ Backup created successfully: {backup_dir}")
            messagebox.showinfo("Backup Complete", f"System backup created: {backup_dir}")
            
        except Exception as e:
            self.log_backup(f"❌ Backup failed: {str(e)}")
            messagebox.showerror("Backup Failed", f"Failed to create backup: {str(e)}")

    def restore_system_backup(self):
        """Restore from a system backup"""
        # Implementation for backup restoration
        messagebox.showinfo("Restore", "Backup restoration feature coming soon...")

    def manage_backups(self):
        """Manage existing backups"""
        # Implementation for backup management
        messagebox.showinfo("Manage Backups", "Backup management feature coming soon...")

    def log_backup(self, message):
        """Log backup activity"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.backup_status_text.insert(tk.END, formatted_message)
        self.backup_status_text.see(tk.END)

    def confirm_action(self, title, message):
        """Show confirmation dialog"""
        return messagebox.askyesno(title, message)

    def show_results(self, title, results):
        """Show operation results in a dialog"""
        result_text = "\n".join(results)

        result_window = tk.Toplevel(self.window)
        try:
            import os
            icon_path = os.path.join(os.path.dirname(__file__), "KeySentinel_logo.ico")
            if os.path.exists(icon_path):
                result_window.iconbitmap(icon_path)
            else:
                result_window.iconbitmap("KeySentinel_logo.ico")
        except Exception:
            try:
                result_window.iconbitmap(default="KeySentinel_logo.ico")
            except Exception:
                pass
        result_window.title(title)
        result_window.geometry("600x400")
        result_window.configure(bg="#0a0a0a")

        text_widget = scrolledtext.ScrolledText(result_window, bg="#0a0a0a", fg="#00ff41", 
                                              font=("Consolas", 10))
        text_widget.pack(fill="both", expand=True, padx=10, pady=10)
        text_widget.insert("1.0", result_text)

    def run(self):
        """Start the system hardening tools"""
        self.refresh_services()
        self.check_firewall_status()
        self.window.mainloop()


# Run as standalone
if __name__ == "__main__":
    tools = SystemHardeningTools()
    tools.run()
