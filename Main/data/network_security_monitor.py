# network_security_monitor.py
import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import socket
import threading
import time
import datetime
from collections import defaultdict
import subprocess
import platform


class NetworkSecurityMonitor:
    """Advanced Network Security Monitor for detecting suspicious network activity"""
    
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🌐 KeySentinel Network Security Monitor")
        self.window.geometry("1200x800")
        self.window.configure(bg="#0a0a0a")
        
        # Monitoring state
        self.monitoring = False
        self.suspicious_connections = []
        self.connection_history = defaultdict(list)
        self.blocked_ips = set()
        
        # Suspicious indicators
        self.suspicious_ports = [1337, 31337, 12345, 54321, 9999, 666, 4444, 5555]
        self.suspicious_processes = ['keylog', 'logger', 'spy', 'rat', 'trojan']
        self.suspicious_domains = ['keylogger', 'malware', 'botnet', 'c2', 'command']
        
        self.setup_ui()
        self.start_monitoring()

    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.window, bg="#1a1a1a", relief="raised", bd=2)
        header_frame.pack(fill="x", padx=5, pady=5)
        
        title = tk.Label(header_frame, text="🌐 Network Security Monitor", 
                        font=("Helvetica", 18, "bold"), fg="#00ff41", bg="#1a1a1a")
        title.pack(side="left", padx=10, pady=10)
        
        # Status indicator
        self.status_label = tk.Label(header_frame, text="🔴 OFFLINE", 
                                   font=("Helvetica", 12, "bold"), 
                                   fg="#ff4444", bg="#1a1a1a")
        self.status_label.pack(side="right", padx=10, pady=10)
        
        # Control panel
        control_frame = tk.Frame(self.window, bg="#1a1a1a", relief="raised", bd=2)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        self.monitor_btn = tk.Button(control_frame, text="🟢 Start Monitoring", 
                                   font=("Helvetica", 11, "bold"), bg="#00aa00", fg="white",
                                   command=self.toggle_monitoring, width=15)
        self.monitor_btn.pack(side="left", padx=10, pady=5)
        
        tk.Button(control_frame, text="🔍 Scan Ports", 
                 font=("Helvetica", 11), bg="#0066aa", fg="white",
                 command=self.scan_open_ports, width=12).pack(side="left", padx=5, pady=5)
        
        tk.Button(control_frame, text="🚫 Block IP", 
                 font=("Helvetica", 11), bg="#aa0000", fg="white",
                 command=self.block_ip_dialog, width=10).pack(side="left", padx=5, pady=5)
        
        tk.Button(control_frame, text="📊 Statistics", 
                 font=("Helvetica", 11), bg="#aa6600", fg="white",
                 command=self.show_statistics, width=10).pack(side="left", padx=5, pady=5)
        
        tk.Button(control_frame, text="🧹 Clear Logs", 
                 font=("Helvetica", 11), bg="#666", fg="white",
                 command=self.clear_logs, width=10).pack(side="left", padx=5, pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Configure dark theme for notebook
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#1a1a1a', borderwidth=0)
        style.configure('TNotebook.Tab', background='#333', foreground='white', 
                       padding=[12, 8], font=('Helvetica', 10))
        style.map('TNotebook.Tab', background=[('selected', '#00aa00')])
        
        self.setup_connections_tab()
        self.setup_suspicious_tab()
        self.setup_firewall_tab()
        self.setup_analysis_tab()

    def setup_connections_tab(self):
        """Active network connections tab"""
        conn_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(conn_frame, text="🔗 Active Connections")
        
        # Connections table
        columns = ("Local Address", "Remote Address", "Status", "PID", "Process", "Risk Level")
        self.connections_tree = ttk.Treeview(conn_frame, columns=columns, show="headings")
        
        for col in columns:
            self.connections_tree.heading(col, text=col)
            if col == "Process":
                self.connections_tree.column(col, width=150)
            else:
                self.connections_tree.column(col, width=120)
        
        # Scrollbars
        conn_v_scroll = tk.Scrollbar(conn_frame, orient="vertical", command=self.connections_tree.yview)
        conn_h_scroll = tk.Scrollbar(conn_frame, orient="horizontal", command=self.connections_tree.xview)
        
        self.connections_tree.configure(yscrollcommand=conn_v_scroll.set, 
                                      xscrollcommand=conn_h_scroll.set)
        
        # Pack
        self.connections_tree.pack(side="left", fill="both", expand=True)
        conn_v_scroll.pack(side="right", fill="y")
        conn_h_scroll.pack(side="bottom", fill="x")
        
        # Configure treeview style
        style = ttk.Style()
        style.configure("Treeview", background="#1a1a1a", foreground="white", 
                       fieldbackground="#1a1a1a", rowheight=25)
        style.map("Treeview", background=[("selected", "#00aa00")])

    def setup_suspicious_tab(self):
        """Suspicious activity tab"""
        susp_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(susp_frame, text="🚨 Suspicious Activity")
        
        # Suspicious activity log
        self.suspicious_text = tk.Text(susp_frame, bg="#0a0a0a", fg="#ff4444", 
                                     font=("Consolas", 10), insertbackground="white")
        susp_scroll = tk.Scrollbar(susp_frame, command=self.suspicious_text.yview)
        self.suspicious_text.config(yscrollcommand=susp_scroll.set)
        
        self.suspicious_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        susp_scroll.pack(side="right", fill="y")

    def setup_firewall_tab(self):
        """Firewall management tab"""
        fw_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(fw_frame, text="🛡️ Firewall Control")
        
        # Blocked IPs section
        blocked_frame = tk.LabelFrame(fw_frame, text="Blocked IP Addresses", 
                                    font=("Helvetica", 12, "bold"),
                                    fg="#00ff41", bg="#1a1a1a", bd=2)
        blocked_frame.pack(fill="x", padx=10, pady=5)
        
        self.blocked_listbox = tk.Listbox(blocked_frame, bg="#1a1a1a", fg="white", 
                                        font=("Consolas", 10), height=8)
        blocked_scroll = tk.Scrollbar(blocked_frame, command=self.blocked_listbox.yview)
        self.blocked_listbox.config(yscrollcommand=blocked_scroll.set)
        
        self.blocked_listbox.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        blocked_scroll.pack(side="right", fill="y")
        
        # Firewall rules section
        rules_frame = tk.LabelFrame(fw_frame, text="Firewall Rules", 
                                  font=("Helvetica", 12, "bold"),
                                  fg="#00ff41", bg="#1a1a1a", bd=2)
        rules_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Rules table
        rules_columns = ("Rule", "Direction", "Action", "Protocol", "Port", "IP", "Status")
        self.rules_tree = ttk.Treeview(rules_frame, columns=rules_columns, show="headings")
        
        for col in rules_columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=100)
        
        rules_v_scroll = tk.Scrollbar(rules_frame, orient="vertical", command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=rules_v_scroll.set)
        
        self.rules_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        rules_v_scroll.pack(side="right", fill="y")

    def setup_analysis_tab(self):
        """Network analysis tab"""
        analysis_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(analysis_frame, text="📈 Analysis")
        
        # Statistics display
        stats_frame = tk.LabelFrame(analysis_frame, text="Network Statistics", 
                                  font=("Helvetica", 12, "bold"),
                                  fg="#00ff41", bg="#1a1a1a", bd=2)
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        self.stats_text = tk.Text(stats_frame, bg="#0a0a0a", fg="#00ff41", 
                                font=("Consolas", 10), height=10)
        stats_scroll = tk.Scrollbar(stats_frame, command=self.stats_text.yview)
        self.stats_text.config(yscrollcommand=stats_scroll.set)
        
        self.stats_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        stats_scroll.pack(side="right", fill="y")
        
        # Traffic analysis
        traffic_frame = tk.LabelFrame(analysis_frame, text="Traffic Analysis", 
                                    font=("Helvetica", 12, "bold"),
                                    fg="#00ff41", bg="#1a1a1a", bd=2)
        traffic_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.traffic_text = tk.Text(traffic_frame, bg="#0a0a0a", fg="#888", 
                                  font=("Consolas", 9))
        traffic_scroll = tk.Scrollbar(traffic_frame, command=self.traffic_text.yview)
        self.traffic_text.config(yscrollcommand=traffic_scroll.set)
        
        self.traffic_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        traffic_scroll.pack(side="right", fill="y")

    def toggle_monitoring(self):
        """Toggle network monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_btn.config(text="🔴 Stop Monitoring", bg="#aa0000")
            self.status_label.config(text="🟢 MONITORING", fg="#00aa00")
            self.log_suspicious("Network monitoring started")
            
            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self.monitor_connections, daemon=True)
            self.monitor_thread.start()
        else:
            self.monitoring = False
            self.monitor_btn.config(text="🟢 Start Monitoring", bg="#00aa00")
            self.status_label.config(text="🔴 OFFLINE", fg="#ff4444")
            self.log_suspicious("Network monitoring stopped")

    def start_monitoring(self):
        """Initialize monitoring"""
        self.update_connections()
        self.window.after(2000, self.start_monitoring)  # Update every 2 seconds

    def monitor_connections(self):
        """Monitor network connections in background"""
        while self.monitoring:
            try:
                self.scan_connections()
                time.sleep(1)  # Check every second
            except Exception as e:
                self.log_suspicious(f"Monitoring error: {str(e)}")
                time.sleep(5)

    def update_connections(self):
        """Update the connections display"""
        # Clear existing items
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    
                    # Get process info
                    process_name = "Unknown"
                    risk_level = "Low"
                    
                    try:
                        if conn.pid:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                            
                            # Assess risk level
                            risk_level = self.assess_connection_risk(conn, process_name)
                    except:
                        pass
                    
                    # Insert into tree
                    item = self.connections_tree.insert("", tk.END, values=(
                        local_addr, remote_addr, conn.status, 
                        conn.pid or "N/A", process_name, risk_level
                    ))
                    
                    # Color code by risk
                    if risk_level == "High":
                        self.connections_tree.set(item, "Risk Level", "🔴 High")
                    elif risk_level == "Medium":
                        self.connections_tree.set(item, "Risk Level", "🟡 Medium")
                    else:
                        self.connections_tree.set(item, "Risk Level", "🟢 Low")
        
        except Exception as e:
            self.log_suspicious(f"Error updating connections: {str(e)}")

    def scan_connections(self):
        """Scan for suspicious connections"""
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if self.is_suspicious_connection(conn):
                    self.handle_suspicious_connection(conn)
        except Exception as e:
            pass

    def is_suspicious_connection(self, conn):
        """Check if connection is suspicious"""
        if not conn.laddr:
            return False
        
        # Check for suspicious ports
        if conn.laddr.port in self.suspicious_ports:
            return True
        
        # Check remote address if available
        if conn.raddr:
            if conn.raddr.port in self.suspicious_ports:
                return True
            
            # Check for suspicious remote IPs (private ranges used maliciously)
            remote_ip = conn.raddr.ip
            if self.is_suspicious_ip(remote_ip):
                return True
        
        # Check process name
        try:
            if conn.pid:
                process = psutil.Process(conn.pid)
                process_name = process.name().lower()
                if any(susp in process_name for susp in self.suspicious_processes):
                    return True
        except:
            pass
        
        return False

    def is_suspicious_ip(self, ip):
        """Check if IP address is suspicious"""
        # Check blocked IPs
        if ip in self.blocked_ips:
            return True
        
        # Add more sophisticated IP reputation checking here
        # For now, just basic checks
        
        return False

    def assess_connection_risk(self, conn, process_name):
        """Assess risk level of connection"""
        risk_score = 0
        
        # Check port
        if conn.laddr and conn.laddr.port in self.suspicious_ports:
            risk_score += 3
        
        if conn.raddr and conn.raddr.port in self.suspicious_ports:
            risk_score += 3
        
        # Check process name
        process_lower = process_name.lower()
        if any(susp in process_lower for susp in self.suspicious_processes):
            risk_score += 4
        
        # Check for external connections
        if conn.raddr and not self.is_local_ip(conn.raddr.ip):
            risk_score += 1
        
        if risk_score >= 4:
            return "High"
        elif risk_score >= 2:
            return "Medium"
        else:
            return "Low"

    def is_local_ip(self, ip):
        """Check if IP is local/private"""
        return (ip.startswith('192.168.') or 
                ip.startswith('10.') or 
                ip.startswith('172.') or
                ip == '127.0.0.1' or
                ip == 'localhost')

    def handle_suspicious_connection(self, conn):
        """Handle detected suspicious connection"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        
        # Get process info
        process_info = "Unknown"
        try:
            if conn.pid:
                process = psutil.Process(conn.pid)
                process_info = f"{process.name()} (PID: {conn.pid})"
        except:
            pass
        
        message = f"[{timestamp}] SUSPICIOUS: {local_addr} -> {remote_addr} | Process: {process_info}"
        self.log_suspicious(message)
        
        # Add to suspicious connections list
        if conn not in self.suspicious_connections:
            self.suspicious_connections.append(conn)

    def log_suspicious(self, message):
        """Log suspicious activity"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.suspicious_text.insert(tk.END, formatted_message)
        self.suspicious_text.see(tk.END)

    def scan_open_ports(self):
        """Scan for open ports on the system"""
        self.log_suspicious("Starting port scan...")
        
        def port_scan():
            try:
                # Get listening ports
                connections = psutil.net_connections(kind='inet')
                listening_ports = []
                
                for conn in connections:
                    if conn.status == 'LISTEN' and conn.laddr:
                        port_info = {
                            'port': conn.laddr.port,
                            'ip': conn.laddr.ip,
                            'pid': conn.pid
                        }
                        
                        # Get process name
                        try:
                            if conn.pid:
                                process = psutil.Process(conn.pid)
                                port_info['process'] = process.name()
                            else:
                                port_info['process'] = 'Unknown'
                        except:
                            port_info['process'] = 'Unknown'
                        
                        listening_ports.append(port_info)
                
                # Display results
                self.window.after(0, lambda: self.display_port_scan_results(listening_ports))
                
            except Exception as e:
                self.window.after(0, lambda: self.log_suspicious(f"Port scan error: {str(e)}"))
        
        threading.Thread(target=port_scan, daemon=True).start()

    def display_port_scan_results(self, ports):
        """Display port scan results"""
        result_window = tk.Toplevel(self.window)
        result_window.title("Port Scan Results")
        result_window.geometry("600x400")
        result_window.configure(bg="#0a0a0a")
        
        # Results table
        columns = ("Port", "IP", "Process", "PID", "Risk")
        tree = ttk.Treeview(result_window, columns=columns, show="headings")
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        
        scroll = tk.Scrollbar(result_window, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        
        for port_info in ports:
            risk = "High" if port_info['port'] in self.suspicious_ports else "Low"
            tree.insert("", tk.END, values=(
                port_info['port'], port_info['ip'], 
                port_info['process'], port_info['pid'] or 'N/A', risk
            ))
        
        tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scroll.pack(side="right", fill="y")
        
        self.log_suspicious(f"Port scan completed - {len(ports)} open ports found")

    def block_ip_dialog(self):
        """Show dialog to block an IP address"""
        ip = tk.simpledialog.askstring("Block IP", "Enter IP address to block:")
        if ip:
            self.block_ip(ip)

    def block_ip(self, ip):
        """Block an IP address"""
        try:
            self.blocked_ips.add(ip)
            self.blocked_listbox.insert(tk.END, ip)
            
            # Add firewall rule (Windows example)
            if platform.system() == "Windows":
                cmd = f'netsh advfirewall firewall add rule name="KeySentinel Block {ip}" dir=in action=block remoteip={ip}'
                try:
                    subprocess.run(cmd, shell=True, check=True)
                    self.log_suspicious(f"IP {ip} blocked successfully")
                except subprocess.CalledProcessError:
                    self.log_suspicious(f"Failed to add firewall rule for {ip}")
            else:
                self.log_suspicious(f"IP {ip} added to block list (manual firewall configuration required)")
            
        except Exception as e:
            self.log_suspicious(f"Error blocking IP {ip}: {str(e)}")

    def show_statistics(self):
        """Show network statistics"""
        stats = psutil.net_io_counters()
        
        stats_info = f"""Network Interface Statistics:
        
Bytes Sent: {stats.bytes_sent:,}
Bytes Received: {stats.bytes_recv:,}
Packets Sent: {stats.packets_sent:,}
Packets Received: {stats.packets_recv:,}
Errors In: {stats.errin:,}
Errors Out: {stats.errout:,}
Dropped In: {stats.dropin:,}
Dropped Out: {stats.dropout:,}

Active Connections: {len(psutil.net_connections())}
Suspicious Connections: {len(self.suspicious_connections)}
Blocked IPs: {len(self.blocked_ips)}
"""
        
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert("1.0", stats_info)

    def clear_logs(self):
        """Clear all logs"""
        if messagebox.askyesno("Clear Logs", "Clear all network logs?"):
            self.suspicious_text.delete("1.0", tk.END)
            self.traffic_text.delete("1.0", tk.END)
            self.suspicious_connections.clear()
            self.log_suspicious("Logs cleared")

    def run(self):
        """Start the network monitor"""
        self.window.mainloop()


# Run as standalone
if __name__ == "__main__":
    monitor = NetworkSecurityMonitor()
    monitor.run()
