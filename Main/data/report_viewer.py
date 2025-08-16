# report_viewer.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from keylogger_db import KeyloggerThreatDB
import datetime

class ThreatReportViewer:
    def __init__(self):
        self.db = KeyloggerThreatDB()
        self.window = tk.Tk()
        self.window.title("🧾 KeySentinel - Threat Report Viewer")
        self.window.geometry("1000x600")
        self.window.configure(bg="#0a0a0a")

        self.setup_ui()
        self.load_data()

        self.window.mainloop()

    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.window, bg="#1a1a1a", relief="raised", bd=2)
        header_frame.pack(fill="x", padx=5, pady=5)
        
        title = tk.Label(header_frame, text="🧾 KeySentinel Threat Report Viewer", 
                        font=("Helvetica", 16, "bold"), fg="#00ff41", bg="#1a1a1a")
        title.pack(side="left", padx=10, pady=10)
        
        # Control buttons
        btn_frame = tk.Frame(header_frame, bg="#1a1a1a")
        btn_frame.pack(side="right", padx=10, pady=10)
        
        refresh_btn = tk.Button(btn_frame, text="🔄 Refresh", font=("Helvetica", 10), 
                              bg="#0066aa", fg="white", command=self.load_data)
        refresh_btn.pack(side="left", padx=5)
        
        export_btn = tk.Button(btn_frame, text="💾 Export", font=("Helvetica", 10), 
                             bg="#aa6600", fg="white", command=self.export_data)
        export_btn.pack(side="left", padx=5)
        
        clear_btn = tk.Button(btn_frame, text="🗑️ Clear", font=("Helvetica", 10), 
                            bg="#aa0000", fg="white", command=self.clear_data)
        clear_btn.pack(side="left", padx=5)

        # Statistics frame
        stats_frame = tk.LabelFrame(self.window, text="Threat Statistics", 
                                  font=("Helvetica", 12, "bold"),
                                  fg="#00ff41", bg="#1a1a1a", bd=2)
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        self.stats_label = tk.Label(stats_frame, text="Loading statistics...", 
                                  font=("Helvetica", 10), fg="white", bg="#1a1a1a")
        self.stats_label.pack(padx=10, pady=10)

        # Main content area
        content_frame = tk.Frame(self.window, bg="#0a0a0a")
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview for threats
        columns = ("ID", "Time", "Process", "PID", "Severity", "Action")
        self.tree = ttk.Treeview(content_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        column_widths = {"ID": 50, "Time": 150, "Process": 200, "PID": 80, "Severity": 100, "Action": 150}
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=column_widths.get(col, 100), anchor="center")

        # Scrollbars
        v_scroll = tk.Scrollbar(content_frame, orient="vertical", command=self.tree.yview)
        h_scroll = tk.Scrollbar(content_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        # Pack treeview and scrollbars
        self.tree.pack(side="left", fill="both", expand=True)
        v_scroll.pack(side="right", fill="y")
        h_scroll.pack(side="bottom", fill="x")

        # Configure treeview style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1a1a1a", foreground="white", 
                       fieldbackground="#1a1a1a", rowheight=25)
        style.map("Treeview", background=[("selected", "#00aa00")])

        # Context menu
        self.context_menu = tk.Menu(self.window, tearoff=0, bg="#1a1a1a", fg="white")
        self.context_menu.add_command(label="View Details", command=self.view_details)
        self.context_menu.add_command(label="Delete Entry", command=self.delete_entry)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy to Clipboard", command=self.copy_to_clipboard)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.view_details)

    def load_data(self):
        """Load threat data from database"""
        try:
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Fetch data
            rows = self.db.fetch_all_threats()
            
            # Update statistics
            total_threats = len(rows)
            high_severity = len([r for r in rows if r[4] == 'High'])
            medium_severity = len([r for r in rows if r[4] == 'Medium'])
            low_severity = len([r for r in rows if r[4] == 'Low'])
            
            stats_text = f"""Total Threats: {total_threats} | High: {high_severity} | Medium: {medium_severity} | Low: {low_severity} | Last Updated: {datetime.datetime.now().strftime('%H:%M:%S')}"""
            self.stats_label.config(text=stats_text)
            
            # Insert data with color coding
            for row in rows:
                item = self.tree.insert("", "end", values=row)
                
                # Color code by severity
                if row[4] == 'High':
                    self.tree.set(item, "Severity", "🔴 High")
                elif row[4] == 'Medium':
                    self.tree.set(item, "Severity", "🟡 Medium")
                else:
                    self.tree.set(item, "Severity", "🟢 Low")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load data: {str(e)}")

    def export_data(self):
        """Export threat data to file"""
        try:
            filename = filedialog.asksaveasfilename(
                title="Export Threat Data",
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filename:
                rows = self.db.fetch_all_threats()
                
                with open(filename, 'w', encoding='utf-8') as f:
                    if filename.endswith('.csv'):
                        # CSV format
                        f.write("ID,Time,Process,PID,Severity,Action\n")
                        for row in rows:
                            f.write(f"{row[0]},{row[1]},{row[2]},{row[3]},{row[4]},{row[5]}\n")
                    else:
                        # Text format
                        f.write("KeySentinel Threat Report\n")
                        f.write("=" * 50 + "\n\n")
                        for row in rows:
                            f.write(f"ID: {row[0]} | Time: {row[1]} | Process: {row[2]} | PID: {row[3]} | Severity: {row[4]} | Action: {row[5]}\n")
                
                messagebox.showinfo("Export Successful", f"Data exported to:\n{filename}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")

    def clear_data(self):
        """Clear all threat data"""
        if messagebox.askyesno("Confirm Clear", "This will delete all threat records. Continue?"):
            try:
                self.db.cursor.execute("DELETE FROM threats")
                self.db.conn.commit()
                self.load_data()
                messagebox.showinfo("Success", "All threat data cleared")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear data: {str(e)}")

    def show_context_menu(self, event):
        """Show context menu for treeview"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def view_details(self, event=None):
        """View detailed information about selected threat"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a threat to view details.")
            return
        
        item = selection[0]
        values = self.tree.item(item)['values']
        
        details_window = tk.Toplevel(self.window)
        details_window.title(f"Threat Details - ID {values[0]}")
        details_window.geometry("600x400")
        details_window.configure(bg="#0a0a0a")
        
        details_text = tk.Text(details_window, bg="#0a0a0a", fg="#00ff41", 
                             font=("Consolas", 10))
        details_scroll = tk.Scrollbar(details_window, command=details_text.yview)
        details_text.config(yscrollcommand=details_scroll.set)
        
        details_content = f"""Threat Details Report
{'='*50}

Threat ID: {values[0]}
Detection Time: {values[1]}
Process Name: {values[2]}
Process ID: {values[3]}
Severity Level: {values[4]}
Action Taken: {values[5]}

Additional Information:
• This threat was detected by KeySentinel Pro
• Process monitoring and analysis performed
• Threat assessment completed automatically
• Recommended action: {values[5]}

System Impact Assessment:
• Severity: {values[4]}
• Risk Level: {'High' if values[4] == 'High' else 'Medium' if values[4] == 'Medium' else 'Low'}
• Recommended Response: {'Immediate action required' if values[4] == 'High' else 'Monitor closely' if values[4] == 'Medium' else 'Low priority'}
"""
        
        details_text.insert("1.0", details_content)
        details_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        details_scroll.pack(side="right", fill="y")

    def delete_entry(self):
        """Delete selected threat entry"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a threat to delete.")
            return
        
        if messagebox.askyesno("Confirm Delete", "Delete the selected threat entry?"):
            try:
                item = selection[0]
                threat_id = self.tree.item(item)['values'][0]
                
                self.db.cursor.execute("DELETE FROM threats WHERE id = ?", (threat_id,))
                self.db.conn.commit()
                
                self.load_data()
                messagebox.showinfo("Success", "Threat entry deleted")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete entry: {str(e)}")

    def copy_to_clipboard(self):
        """Copy selected threat info to clipboard"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a threat to copy.")
            return
        
        try:
            item = selection[0]
            values = self.tree.item(item)['values']
            
            clipboard_text = f"Threat ID: {values[0]} | Time: {values[1]} | Process: {values[2]} | PID: {values[3]} | Severity: {values[4]} | Action: {values[5]}"
            
            self.window.clipboard_clear()
            self.window.clipboard_append(clipboard_text)
            
            messagebox.showinfo("Copied", "Threat information copied to clipboard")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")

# Run as standalone
if __name__ == "__main__":
    ThreatReportViewer()
