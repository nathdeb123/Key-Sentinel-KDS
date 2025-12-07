# keylogger_db.py
import sqlite3
import datetime
import os

def get_app_data_dir():
    """Get writable application data directory for storing databases."""
    if os.name == 'nt':  # Windows
        app_data = os.path.expandvars(r'%LOCALAPPDATA%\KeySentinel')
    else:  # Unix/Linux/Mac
        app_data = os.path.expanduser('~/.keysentinel')
    
    os.makedirs(app_data, exist_ok=True)
    return app_data

class KeyloggerThreatDB:
    def __init__(self, db_name="keysentinel_logs.db"):
        db_dir = get_app_data_dir()
        db_path = os.path.join(db_dir, db_name)
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                process_name TEXT,
                process_id INTEGER,
                severity TEXT,
                action_taken TEXT
            )
        """)
        self.conn.commit()

    def log_threat(self, process_name, pid, severity, action):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("""
            INSERT INTO threats (timestamp, process_name, process_id, severity, action_taken)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, process_name, pid, severity, action))
        self.conn.commit()

    def fetch_all_threats(self):
        self.cursor.execute("SELECT * FROM threats ORDER BY id DESC")
        return self.cursor.fetchall()

    def close(self):
        self.conn.close()
