# admin_db.py
import sqlite3
import hashlib
import os

def get_app_data_dir():
    """Get writable application data directory for storing databases."""
    if os.name == 'nt':  # Windows
        app_data = os.path.expandvars(r'%LOCALAPPDATA%\KeySentinel')
    else:  # Unix/Linux/Mac
        app_data = os.path.expanduser('~/.keysentinel')
    
    os.makedirs(app_data, exist_ok=True)
    return app_data

DB_FILE = os.path.join(get_app_data_dir(), "admin_credentials.db")

class AdminDB:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)
        self.conn.commit()

        # Initialize password if empty
        self.cursor.execute("SELECT * FROM admin")
        if not self.cursor.fetchone():
            self.set_password("admin123")  # default password

    def set_password(self, new_password):
        hashed = hashlib.sha256(new_password.encode()).hexdigest()
        self.cursor.execute("DELETE FROM admin")
        self.cursor.execute("INSERT INTO admin (password_hash) VALUES (?)", (hashed,))
        self.conn.commit()

    def verify_password(self, password_input):
        hashed_input = hashlib.sha256(password_input.encode()).hexdigest()
        self.cursor.execute("SELECT password_hash FROM admin")
        result = self.cursor.fetchone()
        if result:
            return hashed_input == result[0]
        return False
