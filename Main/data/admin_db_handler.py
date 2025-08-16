import json
import os

class AdminDB:
    def __init__(self, file_path='admin_credentials.json'):
        self.file_path = file_path
        if not os.path.exists(self.file_path):
            self.set_password('admin')  # Default password

    def set_password(self, password):
        with open(self.file_path, 'w') as f:
            json.dump({'password': password}, f)

    def verify_password(self, password):
        with open(self.file_path, 'r') as f:
            data = json.load(f)
        return data.get('password') == password
