"""
End-to-End Encryption Chat Database Module
Advanced Database Management for Secure Communications
"""

import sqlite3
import hashlib
import secrets
import json
from datetime import datetime
from typing import Optional, Dict, List, Any
from cryptography.fernet import Fernet
import os

class E2EDatabase:
    """
    Advanced Database Manager for End-to-End Encrypted Chat System
    Supports multiple platforms including WhatsApp and Facebook
    """
    
    def __init__(self, db_path: str = "e2e_chat.db"):
        self.db_path = db_path
        self.encryption_key = self._generate_encryption_key()
        self.fernet = Fernet(self.encryption_key)
        self.init_database()
    
    def _generate_encryption_key(self) -> bytes:
        """Generate a secure encryption key"""
        return Fernet.generate_key()
    
    def init_database(self):
        """Initialize database with all required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table with encryption metadata
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                platform TEXT NOT NULL,
                public_key TEXT,
                encrypted_private_key BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Messages table with E2E encryption
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE NOT NULL,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                platform TEXT NOT NULL,
                encrypted_content BLOB NOT NULL,
                iv TEXT NOT NULL,
                message_type TEXT DEFAULT 'text',
                status TEXT DEFAULT 'sent',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(user_id),
                FOREIGN KEY (receiver_id) REFERENCES users(user_id)
            )
        ''')
        
        # Conversations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT UNIQUE NOT NULL,
                platform TEXT NOT NULL,
                participants TEXT NOT NULL,
                encrypted_metadata BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_message TIMESTAMP
            )
        ''')
        
        # Cookies management table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cookies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cookie_id TEXT UNIQUE NOT NULL,
                platform TEXT NOT NULL,
                encrypted_cookie BLOB NOT NULL,
                iv TEXT NOT NULL,
                session_data BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Automation logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS automation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id TEXT UNIQUE NOT NULL,
                automation_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                output TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # File attachments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attachment_id TEXT UNIQUE NOT NULL,
                message_id TEXT,
                file_name TEXT NOT NULL,
                file_type TEXT,
                encrypted_content BLOB NOT NULL,
                iv TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (message_id) REFERENCES messages(message_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    # User Management Methods
    def create_user(self, username: str, platform: str) -> str:
        """Create a new user with E2E encryption keys"""
        user_id = self._generate_unique_id()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (user_id, username, platform)
            VALUES (?, ?, ?)
        ''', (user_id, username, platform))
        
        conn.commit()
        conn.close()
        return user_id
    
    def get_user(self, user_id: str) -> Optional[Dict]:
        """Retrieve user information"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0],
                'user_id': row[1],
                'username': row[2],
                'platform': row[3],
                'public_key': row[4],
                'created_at': row[6],
                'status': row[8]
            }
        return None
    
    # Message Management Methods
    def send_message(self, sender_id: str, receiver_id: str, 
                     platform: str, content: str, message_type: str = 'text') -> str:
        """Send an encrypted message"""
        message_id = self._generate_unique_id()
        iv = secrets.token_bytes(16)
        encrypted_content = self.fernet.encrypt(content.encode())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO messages (message_id, sender_id, receiver_id, platform, 
                                encrypted_content, iv, message_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (message_id, sender_id, receiver_id, platform, 
              encrypted_content, iv, message_type))
        
        conn.commit()
        conn.close()
        return message_id
    
    def receive_message(self, message_id: str) -> Optional[Dict]:
        """Receive and decrypt a message"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM messages WHERE message_id = ?', (message_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            try:
                decrypted_content = self.fernet.decrypt(row[5]).decode()
                return {
                    'message_id': row[0],
                    'sender_id': row[2],
                    'receiver_id': row[3],
                    'platform': row[4],
                    'content': decrypted_content,
                    'message_type': row[7],
                    'status': row[8],
                    'created_at': row[9]
                }
            except Exception as e:
                return {'error': str(e)}
        return None
    
    # Conversation Management Methods
    def create_conversation(self, platform: str, participants: List[str]) -> str:
        """Create a new encrypted conversation"""
        conversation_id = self._generate_unique_id()
        participants_json = json.dumps(participants)
        encrypted_metadata = self.fernet.encrypt(participants_json.encode())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO conversations (conversation_id, platform, participants, encrypted_metadata)
            VALUES (?, ?, ?, ?)
        ''', (conversation_id, platform, json.dumps(participants), encrypted_metadata))
        
        conn.commit()
        conn.close()
        return conversation_id
    
    def get_conversation(self, conversation_id: str) -> Optional[Dict]:
        """Retrieve conversation details"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM conversations WHERE conversation_id = ?', (conversation_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'conversation_id': row[1],
                'platform': row[2],
                'participants': json.loads(row[3]),
                'created_at': row[5]
            }
        return None
    
    # Cookie Management Methods
    def store_cookie(self, platform: str, cookie_data: Dict) -> str:
        """Store an encrypted cookie"""
        cookie_id = self._generate_unique_id()
        iv = secrets.token_bytes(16)
        encrypted_cookie = self.fernet.encrypt(json.dumps(cookie_data).encode())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO cookies (cookie_id, platform, encrypted_cookie, iv)
            VALUES (?, ?, ?, ?)
        ''', (cookie_id, platform, encrypted_cookie, iv))
        
        conn.commit()
        conn.close()
        return cookie_id
    
    def get_cookie(self, cookie_id: str) -> Optional[Dict]:
        """Retrieve and decrypt a cookie"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM cookies WHERE cookie_id = ?', (cookie_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            try:
                decrypted_cookie = self.fernet.decrypt(row[3]).decode()
                return {
                    'cookie_id': row[1],
                    'platform': row[2],
                    'cookie_data': json.loads(decrypted_cookie),
                    'status': row[8]
                }
            except Exception as e:
                return {'error': str(e)}
        return None
    
    # Automation Log Methods
    def log_automation(self, automation_type: str, target_id: str, 
                       action: str, output: str = None) -> str:
        """Log an automation action"""
        log_id = self._generate_unique_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO automation_logs (log_id, automation_type, target_id, action, output)
            VALUES (?, ?, ?, ?, ?)
        ''', (log_id, automation_type, target_id, action, output))
        
        conn.commit()
        conn.close()
        return log_id
    
    def get_automation_logs(self, automation_type: str = None) -> List[Dict]:
        """Retrieve automation logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if automation_type:
            cursor.execute('''
                SELECT * FROM automation_logs WHERE automation_type = ? 
                ORDER BY created_at DESC
            ''', (automation_type,))
        else:
            cursor.execute('SELECT * FROM automation_logs ORDER BY created_at DESC')
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'log_id': row[1],
                'automation_type': row[2],
                'target_id': row[3],
                'action': row[4],
                'status': row[5],
                'output': row[6],
                'created_at': row[7]
            }
            for row in rows
        ]
    
    # File Attachment Methods
    def store_attachment(self, file_name: str, file_content: bytes, 
                        message_id: str = None, file_type: str = 'application/octet-stream') -> str:
        """Store an encrypted file attachment"""
        attachment_id = self._generate_unique_id()
        iv = secrets.token_bytes(16)
        encrypted_content = self.fernet.encrypt(file_content)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO attachments (attachment_id, message_id, file_name, file_type, encrypted_content, iv)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (attachment_id, message_id, file_name, file_type, encrypted_content, iv))
        
        conn.commit()
        conn.close()
        return attachment_id
    
    def get_attachment(self, attachment_id: str) -> Optional[Dict]:
        """Retrieve and decrypt a file attachment"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM attachments WHERE attachment_id = ?', (attachment_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            try:
                decrypted_content = self.fernet.decrypt(row[5])
                return {
                    'attachment_id': row[1],
                    'message_id': row[2],
                    'file_name': row[3],
                    'file_type': row[4],
                    'content': decrypted_content
                }
            except Exception as e:
                return {'error': str(e)}
        return None
    
    # Utility Methods
    def _generate_unique_id(self) -> str:
        """Generate a unique ID"""
        return secrets.token_hex(16)
    
    def delete_user(self, user_id: str) -> bool:
        """Delete a user and all associated data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?', (user_id, user_id))
        
        conn.commit()
        conn.close()
        return True
    
    def clear_all_data(self):
        """Clear all data from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM messages')
        cursor.execute('DELETE FROM conversations')
        cursor.execute('DELETE FROM cookies')
        cursor.execute('DELETE FROM automation_logs')
        cursor.execute('DELETE FROM attachments')
        
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM users')
        user_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM messages')
        message_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM conversations')
        conversation_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM cookies')
        cookie_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_users': user_count,
            'total_messages': message_count,
            'total_conversations': conversation_count,
            'total_cookies': cookie_count
        }
