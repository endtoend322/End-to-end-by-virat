"""
Database Models for E2EE Messenger
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import hashlib
import json

db = SQLAlchemy()

class User(db.Model):
    """User Account Model"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(50), unique=True, nullable=False, index=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    salt = db.Column(db.String(100), nullable=False)
    
    # E2EE Keys
    public_key = db.Column(db.Text)
    private_key_encrypted = db.Column(db.Text)
    
    # Facebook Integration
    fb_uid = db.Column(db.String(50))
    fb_cookie_encrypted = db.Column(db.Text)
    
    # Profile
    avatar = db.Column(db.String(200))
    bio = db.Column(db.Text)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic')
    sessions = db.relationship('Session', backref='user', lazy='dynamic')
    
    def to_dict(self):
        """Convert user to dictionary (safe version)"""
        return {
            'uid': self.uid,
            'username': self.username,
            'email': self.email,
            'avatar': self.avatar,
            'bio': self.bio,
            'public_key': self.public_key,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_verified': self.is_verified
        }
    
    def __repr__(self):
        return f'<User {self.email}>'

class Session(db.Model):
    """User Session Model (1 year persistence)"""
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(200), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Cookie Data
    cookie_token = db.Column(db.String(500), unique=True, nullable=False)
    cookie_data = db.Column(db.Text)
    
    # Security
    user_agent = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    
    # Expiry (1 year)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_accessed = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_valid(self):
        """Check if session is still valid"""
        return datetime.utcnow() < self.expires_at
    
    def __repr__(self):
        return f'<Session {self.session_id[:8]}...>'

class Message(db.Model):
    """Encrypted Message Model"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Encrypted Content
    encrypted_content = db.Column(db.Text, nullable=False)
    encrypted_file = db.Column(db.Text)
    file_name = db.Column(db.String(255))
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(100))
    
    # E2EE Metadata
    signature = db.Column(db.String(500))
    key_id = db.Column(db.String(100))
    
    # Status
    is_delivered = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False)
    is_offline = db.Column(db.Boolean, default=False)
    delivery_attempts = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    delivered_at = db.Column(db.DateTime)
    read_at = db.Column(db.DateTime)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_chat_time', chat_id, created_at),
        db.Index('idx_receiver_delivered', receiver_id, is_delivered),
    )
    
    def to_dict(self):
        """Convert message to dictionary"""
        return {
            'id': self.id,
            'chat_id': self.chat_id,
            'sender': self.sender.uid if self.sender else None,
            'receiver': self.receiver.uid if self.receiver else None,
            'encrypted_content': self.encrypted_content,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'is_delivered': self.is_delivered,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class OfflineQueue(db.Model):
    """Offline Message Queue"""
    __tablename__ = 'offline_queue'
    
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Queue Status
    retry_count = db.Column(db.Integer, default=0)
    max_retries = db.Column(db.Integer, default=5)
    next_retry = db.Column(db.DateTime)
    is_processed = db.Column(db.Boolean, default=False)
    error_message = db.Column(db.Text)
    
    # Timestamps
    queued_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    last_attempt = db.Column(db.DateTime)
    
    # Relationships
    message = db.relationship('Message', backref='queue_items')
    
    __table_args__ = (
        db.Index('idx_queue_retry', next_retry, is_processed),
    )

class LoginAttempt(db.Model):
    """Login Attempt Tracking for Security"""
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    success = db.Column(db.Boolean, default=False)
    attempt_time = db.Column(db.DateTime, default=datetime.utcnow)

class UserKey(db.Model):
    """Additional E2EE Keys Storage"""
    __tablename__ = 'user_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    key_type = db.Column(db.String(50))  # 'e2ee', 'backup', 'recovery'
    public_key = db.Column(db.Text, nullable=False)
    encrypted_private_key = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    user = db.relationship('User', backref='keys')

class Chat(db.Model):
    """Chat Room Model"""
    __tablename__ = 'chats'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200))
    type = db.Column(db.String(50))  # 'direct', 'group'
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    participants = db.relationship('ChatParticipant', backref='chat', lazy='dynamic')

class ChatParticipant(db.Model):
    """Chat Participants"""
    __tablename__ = 'chat_participants'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_read = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Relationships
    user = db.relationship('User', backref='chats')
