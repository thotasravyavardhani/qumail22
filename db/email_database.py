#!/usr/bin/env python3
"""
QuMail Email Database - Shared SQLite Database for Email Storage
Enables real email delivery between QuMail users
"""

import sqlite3
import json
import logging
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from contextlib import asynccontextmanager

class EmailDatabase:
    """Shared database for storing and retrieving emails between QuMail users"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = str(Path.home() / '.qumail' / 'data' / 'emails.db')
        
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database schema
        self._init_database()
        logging.info(f"Email database initialized at {db_path}")
    
    def _init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create emails table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT UNIQUE NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT,
                body TEXT,
                encrypted_payload TEXT,
                security_level TEXT,
                sent_at TEXT NOT NULL,
                read_status INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                display_name TEXT,
                password_hash TEXT,
                sae_id TEXT,
                provider TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            )
        ''')
        
        # Create indexes for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_recipient ON emails(recipient)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sender ON emails(sender)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sent_at ON emails(sent_at DESC)')
        
        conn.commit()
        conn.close()
        logging.info("Database schema initialized successfully")
    
    async def store_email(self, email_data: Dict[str, Any]) -> bool:
        """
        Store an email in the shared database
        
        Args:
            email_data: Dictionary containing email information
                - email_id: Unique message ID
                - sender: Sender email address
                - recipient: Recipient email address
                - subject: Email subject (optional)
                - body: Email body (optional)
                - encrypted_payload: JSON encrypted payload
                - security_level: Security level used (L1-L4)
                - sent_at: Timestamp
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Run database operation in executor to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._store_email_sync, email_data)
            
            logging.info(f"Email stored: {email_data['email_id']} from {email_data['sender']} to {email_data['recipient']}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to store email: {e}")
            return False
    
    def _store_email_sync(self, email_data: Dict[str, Any]):
        """Synchronous email storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Convert encrypted_payload to JSON string if it's a dict
        encrypted_payload = email_data.get('encrypted_payload', {})
        if isinstance(encrypted_payload, dict):
            encrypted_payload = json.dumps(encrypted_payload)
        
        cursor.execute('''
            INSERT INTO emails (email_id, sender, recipient, subject, body, 
                              encrypted_payload, security_level, sent_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            email_data['email_id'],
            email_data['sender'],
            email_data['recipient'],
            email_data.get('subject', ''),
            email_data.get('body', ''),
            encrypted_payload,
            email_data.get('security_level', 'L2'),
            email_data.get('sent_at', datetime.utcnow().isoformat())
        ))
        
        conn.commit()
        conn.close()
    
    async def get_inbox(self, recipient: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve inbox emails for a recipient
        
        Args:
            recipient: Recipient email address
            limit: Maximum number of emails to retrieve
        
        Returns:
            List of email dictionaries
        """
        try:
            loop = asyncio.get_event_loop()
            emails = await loop.run_in_executor(None, self._get_inbox_sync, recipient, limit)
            
            logging.info(f"Retrieved {len(emails)} emails for {recipient}")
            return emails
            
        except Exception as e:
            logging.error(f"Failed to retrieve inbox: {e}")
            return []
    
    def _get_inbox_sync(self, recipient: str, limit: int) -> List[Dict[str, Any]]:
        """Synchronous inbox retrieval"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM emails 
            WHERE recipient = ? 
            ORDER BY sent_at DESC 
            LIMIT ?
        ''', (recipient, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        emails = []
        for row in rows:
            email = dict(row)
            # Parse encrypted_payload back to dict
            if email['encrypted_payload']:
                try:
                    email['encrypted_payload'] = json.loads(email['encrypted_payload'])
                except:
                    pass
            emails.append(email)
        
        return emails
    
    async def get_sent_emails(self, sender: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve sent emails for a sender
        
        Args:
            sender: Sender email address
            limit: Maximum number of emails to retrieve
        
        Returns:
            List of email dictionaries
        """
        try:
            loop = asyncio.get_event_loop()
            emails = await loop.run_in_executor(None, self._get_sent_emails_sync, sender, limit)
            
            logging.info(f"Retrieved {len(emails)} sent emails for {sender}")
            return emails
            
        except Exception as e:
            logging.error(f"Failed to retrieve sent emails: {e}")
            return []
    
    def _get_sent_emails_sync(self, sender: str, limit: int) -> List[Dict[str, Any]]:
        """Synchronous sent emails retrieval"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM emails 
            WHERE sender = ? 
            ORDER BY sent_at DESC 
            LIMIT ?
        ''', (sender, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        emails = []
        for row in rows:
            email = dict(row)
            # Parse encrypted_payload back to dict
            if email['encrypted_payload']:
                try:
                    email['encrypted_payload'] = json.loads(email['encrypted_payload'])
                except:
                    pass
            emails.append(email)
        
        return emails
    
    async def mark_as_read(self, email_id: str) -> bool:
        """Mark an email as read"""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._mark_as_read_sync, email_id)
            return True
        except Exception as e:
            logging.error(f"Failed to mark email as read: {e}")
            return False
    
    def _mark_as_read_sync(self, email_id: str):
        """Synchronous mark as read"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE emails 
            SET read_status = 1 
            WHERE email_id = ?
        ''', (email_id,))
        
        conn.commit()
        conn.close()
    
    async def get_unread_count(self, recipient: str) -> int:
        """Get count of unread emails"""
        try:
            loop = asyncio.get_event_loop()
            count = await loop.run_in_executor(None, self._get_unread_count_sync, recipient)
            return count
        except Exception as e:
            logging.error(f"Failed to get unread count: {e}")
            return 0
    
    def _get_unread_count_sync(self, recipient: str) -> int:
        """Synchronous unread count"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM emails 
            WHERE recipient = ? AND read_status = 0
        ''', (recipient,))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count
    
    async def store_user(self, user_data: Dict[str, Any]) -> bool:
        """Store user information"""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._store_user_sync, user_data)
            return True
        except Exception as e:
            logging.error(f"Failed to store user: {e}")
            return False
    
    def _store_user_sync(self, user_data: Dict[str, Any]):
        """Synchronous user storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO users 
            (email, display_name, password_hash, sae_id, provider, last_login)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_data['email'],
            user_data.get('display_name', ''),
            user_data.get('password_hash', ''),
            user_data.get('sae_id', ''),
            user_data.get('provider', ''),
            datetime.utcnow().isoformat()
        ))
        
        conn.commit()
        conn.close()
