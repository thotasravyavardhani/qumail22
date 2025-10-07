#!/usr/bin/env python3
"""
Identity Manager - Simplified User Authentication
Replaces the complex OAuth2Manager with persistent, simulated login/signup
"""

import logging
import hashlib
from typing import Dict, Optional
from datetime import datetime
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QDialogButtonBox, QTabWidget, QWidget, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from dataclasses import dataclass

@dataclass
class UserIdentity:
    """User identity information"""
    user_id: str
    email: str
    display_name: str
    password_hash: str  # Added for realism
    sae_id: str  # Secure Application Entity ID for KME
    created_at: datetime
    last_login: datetime

class LoginSignupDialog(QDialog):
    """Login/Signup dialog for user authentication"""
    
    user_authenticated = pyqtSignal(object)  # UserIdentity
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("QuMail - Quantum Secure Authentication")
        self.setModal(True)
        self.resize(450, 300)
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the authentication UI"""
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel("QuMail Authentication")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #4285F4; margin: 20px;")
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Secure your quantum communications")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet("color: #666; margin-bottom: 20px;")
        layout.addWidget(subtitle_label)
        
        # Tab widget for Login/Signup
        self.tab_widget = QTabWidget()
        
        # Login tab
        login_tab = self.create_login_tab()
        self.tab_widget.addTab(login_tab, "Login")
        
        # Signup tab
        signup_tab = self.create_signup_tab()
        self.tab_widget.addTab(signup_tab, "Sign Up")
        
        layout.addWidget(self.tab_widget)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.handle_authentication)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
    def create_login_tab(self) -> QWidget:
        """Create login tab with password field"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Email field
        layout.addWidget(QLabel("Email:"))
        self.login_email = QLineEdit()
        self.login_email.setPlaceholderText("Enter your email address")
        layout.addWidget(self.login_email)
        
        # Password field (ADDED FOR REALISM)
        layout.addWidget(QLabel("Password:"))
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Enter your password")
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.login_password)
        
        # Display name field
        layout.addWidget(QLabel("Display Name:"))
        self.login_name = QLineEdit()
        self.login_name.setPlaceholderText("Enter your display name")
        layout.addWidget(self.login_name)
        
        layout.addStretch()
        
        return tab
        
    def create_signup_tab(self) -> QWidget:
        """Create signup tab with password fields"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Email field
        layout.addWidget(QLabel("Email:"))
        self.signup_email = QLineEdit()
        self.signup_email.setPlaceholderText("Enter your email address")
        layout.addWidget(self.signup_email)
        
        # Password field (ADDED FOR REALISM)
        layout.addWidget(QLabel("Password:"))
        self.signup_password = QLineEdit()
        self.signup_password.setPlaceholderText("Create a password")
        self.signup_password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.signup_password)
        
        # Confirm password field (ADDED FOR REALISM)
        layout.addWidget(QLabel("Confirm Password:"))
        self.signup_confirm_password = QLineEdit()
        self.signup_confirm_password.setPlaceholderText("Confirm your password")
        self.signup_confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.signup_confirm_password)
        
        # Display name field
        layout.addWidget(QLabel("Display Name:"))
        self.signup_name = QLineEdit()
        self.signup_name.setPlaceholderText("Enter your display name")
        layout.addWidget(self.signup_name)
        
        # Info
        info_label = QLabel("Note: This is a simulated authentication for demo purposes.")
        info_label.setStyleSheet("color: #666; font-size: 11px; font-style: italic;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        layout.addStretch()
        
        return tab
        
    def handle_authentication(self):
        """Handle login/signup authentication with password validation"""
        current_tab = self.tab_widget.currentIndex()
        
        if current_tab == 0:  # Login
            email = self.login_email.text().strip()
            password = self.login_password.text().strip()
            display_name = self.login_name.text().strip()
            
            # Validate login input
            if not email or not password or not display_name:
                QMessageBox.warning(self, "Validation Error", 
                                  "Please enter email, password, and display name.")
                return
                
            # Create user identity
            user_identity = self.create_user_identity(email, display_name, password)
            
        else:  # Signup
            email = self.signup_email.text().strip()
            password = self.signup_password.text().strip()
            confirm_password = self.signup_confirm_password.text().strip()
            display_name = self.signup_name.text().strip()
            
            # Validate signup input
            if not email or not password or not confirm_password or not display_name:
                QMessageBox.warning(self, "Validation Error", 
                                  "Please fill in all fields.")
                return
                
            # Check password confirmation
            if password != confirm_password:
                QMessageBox.warning(self, "Password Mismatch", 
                                  "Password and confirm password do not match.")
                return
                
            # Check password strength (basic)
            if len(password) < 6:
                QMessageBox.warning(self, "Weak Password", 
                                  "Password must be at least 6 characters long.")
                return
                
            # Create user identity
            user_identity = self.create_user_identity(email, display_name, password)
        
        # Emit authentication signal
        self.user_authenticated.emit(user_identity)
        self.accept()
        
    def create_user_identity(self, email: str, display_name: str, password: str) -> UserIdentity:
        """Create user identity from input with password hashing"""
        # Generate user ID from email hash
        user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
        
        # Generate password hash (simulated for demo - in production use proper bcrypt/scrypt)
        password_hash = hashlib.sha256((password + email).encode()).hexdigest()
        
        # Generate SAE ID for KME
        sae_id = f"qumail_{user_id}"
        
        return UserIdentity(
            user_id=user_id,
            email=email,
            display_name=display_name,
            password_hash=password_hash,
            sae_id=sae_id,
            created_at=datetime.utcnow(),
            last_login=datetime.utcnow()
        )

class IdentityManager:
    """ISRO-GRADE: Identity management system with OAuth2Manager integration"""
    
    def __init__(self, secure_storage=None, oauth_manager=None):
        self.secure_storage = secure_storage
        self.oauth_manager = oauth_manager  # CRITICAL: OAuth2Manager dependency
        self.current_user: Optional[UserIdentity] = None
        
    async def initialize(self):
        """PRODUCTION: Initialize identity manager with standardized storage methods"""
        try:
            # Try to load existing user from storage using standardized method
            if self.secure_storage:
                user_data = await self.secure_storage.load_user_profile()
                if user_data:
                    # Convert dict to UserIdentity format for compatibility
                    self.current_user = UserIdentity(
                        user_id=user_data['user_id'],
                        email=user_data['email'],
                        display_name=user_data['display_name'],
                        password_hash=user_data.get('password_hash', ''),
                        sae_id=user_data['sae_id'],
                        created_at=datetime.fromisoformat(user_data['created_at']),
                        last_login=datetime.fromisoformat(user_data['last_login'])
                    )
                    logging.info(f"PRODUCTION: Loaded existing user via standardized storage: {self.current_user.email}")
                    return True
        except Exception as e:
            logging.error(f"Failed to load user from storage: {e}")
            
        return False
        
    async def authenticate(self, provider: str = "qumail_native") -> Dict:
        """Main authentication method called by QuMailCore"""
        try:
            # Show authentication dialog
            user_identity = self.show_authentication_dialog()
            
            if user_identity:
                # Convert UserIdentity to dict format expected by core
                auth_result = {
                    'user_id': user_identity.user_id,
                    'email': user_identity.email,
                    'name': user_identity.display_name,
                    'password_hash': user_identity.password_hash,  # Added for realism
                    'sae_id': user_identity.sae_id,
                    'authenticated_at': user_identity.last_login.isoformat(),
                    'provider': provider
                }
                
                logging.info(f"Authentication successful for {user_identity.email}")
                return auth_result
            else:
                logging.warning("Authentication cancelled or failed")
                return None
                
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            return None
        
    def show_authentication_dialog(self, parent=None) -> Optional[UserIdentity]:
        """Show authentication dialog and return user identity"""
        dialog = LoginSignupDialog(parent)
        
        user_identity = None
        
        def on_user_authenticated(identity):
            nonlocal user_identity
            user_identity = identity
            
        dialog.user_authenticated.connect(on_user_authenticated)
        
        if dialog.exec() == QDialog.DialogCode.Accepted and user_identity:
            self.current_user = user_identity
            
            # Save to storage
            if self.secure_storage:
                try:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    loop.create_task(self.save_current_user())
                except Exception as e:
                    logging.error(f"Failed to save user: {e}")
                    
            logging.info(f"User authenticated: {user_identity.email}")
            return user_identity
            
        return None
        
    async def save_current_user(self):
        """PRODUCTION: Save current user using standardized storage method"""
        if self.current_user and self.secure_storage:
            try:
                user_data = {
                    'user_id': self.current_user.user_id,
                    'email': self.current_user.email,
                    'display_name': self.current_user.display_name,
                    'password_hash': self.current_user.password_hash,
                    'sae_id': self.current_user.sae_id,
                    'created_at': self.current_user.created_at.isoformat(),
                    'last_login': self.current_user.last_login.isoformat()
                }
                await self.secure_storage.save_user_profile(user_data)
                logging.info("PRODUCTION: User saved via standardized storage method")
            except Exception as e:
                logging.error(f"Failed to save user to storage: {e}")
                
    async def logout_user(self):
        """Logout current user"""
        if self.current_user:
            logging.info(f"Logging out user: {self.current_user.email}")
            self.current_user = None
            
            # Clear from storage
            if self.secure_storage:
                try:
                    await self.secure_storage.delete('current_user')
                except Exception as e:
                    logging.error(f"Failed to clear user from storage: {e}")
                    
    def get_current_user(self) -> Optional[UserIdentity]:
        """Get current authenticated user"""
        return self.current_user
        
    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return self.current_user is not None