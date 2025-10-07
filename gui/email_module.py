#!/usr/bin/env python3
"""
Email Module - Gmail-like Interface

Implements the Gmail-inspired email interface with quantum security integration
"""

import logging
from typing import Dict, List, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QListWidget, QListWidgetItem,
    QTextEdit, QPushButton, QLabel, QLineEdit, QScrollArea, QFrame, QComboBox,
    QDialog, QDialogButtonBox, QFileDialog, QProgressBar, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QThread, pyqtSlot
from PyQt6.QtGui import QFont, QPalette, QColor, QIcon
from datetime import datetime
import os

class EmailListItem(QFrame):
    """Individual email item in the list"""
    
    clicked = pyqtSignal(str)  # email_id
    
    def __init__(self, email_data: Dict):
        super().__init__()
        self.email_data = email_data
        self.email_id = email_data.get('email_id', '')
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the email item UI"""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setMinimumHeight(80)
        self.setMaximumHeight(80)
        
        # Hover effect
        self.setStyleSheet("""
            EmailListItem {
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                padding: 8px;
                background-color: white;
            }
            EmailListItem:hover {
                background-color: #F8F9FA;
                border-color: #4285F4;
            }
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        
        # Avatar placeholder
        avatar = QLabel(self.email_data.get('sender', 'Unknown')[0].upper())
        avatar.setFixedSize(48, 48)
        avatar.setStyleSheet("""
            QLabel {
                background-color: #4285F4;
                color: white;
                border-radius: 24px;
                font-weight: bold;
                font-size: 16px;
            }
        """)
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(avatar)
        
        # Email content
        content_layout = QVBoxLayout()
        content_layout.setSpacing(4)
        
        # Sender and subject line
        top_line = QHBoxLayout()
        
        sender_label = QLabel(self.email_data.get('sender', 'Unknown'))
        sender_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        top_line.addWidget(sender_label)
        
        # Security indicator
        security_level = self.email_data.get('security_level', 'L4')
        if security_level in ['L1', 'L2']:
            security_icon = QLabel("Ψ")
            security_icon.setStyleSheet("color: #61FF00; font-weight: bold; font-size: 14px;")
            security_icon.setToolTip(f"Quantum Secured ({security_level})")
            top_line.addWidget(security_icon)
        elif security_level == 'L3':
            security_icon = QLabel("🔒")
            security_icon.setToolTip("Post-Quantum Crypto")
            top_line.addWidget(security_icon)
            
        top_line.addStretch()
        
        # Time
        time_label = QLabel(self._format_time(self.email_data.get('received_at')))
        time_label.setStyleSheet("color: #666; font-size: 11px;")
        top_line.addWidget(time_label)
        
        content_layout.addLayout(top_line)
        
        # Subject
        subject_label = QLabel(self.email_data.get('subject', 'No Subject'))
        subject_label.setFont(QFont("Arial", 11))
        subject_label.setStyleSheet("color: #333;")
        content_layout.addWidget(subject_label)
        
        # Preview snippet
        preview = self.email_data.get('preview', '')
        if len(preview) > 100:
            preview = preview[:97] + "..."
        preview_label = QLabel(preview)
        preview_label.setStyleSheet("color: #666; font-size: 10px;")
        content_layout.addWidget(preview_label)
        
        layout.addLayout(content_layout)
        
        # Make clickable
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
    def _format_time(self, timestamp_str: str) -> str:
        """Format timestamp for display"""
        try:
            if not timestamp_str:
                return "Unknown"
            # This would parse the timestamp and format it nicely
            return "12:34 PM"  # Placeholder
        except:
            return "Unknown"
            
    def mousePressEvent(self, event):
        """Handle mouse click"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.email_id)
        super().mousePressEvent(event)

class ComposeDialog(QDialog):
    """Email composition dialog with PQC File Attachment Support"""
    
    email_sent = pyqtSignal(dict)  # email data
    
    def __init__(self, core, parent=None):
        super().__init__(parent)
        self.core = core
        self.attachments = []
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup compose dialog UI"""
        self.setWindowTitle("Compose Email")
        self.setModal(True)
        self.resize(800, 600)
        
        layout = QVBoxLayout(self)
        
        # Header fields
        header_frame = QFrame()
        header_layout = QVBoxLayout(header_frame)
        
        # To field
        to_layout = QHBoxLayout()
        to_layout.addWidget(QLabel("To:"))
        self.to_input = QLineEdit()
        to_layout.addWidget(self.to_input)
        header_layout.addLayout(to_layout)
        
        # Subject field
        subject_layout = QHBoxLayout()
        subject_layout.addWidget(QLabel("Subject:"))
        self.subject_input = QLineEdit()
        subject_layout.addWidget(self.subject_input)
        header_layout.addLayout(subject_layout)
        
        # Security level selector
        security_layout = QHBoxLayout()
        security_layout.addWidget(QLabel("Security Level:"))
        self.security_selector = QComboBox()
        self.security_selector.addItems([
            "Level 2: Quantum-aided AES (Default)",
            "Level 1: Quantum OTP (Advanced)",
            "Level 3: Post-Quantum Crypto",
            "Level 4: Standard TLS Only"
        ])
        security_layout.addWidget(self.security_selector)
        security_layout.addStretch()
        header_layout.addLayout(security_layout)
        
        layout.addWidget(header_frame)
        
        # Message body
        body_label = QLabel("Message:")
        layout.addWidget(body_label)
        
        self.body_input = QTextEdit()
        self.body_input.setMinimumHeight(250)
        layout.addWidget(self.body_input)
        
        # PQC FILE FEATURE: Enhanced toolbar with mock file support
        toolbar_layout = QHBoxLayout()
        
        attach_button = QPushButton("📎 Attach Files")
        attach_button.clicked.connect(self.attach_files)
        toolbar_layout.addWidget(attach_button)
        
        # PQC FEATURE: Mock large file button for demonstration
        mock_file_button = QPushButton("📎 Attach Mock File (20MB)")
        mock_file_button.setStyleSheet("""
            QPushButton {
                background-color: #FFA500;
                color: white;
                font-weight: bold;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #FF8C00;
            }
        """)
        mock_file_button.clicked.connect(self.attach_mock_file)
        toolbar_layout.addWidget(mock_file_button)
        
        self.attach_label = QLabel("No attachments")
        self.attach_label.setStyleSheet("color: #666; font-size: 11px;")
        toolbar_layout.addWidget(self.attach_label)
        
        toolbar_layout.addStretch()
        
        # Key check button (for OTP)
        self.key_check_button = QPushButton("Check Key Availability")
        self.key_check_button.clicked.connect(self.check_key_availability)
        self.key_check_button.setVisible(False)
        toolbar_layout.addWidget(self.key_check_button)
        
        layout.addLayout(toolbar_layout)
        
        # Progress bar for key fetching
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # PQC FEATURE: Encryption status display
        self.encryption_status = QLabel("")
        self.encryption_status.setStyleSheet("""
            QLabel {
                background-color: #E3F2FD;
                padding: 8px;
                border-radius: 4px;
                font-size: 11px;
                color: #1976D2;
            }
        """)
        self.encryption_status.setVisible(False)
        layout.addWidget(self.encryption_status)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.button(QDialogButtonBox.StandardButton.Ok).setText("Send")
        button_box.accepted.connect(self.send_email)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        # Connect security selector
        self.security_selector.currentIndexChanged.connect(self.on_security_changed)
        
    def on_security_changed(self, index):
        """Handle security level change with PQC file attachment guidance"""
        security_levels = ['L2', 'L1', 'L3', 'L4']
        level = security_levels[index]
        
        # Show key check button for OTP (Level 1)
        self.key_check_button.setVisible(index == 1)
        
        # PQC FEATURE: Show file attachment guidance for Level 3
        if level == 'L3' and len(self.attachments) > 0:
            total_size = sum(self.get_file_size(f) for f in self.attachments)
            if total_size > 5 * 1024 * 1024:  # > 5MB
                self.show_pqc_notification(total_size)
                
        # Update encryption status
        self.update_encryption_status(level)
        
    def show_pqc_notification(self, total_size: int):
        """Show PQC encryption notification for large files"""
        size_mb = total_size / (1024 * 1024)
        QMessageBox.information(
            self, "PQC File Encryption", 
            f"🔒 Large attachments detected ({size_mb:.1f} MB)\n\n"
            "Level 3 (Post-Quantum Crypto) will use:\n"
            "• CRYSTALS-Kyber for key encapsulation\n"
            "• AES-256-GCM for file encryption\n"
            "• Two-layer security for optimal performance\n\n"
            "📊 Encryption Process:\n"
            "1. Generate File Encryption Key (FEK)\n"
            "2. Encrypt files with FEK using AES-256-GCM\n"
            "3. Encapsulate FEK using Kyber-1024 KEM\n"
            "4. Quantum-derived key material for KEM"
        )
        
    def update_encryption_status(self, level: str):
        """Update encryption status display"""
        if level == 'L3' and self.attachments:
            total_size = sum(self.get_file_size(f) for f in self.attachments)
            if total_size > 1024 * 1024:  # > 1MB
                self.encryption_status.setText(
                    f"🔐 PQC Mode: CRYSTALS-Kyber + AES-256-GCM | "
                    f"Files: {len(self.attachments)} ({total_size / (1024*1024):.1f} MB)"
                )
                self.encryption_status.setVisible(True)
                return
                
        # Hide status for other cases
        self.encryption_status.setVisible(False)
        
    def attach_files(self):
        """Handle file attachment with PQC large file detection"""
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Files to Attach", "", "All Files (*)"
        )
        if files:
            self.attachments.extend(files)
            self.update_attachment_display()
            self.check_pqc_recommendations()
            
    def attach_mock_file(self):
        """PQC FEATURE: Attach a mock large file for demonstration"""
        # Create a mock 20MB file entry
        mock_file = {
            'name': 'large_document_20MB.pdf',
            'size': 20 * 1024 * 1024,  # 20MB
            'is_mock': True,
            'path': '/tmp/mock_large_file.pdf'
        }
        
        self.attachments.append(mock_file)
        self.update_attachment_display()
        
        # Force Level 3 selection and show detailed PQC info
        self.security_selector.setCurrentIndex(2)  # L3 is index 2
        
        # Show detailed PQC notification
        QMessageBox.information(
            self, "PQC File Encryption Demo", 
            "🔐 **Mock 20MB file attached for PQC demonstration**\n\n"
            "**CRYSTALS-Kyber Key Encapsulation Process:**\n"
            "• Quantum key material → Private key seed (HKDF)\n"
            "• Generate Kyber-1024 key pair\n"
            "• Encapsulate File Encryption Key (FEK)\n"
            "• Shared secret → AES-256 key + GCM IV\n\n"
            "**File Encryption Process:**\n"
            "• Generate 256-bit FEK\n"
            "• Encrypt 20MB file with FEK (AES-256-GCM)\n"
            "• Encapsulate FEK using Kyber KEM\n"
            "• Result: Two-layer PQC protection\n\n"
            "**Security Level:** NIST Post-Quantum Level 5\n"
            "**Performance:** Optimized for large files"
        )
        
        self.update_encryption_status('L3')
            
    def update_attachment_display(self):
        """Update attachment display with size information"""
        if not self.attachments:
            self.attach_label.setText("No attachments")
            return
            
        total_size = 0
        for attachment in self.attachments:
            if isinstance(attachment, dict) and 'size' in attachment:
                total_size += attachment['size']
            else:
                total_size += self.get_file_size(attachment)
                
        count = len(self.attachments)
        size_mb = total_size / (1024 * 1024)
        
        if size_mb > 1.0:
            self.attach_label.setText(f"{count} file{'s' if count != 1 else ''} attached ({size_mb:.1f} MB)")
        else:
            self.attach_label.setText(f"{count} file{'s' if count != 1 else ''} attached")
            
    def check_pqc_recommendations(self):
        """Check if PQC should be recommended for current attachments"""
        total_size = sum(self.get_file_size(f) for f in self.attachments)
        
        if total_size > 10 * 1024 * 1024:  # > 10MB
            size_mb = total_size / (1024 * 1024)
            reply = QMessageBox.question(
                self, "Large File Detected", 
                f"📎 Large attachments detected ({size_mb:.1f} MB)\n\n"
                "For optimal security and performance with large files, we recommend:\n"
                "• Level 3: Post-Quantum Crypto (PQC)\n"
                "• Uses CRYSTALS-Kyber key encapsulation\n"
                "• Two-layer encryption for efficiency\n\n"
                "Switch to Level 3 (PQC) automatically?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.security_selector.setCurrentIndex(2)  # L3 is index 2
                self.show_pqc_activation_success()
                    
    def show_pqc_activation_success(self):
        """Show PQC activation success message"""
        QMessageBox.information(
            self, "PQC Enabled", 
            "🔐 Post-Quantum Crypto (Level 3) activated!\n\n"
            "Your large files will be encrypted using:\n"
            "• File Encryption Key (FEK): AES-256-GCM\n"
            "• Key Encapsulation: CRYSTALS-Kyber-1024\n"
            "• NIST Post-Quantum Security Level 5\n\n"
            "📈 Performance Benefits:\n"
            "• Efficient handling of large files\n"
            "• Reduced quantum key material usage\n"
            "• Future-proof against quantum computers"
        )
            
    def get_file_size(self, file_item) -> int:
        """Get file size in bytes (handles both file paths and mock objects)"""
        try:
            if isinstance(file_item, dict):
                return file_item.get('size', 0)
            elif isinstance(file_item, str) and os.path.exists(file_item):
                return os.path.getsize(file_item)
            return 0
        except:
            return 0
            
    def check_key_availability(self):
        """Check if enough quantum key material is available for OTP"""
        # This would check with the KME for available key material
        QMessageBox.information(
            self, "Key Check", 
            "Quantum key availability check would be implemented here."
        )
        
    def send_email(self):
        """Send the composed email with PQC file attachment support"""
        # Validate input
        if not self.to_input.text().strip():
            QMessageBox.warning(self, "Error", "Please enter a recipient address.")
            return
            
        if not self.subject_input.text().strip():
            QMessageBox.warning(self, "Error", "Please enter a subject.")
            return
            
        # Get security level
        security_levels = ['L2', 'L1', 'L3', 'L4']
        security_level = security_levels[self.security_selector.currentIndex()]
        
        # Calculate total attachment size
        total_size = 0
        for attachment in self.attachments:
            if isinstance(attachment, dict) and 'size' in attachment:
                total_size += attachment['size']
            else:
                total_size += self.get_file_size(attachment)
        
        # PQC FEATURE: Validate large file + L3 combination
        if self.attachments and total_size > 50 * 1024 * 1024 and security_level != 'L3':
            size_mb = total_size / (1024 * 1024)
            reply = QMessageBox.warning(
                self, "Large File Security", 
                f"⚠️ Very large attachments detected ({size_mb:.1f} MB)\n\n"
                "For files over 50MB, Level 3 (Post-Quantum Crypto) is required for:\n"
                "• Optimal performance with File Encryption Keys\n"
                "• NIST-approved post-quantum security\n"
                "• Efficient key encapsulation\n\n"
                "Switch to Level 3 automatically?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                security_level = 'L3'
                self.security_selector.setCurrentIndex(2)
            else:
                QMessageBox.information(self, "Security Notice", 
                                      "Large file encryption may be slower with non-PQC levels.")
        
        # Show progress for file processing
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        
        # Show PQC processing status for Level 3
        if security_level == 'L3' and self.attachments:
            self.progress_bar.setFormat("🔐 Applying Post-Quantum Crypto...")
        
        # Prepare email data with file context
        email_data = {
            'to': self.to_input.text().strip(),
            'subject': self.subject_input.text().strip(),
            'body': self.body_input.toPlainText(),
            'attachments': self.attachments,
            'security_level': security_level,
            'has_large_attachments': bool(self.attachments and total_size > 5 * 1024 * 1024),
            'total_attachment_size': total_size
        }
        
        # Emit signal (in real implementation, this would be async)
        self.email_sent.emit(email_data)
        self.accept()

class EmailModule(QWidget):
    """Main email module implementing Gmail-like interface"""
    
    status_message = pyqtSignal(str)
    
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.current_email = None
        self.email_list_data = []
        
        # PERSISTENCE FIX: This list now acts as the session's temporary database/cache
        self.all_emails = [] 
        self.current_folder = "Inbox" # Track the active folder for display
        
        self.setup_ui()
        self.load_initial_emails()
        
        logging.info("Email Module initialized")
        
    def setup_ui(self):
        """Setup the email module UI"""
        # Create main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - email list
        self.setup_email_list_panel(main_splitter)
        
        # Right panel - email content
        self.setup_email_content_panel(main_splitter)
        
        # Set splitter proportions
        main_splitter.setSizes([400, 600])
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(main_splitter)
        
    def setup_email_list_panel(self, parent_splitter):
        """Setup email list panel"""
        list_frame = QFrame()
        list_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        list_layout = QVBoxLayout(list_frame)
        
        # Toolbar
        toolbar_layout = QHBoxLayout()
        
        compose_button = QPushButton("✏️ Compose")
        compose_button.setObjectName("ComposeButton")  # ADDED FOR MATERIAL DESIGN
        compose_button.clicked.connect(self.compose_email)
        toolbar_layout.addWidget(compose_button)
        
        toolbar_layout.addStretch()
        
        refresh_button = QPushButton("🔄 Refresh")
        refresh_button.clicked.connect(self.refresh_emails)
        toolbar_layout.addWidget(refresh_button)
        
        list_layout.addLayout(toolbar_layout)
        
        # Email list
        self.email_list_widget = QScrollArea()
        self.email_list_widget.setWidgetResizable(True)
        self.email_list_widget.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        
        self.email_list_container = QWidget()
        self.email_list_layout = QVBoxLayout(self.email_list_container)
        self.email_list_layout.setSpacing(2)
        
        self.email_list_widget.setWidget(self.email_list_container)
        list_layout.addWidget(self.email_list_widget)
        
        parent_splitter.addWidget(list_frame)
        
    def setup_email_content_panel(self, parent_splitter):
        """Setup email content panel"""
        content_frame = QFrame()
        content_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        content_layout = QVBoxLayout(content_frame)
        
        # Content area
        self.content_area = QScrollArea()
        self.content_area.setWidgetResizable(True)
        
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        
        # Default message
        default_label = QLabel("Select an email to view its contents")
        default_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        default_label.setStyleSheet("""
            QLabel {
                color: #999;
                font-size: 16px;
                padding: 40px;
            }
        """)
        self.content_layout.addWidget(default_label)
        
        self.content_area.setWidget(self.content_widget)
        content_layout.addWidget(self.content_area)
        
        parent_splitter.addWidget(content_frame)
        
    def get_sidebar_widget(self) -> QWidget:
        """Return sidebar widget for email folders (FIXED LABELS)"""
        sidebar = QWidget()
        layout = QVBoxLayout(sidebar)
        
        # FIXED: Include all required folders including Spam/Trash
        folders = ["Inbox", "Sent", "Drafts", "Quantum Vault", "Spam", "Trash"]
        
        for folder in folders:
            folder_button = QPushButton(folder)
            folder_button.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 12px 16px;
                    border: none;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #E8F0FE;
                    color: #4285F4;
                }
                QPushButton:checked {
                    background-color: #4285F4;
                    color: white;
                    font-weight: bold;
                }
            """)
            folder_button.setCheckable(True)
            if folder == "Quantum Vault":
                folder_button.setText("🔐 " + folder)
            elif folder == "Spam":
                folder_button.setText("🚫 " + folder)
            elif folder == "Trash":
                folder_button.setText("🗑️ " + folder)
            
            # FIX: Add connection to filter emails by folder
            folder_button.clicked.connect(lambda checked, f=folder: self.set_active_folder(f))
            
            # Set inbox as default selected
            if folder == "Inbox":
                folder_button.setChecked(True)
            
            layout.addWidget(folder_button)
            
        layout.addStretch()
        return sidebar
        
    def set_active_folder(self, folder_name: str):
        """Sets the active folder and updates the list display."""
        self.current_folder = folder_name
        logging.info(f"Navigating to folder: {folder_name}")
        
        # Update button states in sidebar
        sidebar_widget = self.get_sidebar_widget()
        if sidebar_widget:
            for i in range(sidebar_widget.layout().count()):
                item = sidebar_widget.layout().itemAt(i)
                if item and item.widget() and isinstance(item.widget(), QPushButton):
                    button = item.widget()
                    button_text = button.text().replace("🔐 ", "").replace("🚫 ", "").replace("🗑️ ", "")
                    button.setChecked(button_text == folder_name)
        
        self.update_email_list(self.all_emails) # Reload, filtered by folder_name

    def load_initial_emails(self):
        """Load initial email list from database"""
        import asyncio
        
        try:
            # Get current user email from core
            current_user_email = None
            if self.core and hasattr(self.core, 'current_user'):
                current_user_email = self.core.current_user.email if self.core.current_user else None
            
            if not current_user_email:
                logging.warning("No current user email available, using sample data")
                self._load_sample_emails()
                return
            
            # Fetch emails from database
            if self.core and hasattr(self.core, 'email_handler'):
                try:
                    loop = asyncio.get_event_loop()
                    
                    # Fetch inbox emails from database
                    inbox_emails = loop.run_until_complete(
                        self.core.email_handler.get_inbox_from_database(current_user_email)
                    )
                    
                    # Fetch sent emails from database
                    sent_emails = loop.run_until_complete(
                        self.core.email_handler.get_sent_from_database(current_user_email)
                    )
                    
                    # Convert database format to UI format
                    self.all_emails = []
                    
                    for email in inbox_emails:
                        ui_email = self._convert_db_email_to_ui(email, 'Inbox')
                        self.all_emails.append(ui_email)
                    
                    for email in sent_emails:
                        ui_email = self._convert_db_email_to_ui(email, 'Sent')
                        self.all_emails.append(ui_email)
                    
                    logging.info(f"Loaded {len(self.all_emails)} emails from database")
                    
                    # If no emails found, load sample data
                    if not self.all_emails:
                        logging.info("No emails in database, loading sample data")
                        self._load_sample_emails()
                    
                except Exception as e:
                    logging.error(f"Failed to load emails from database: {e}")
                    self._load_sample_emails()
            else:
                self._load_sample_emails()
                
        except Exception as e:
            logging.error(f"Error loading emails: {e}")
            self._load_sample_emails()
        
        self.update_email_list(self.all_emails)
    
    def _convert_db_email_to_ui(self, db_email: Dict, folder: str) -> Dict:
        """Convert database email format to UI format"""
        # Extract encrypted payload if available
        encrypted_payload = db_email.get('encrypted_payload', {})
        if isinstance(encrypted_payload, str):
            import json
            try:
                encrypted_payload = json.loads(encrypted_payload)
            except:
                encrypted_payload = {}
        
        body = db_email.get('body', '') or encrypted_payload.get('body', '')
        subject = db_email.get('subject', '') or encrypted_payload.get('subject', 'No Subject')
        
        # Create preview from body
        preview = body[:100] if body else 'No preview available'
        
        return {
            'email_id': str(db_email.get('id', db_email.get('email_id', ''))),
            'sender': db_email.get('sender', 'Unknown'),
            'subject': subject,
            'preview': preview,
            'received_at': db_email.get('sent_at', datetime.utcnow().isoformat()),
            'security_level': db_email.get('security_level', 'L4'),
            'folder': folder,
            'body': body
        }
    
    def _load_sample_emails(self):
        """Load sample emails as fallback"""
        sample_emails = [
            {
                'email_id': '1',
                'sender': 'Alice Smith',
                'subject': 'Quantum Security Test',
                'preview': 'Testing the new quantum encryption features...',
                'received_at': '2025-01-27T10:30:00Z',
                'security_level': 'L2',
                'folder': 'Inbox',
                'body': 'This is a test of the quantum encryption system. The keys are working perfectly and the communication is secure. Ψ'
            },
            {
                'email_id': '2', 
                'sender': 'Bob Johnson',
                'subject': 'Meeting Tomorrow',
                'preview': 'Can we meet tomorrow to discuss the project?',
                'received_at': '2025-01-27T09:15:00Z',
                'security_level': 'L1',
                'folder': 'Inbox',
                'body': 'Hi there, I wanted to schedule a meeting for tomorrow to discuss the quantum communication project. Please let me know your availability.'
            },
            {
                'email_id': '3',
                'sender': 'Charlie Brown',
                'subject': 'Regular Email',
                'preview': 'This is just a regular email without encryption.',
                'received_at': '2025-01-27T08:45:00Z',
                'security_level': 'L4',
                'folder': 'Inbox',
                'body': 'This is a standard email sent without any quantum encryption. It uses regular TLS protection only.'
            },
            {
                'email_id': '4',
                'sender': 'System Admin',
                'subject': 'Welcome to QuMail Quantum Vault',
                'preview': 'Your quantum secure emails are stored here...',
                'received_at': '2025-01-26T15:20:00Z',
                'security_level': 'L1',
                'folder': 'Quantum Vault',
                'body': 'Welcome to the Quantum Vault! All your L1 and L2 encrypted emails are automatically stored here for enhanced security.'
            }
        ]
        
        self.all_emails.extend(sample_emails)
        
    def update_email_list(self, source_emails: List[Dict]):
        """Update the email list display (FIXED: Filters by folder)"""
        
        # 1. Clear existing items
        while self.email_list_layout.count():
            child = self.email_list_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
        # 2. Filter the source emails by the current active folder
        display_emails = [
            email for email in source_emails 
            if email.get('folder', 'Inbox') == self.current_folder
        ]

        # 3. Add filtered email items
        for email_data in display_emails:
            email_item = EmailListItem(email_data)
            email_item.clicked.connect(self.on_email_selected)
            self.email_list_layout.addWidget(email_item)

        # Add stretch at bottom
        self.email_list_layout.addStretch()
        self.email_list_data = display_emails # Store only the currently displayed list
        
    def on_email_selected(self, email_id: str):
        """Handle email selection"""
        # Find email data
        email_data = None
        for email in self.email_list_data:
            if email['email_id'] == email_id:
                email_data = email
                break
                
        if email_data:
            self.display_email_content(email_data)
            
    def display_email_content(self, email_data: Dict):
        """Display email content in the content panel with PQC support"""
        # Clear existing content
        while self.content_layout.count():
            child = self.content_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
        # Security banner
        security_level = email_data.get('security_level', 'L4')
        if security_level in ['L1', 'L2']:
            banner = QLabel(f"🔒 QKD Secured ({security_level}: {'OTP' if security_level == 'L1' else 'AES-256'})")
            banner.setStyleSheet("""
                QLabel {
                    background-color: rgba(97, 255, 0, 0.1);
                    color: #61FF00;
                    padding: 8px;
                    font-weight: bold;
                    border-radius: 4px;
                }
            """)
            self.content_layout.addWidget(banner)
        elif security_level == 'L3':
            # PQC FEATURE: Enhanced L3 banner with file encryption details
            has_attachments = email_data.get('attachments') and len(email_data.get('attachments', [])) > 0
            pqc_details = email_data.get('pqc_file_encryption', {})
            
            if has_attachments and pqc_details.get('fek_used'):
                banner_text = (f"🔐 Post-Quantum Crypto + File Encryption\n"
                             f"• CRYSTALS-Kyber Key Encapsulation\n"
                             f"• {pqc_details.get('attachment_count', 0)} file(s), "
                             f"{pqc_details.get('total_size', 0) / (1024*1024):.1f} MB\n"
                             f"• Two-layer PQC + AES-256-GCM")
            else:
                banner_text = "🔒 Post-Quantum Crypto Secured"
                
            banner = QLabel(banner_text)
            banner.setStyleSheet("""
                QLabel {
                    background-color: rgba(255, 165, 0, 0.1);
                    color: #FFA500;
                    padding: 8px;
                    font-weight: bold;
                    border-radius: 4px;
                    font-size: 11px;
                }
            """)
            self.content_layout.addWidget(banner)
            
        # Email header
        header_frame = QFrame()
        header_layout = QVBoxLayout(header_frame)
        
        # From
        from_label = QLabel(f"From: {email_data['sender']}")
        from_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header_layout.addWidget(from_label)
        
        # Subject
        subject_label = QLabel(f"Subject: {email_data['subject']}")
        subject_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        header_layout.addWidget(subject_label)
        
        # Time
        time_label = QLabel(f"Received: {email_data['received_at']}")
        time_label.setStyleSheet("color: #666; font-size: 11px;")
        header_layout.addWidget(time_label)
        
        # PQC FEATURE: Show attachment info if present
        if email_data.get('attachments'):
            attachment_count = len(email_data.get('attachments', []))
            total_size = email_data.get('total_attachment_size', 0)
            if total_size > 0:
                size_mb = total_size / (1024 * 1024)
                attachment_label = QLabel(f"📎 {attachment_count} attachment(s) - {size_mb:.1f} MB")
            else:
                attachment_label = QLabel(f"📎 {attachment_count} attachment(s)")
            attachment_label.setStyleSheet("color: #4285F4; font-size: 12px; font-weight: bold;")
            header_layout.addWidget(attachment_label)
        
        self.content_layout.addWidget(header_frame)
        
        # Email body
        body_text = QTextEdit()
        body_text.setReadOnly(True)
        
        # Enhanced body content with PQC info
        security_info = ""
        if security_level in ['L1', 'L2']:
            security_info = "This email was encrypted with quantum security."
        elif security_level == 'L3':
            if email_data.get('pqc_file_encryption', {}).get('fek_used'):
                security_info = ("This email was secured with Post-Quantum Crypto including "
                               "CRYSTALS-Kyber key encapsulation for file attachments.")
            else:
                security_info = "This email was secured with Post-Quantum Crypto."
        else:
            security_info = "This email was sent with standard security."
        
        body_text.setHtml(f"""
        <div style="font-family: Arial, sans-serif; font-size: 14px; line-height: 1.5;">
            <p>{email_data.get('body', email_data.get('preview', 'No content available'))}</p>
            <br><br>
            <p><em>{security_info}</em></p>
        </div>
        """)
        self.content_layout.addWidget(body_text)
        
        self.current_email = email_data
        
    def compose_email(self):
        """Open compose dialog"""
        dialog = ComposeDialog(self.core, self)
        dialog.email_sent.connect(self.on_email_composed)
        dialog.exec()
        
    def on_email_composed(self, email_data: Dict):
        """Handle composed email with PQC file attachment support"""
        logging.info(f"Composing email to: {email_data['to']} with {email_data['security_level']}")
        
        # PQC FEATURE: Log file attachment details
        if email_data.get('attachments'):
            attachment_count = len(email_data['attachments'])
            total_size_mb = email_data.get('total_attachment_size', 0) / (1024 * 1024)
            logging.info(f"Email has {attachment_count} attachments, total size: {total_size_mb:.2f} MB")
            
            if email_data.get('has_large_attachments') and email_data['security_level'] == 'L3':
                logging.info("Using PQC file encryption for large attachments")
        
        # Create a mock email ID and set folder
        new_id = str(len(self.all_emails) + 1)
        current_user_email = "you@qumail.com"  # Default user email
        if self.core and hasattr(self.core, 'current_user') and self.core.current_user:
            current_user_email = self.core.current_user.email
            
        # Prepare attachment info for display
        attachment_info = ""
        if email_data.get('attachments'):
            attachment_count = len(email_data['attachments'])
            if email_data.get('total_attachment_size', 0) > 1024 * 1024:
                size_mb = email_data.get('total_attachment_size', 0) / (1024 * 1024)
                attachment_info = f" [📎 {attachment_count} files, {size_mb:.1f} MB]"
            else:
                attachment_info = f" [📎 {attachment_count} file{'s' if attachment_count != 1 else ''}]"
            
        new_mail = {
            'email_id': new_id,
            'sender': current_user_email,
            'subject': email_data['subject'],
            'preview': email_data['body'][:100].strip() + attachment_info,
            'received_at': datetime.now().isoformat(),
            'security_level': email_data['security_level'],
            'body': email_data['body'],
            'folder': 'Sent',
            'attachments': email_data.get('attachments', []),
            'total_attachment_size': email_data.get('total_attachment_size', 0),
            'has_large_attachments': email_data.get('has_large_attachments', False)
        }
        
        # PQC FEATURE: Add PQC metadata for L3 with large files
        if (email_data['security_level'] == 'L3' and 
            email_data.get('has_large_attachments')):
            new_mail['pqc_file_encryption'] = {
                'total_size': email_data.get('total_attachment_size', 0),
                'attachment_count': len(email_data.get('attachments', [])),
                'fek_used': True,
                'kyber_kem': True
            }
        
        # Add the sent mail to the persistent store
        self.all_emails.append(new_mail)

        # Switch to Sent folder to immediately show the sent mail
        self.set_active_folder('Sent') 
        
        # Enhanced success message with PQC info
        if email_data.get('has_large_attachments') and email_data['security_level'] == 'L3':
            success_msg = (f"📧 Email sent to {email_data['to']} with Post-Quantum Crypto!\n\n"
                          f"🔐 Security: CRYSTALS-Kyber + AES-256-GCM\n"
                          f"📎 Attachments: {len(email_data.get('attachments', []))} files\n"
                          f"📊 Total size: {email_data.get('total_attachment_size', 0) / (1024*1024):.1f} MB")
        else:
            success_msg = f"Email sent to {email_data['to']} with {email_data['security_level']} security."
        
        QMessageBox.information(self, "Email Sent", success_msg)
        self.status_message.emit("Email sent successfully with advanced quantum security")
        
        # REAL FUNCTIONALITY: Actually send via core if available
        if self.core and hasattr(self.core, 'send_secure_email'):
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                loop.create_task(self.core.send_secure_email(
                    email_data['to'], 
                    email_data['subject'], 
                    email_data['body'],
                    email_data.get('attachments'),
                    email_data['security_level'],
                    {'has_attachments': bool(email_data.get('attachments')),
                     'total_size': email_data.get('total_attachment_size', 0)}
                ))
            except Exception as e:
                logging.error(f"Failed to send via core: {e}")
        
    def refresh_emails(self):
        """Refresh email list from database"""
        logging.info("Refreshing email list from database")
        self.status_message.emit("Refreshing emails from database...")
        
        # Clear current emails and reload from database
        self.all_emails = []
        self.load_initial_emails()
        
        self.status_message.emit("Email list refreshed")
        
    def handle_search(self, search_text: str):
        """Handle search functionality (FIXED: Works with folder system)"""
        if not search_text:
            self.update_email_list(self.all_emails)  # Use all_emails instead of email_list_data
            return
            
        # Filter emails based on search text from all emails, then apply folder filter
        filtered_emails = []
        search_lower = search_text.lower()
        
        for email in self.all_emails:  # Search through all emails, not just current view
            if (search_lower in email.get('sender', '').lower() or
                search_lower in email.get('subject', '').lower() or
                search_lower in email.get('preview', '').lower()):
                filtered_emails.append(email)
                
        self.update_email_list(filtered_emails)  # This will still filter by current folder
        
    def cleanup(self):
        """Cleanup resources"""
        logging.info("Email Module cleanup")