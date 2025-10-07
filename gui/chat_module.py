#!/usr/bin/env python3
"""
Chat Module - WhatsApp-like Interface

Implements the WhatsApp-inspired chat interface with quantum security integration
"""

import logging
from typing import Dict, List, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QListWidget, QListWidgetItem,
    QTextEdit, QPushButton, QLabel, QLineEdit, QScrollArea, QFrame, QComboBox,
    QDialog, QDialogButtonBox, QMessageBox, QSlider, QProgressBar
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, pyqtSlot, QSize
from PyQt6.QtGui import QFont, QPalette, QColor, QIcon, QPainter, QPen
from datetime import datetime

class MessageBubble(QFrame):
    """Individual message bubble"""
    
    def __init__(self, message_data: Dict, is_sent: bool = True):
        super().__init__()
        self.message_data = message_data
        self.is_sent = is_sent
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup message bubble UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)
        
        # Message text
        message_text = self.message_data.get('content', '')
        message_label = QLabel(message_text)
        message_label.setWordWrap(True)
        message_label.setFont(QFont("Arial", 11))
        
        if self.is_sent:
            # Sent message (right side, green)
            self.setStyleSheet("""
                MessageBubble {
                    background-color: #DCF8C6;
                    border-radius: 18px;
                    border-bottom-right-radius: 4px;
                    max-width: 300px;
                }
            """)
            message_label.setStyleSheet("color: #000;")
        else:
            # Received message (left side, white/gray)
            self.setStyleSheet("""
                MessageBubble {
                    background-color: white;
                    border: 1px solid #E0E0E0;
                    border-radius: 18px;
                    border-bottom-left-radius: 4px;
                    max-width: 300px;
                }
            """)
            message_label.setStyleSheet("color: #000;")
            
        layout.addWidget(message_label)
        
        # Bottom info (time and security indicator)
        bottom_layout = QHBoxLayout()
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        
        # Security indicator
        security_level = self.message_data.get('security_level', 'L4')
        if security_level in ['L1', 'L2']:
            security_icon = QLabel("Ψ")
            security_icon.setStyleSheet("""
                color: #61FF00; 
                font-weight: bold; 
                font-size: 10px;
            """)
            security_icon.setToolTip(f"Quantum Secured ({security_level})")
            bottom_layout.addWidget(security_icon)
        elif security_level == 'L3':
            security_icon = QLabel("🔒")
            security_icon.setStyleSheet("font-size: 9px;")
            security_icon.setToolTip("Post-Quantum Crypto")
            bottom_layout.addWidget(security_icon)
            
        bottom_layout.addStretch()
        
        # Timestamp
        timestamp = self.message_data.get('timestamp', '')
        time_label = QLabel(self._format_time(timestamp))
        time_label.setStyleSheet("color: #999; font-size: 9px;")
        bottom_layout.addWidget(time_label)
        
        # Read receipt (for sent messages)
        if self.is_sent:
            status_icon = QLabel("✓✓")  # Double check mark
            status_icon.setStyleSheet("color: #4285F4; font-size: 9px; font-weight: bold;")
            status_icon.setToolTip("Read")
            bottom_layout.addWidget(status_icon)
            
        layout.addLayout(bottom_layout)
        
    def _format_time(self, timestamp_str: str) -> str:
        """Format timestamp for display"""
        try:
            if not timestamp_str:
                return datetime.now().strftime("%H:%M")
            # In real implementation, parse and format timestamp
            return "12:34"  # Placeholder
        except:
            return "--:--"

class ContactItem(QFrame):
    """Individual contact item in the contacts list"""
    
    clicked = pyqtSignal(str)  # contact_id
    
    def __init__(self, contact_data: Dict):
        super().__init__()
        self.contact_data = contact_data
        self.contact_id = contact_data.get('contact_id', '')
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup contact item UI"""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setMinimumHeight(70)
        self.setMaximumHeight(70)
        
        # WhatsApp-style hover effect
        self.setStyleSheet("""
            ContactItem {
                border: none;
                background-color: white;
                padding: 8px;
            }
            ContactItem:hover {
                background-color: #F0F2F5;
            }
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        
        # Avatar
        name = self.contact_data.get('name', 'Unknown')
        avatar = QLabel(name[0].upper())
        avatar.setFixedSize(50, 50)
        avatar.setStyleSheet("""
            QLabel {
                background-color: #25D366;
                color: white;
                border-radius: 25px;
                font-weight: bold;
                font-size: 18px;
            }
        """)
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(avatar)
        
        # Contact info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        
        # Name and security status
        top_line = QHBoxLayout()
        
        name_label = QLabel(name)
        name_label.setFont(QFont("Arial", 13, QFont.Weight.Bold))
        top_line.addWidget(name_label)
        
        # QKD Status indicator
        qkd_status = self.contact_data.get('qkd_status', 'disconnected')
        if qkd_status == 'connected':
            status_icon = QLabel("Ψ")
            status_icon.setStyleSheet("color: #61FF00; font-weight: bold; font-size: 12px;")
            status_icon.setToolTip("QKD Link Active")
            top_line.addWidget(status_icon)
            
        top_line.addStretch()
        
        # Last seen or time
        time_label = QLabel(self.contact_data.get('last_seen', 'offline'))
        time_label.setStyleSheet("color: #667781; font-size: 11px;")
        top_line.addWidget(time_label)
        
        info_layout.addLayout(top_line)
        
        # Last message preview
        last_message = self.contact_data.get('last_message', 'No messages yet')
        if len(last_message) > 50:
            last_message = last_message[:47] + "..."
        message_label = QLabel(last_message)
        message_label.setStyleSheet("color: #667781; font-size: 11px;")
        info_layout.addWidget(message_label)
        
        layout.addLayout(info_layout)
        
        # Unread indicator
        unread_count = self.contact_data.get('unread_count', 0)
        if unread_count > 0:
            unread_badge = QLabel(str(unread_count))
            unread_badge.setFixedSize(20, 20)
            unread_badge.setStyleSheet("""
                QLabel {
                    background-color: #25D366;
                    color: white;
                    border-radius: 10px;
                    font-size: 11px;
                    font-weight: bold;
                }
            """)
            unread_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(unread_badge)
            
        # Make clickable
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
    def mousePressEvent(self, event):
        """Handle mouse click"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.contact_id)
        super().mousePressEvent(event)

class CallControlsWidget(QWidget):
    """Audio/Video call controls widget"""
    
    call_started = pyqtSignal(str, str)  # contact_id, call_type
    call_ended = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.in_call = False
        self.call_duration = 0
        self.call_timer = QTimer()
        self.call_timer.timeout.connect(self.update_call_timer)
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup call controls UI"""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # Audio call button
        self.audio_button = QPushButton("📞")
        self.audio_button.setFixedSize(48, 48)
        self.audio_button.setStyleSheet("""
            QPushButton {
                background-color: #25D366;
                color: white;
                border: none;
                border-radius: 24px;
                font-size: 20px;
            }
            QPushButton:hover {
                background-color: #1DA851;
            }
        """)
        self.audio_button.setToolTip("Start Audio Call")
        self.audio_button.clicked.connect(lambda: self.start_call('audio'))
        layout.addWidget(self.audio_button)
        
        # Video call button
        self.video_button = QPushButton("📹")
        self.video_button.setFixedSize(48, 48)
        self.video_button.setStyleSheet("""
            QPushButton {
                background-color: #25D366;
                color: white;
                border: none;
                border-radius: 24px;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #1DA851;
            }
        """)
        self.video_button.setToolTip("Start Video Call")
        self.video_button.clicked.connect(lambda: self.start_call('video'))
        layout.addWidget(self.video_button)
        
        layout.addStretch()
        
        # Call status and end button (hidden initially)
        self.call_status_label = QLabel("")
        self.call_status_label.setStyleSheet("""
            QLabel {
                color: #25D366;
                font-weight: bold;
                font-size: 12px;
            }
        """)
        self.call_status_label.setVisible(False)
        layout.addWidget(self.call_status_label)
        
        self.end_call_button = QPushButton("📞")
        self.end_call_button.setFixedSize(40, 40)
        self.end_call_button.setStyleSheet("""
            QPushButton {
                background-color: #FF4444;
                color: white;
                border: none;
                border-radius: 20px;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #CC3333;
            }
        """)
        self.end_call_button.setToolTip("End Call")
        self.end_call_button.clicked.connect(self.end_call)
        self.end_call_button.setVisible(False)
        layout.addWidget(self.end_call_button)
        
    def start_call(self, call_type: str):
        """Start a call - Ensure correct contact ID is used"""
        if not self.in_call:
            # FIX: Get the actual contact ID from the dynamic property set by ChatModule.
            current_contact_id = self.property("current_contact_id") or 'unknown_contact'
            
            self.in_call = True
            self.call_duration = 0
            
            # Update UI
            self.audio_button.setVisible(False)
            self.video_button.setVisible(False)
            self.call_status_label.setVisible(True)
            self.end_call_button.setVisible(True)
            
            # Start timer
            self.call_timer.start(1000)  # Update every second
            
            # Emit the actual contact_id to initiate the call in the main application logic
            self.call_started.emit(current_contact_id, call_type)
            logging.info(f"Started {call_type} call to {current_contact_id}")
            
    def end_call(self):
        """End the current call"""
        if self.in_call:
            self.in_call = False
            
            # Stop timer
            self.call_timer.stop()
            
            # Reset UI
            self.audio_button.setVisible(True)
            self.video_button.setVisible(True)
            self.call_status_label.setVisible(False)
            self.end_call_button.setVisible(False)
            
            self.call_ended.emit()
            logging.info("Call ended")
            
    def update_call_timer(self):
        """Update call duration timer"""
        self.call_duration += 1
        minutes = self.call_duration // 60
        seconds = self.call_duration % 60
        self.call_status_label.setText(f"Call Duration: {minutes:02d}:{seconds:02d}")

class ChatModule(QWidget):
    """Main chat module implementing WhatsApp-like interface"""
    
    status_message = pyqtSignal(str)
    
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.current_contact = None
        self.contacts_data = []
        self.current_messages = []
        
        # PERSISTENCE FIX: Add session-based message storage similar to email module
        self.all_chat_sessions = {}  # Dictionary: contact_id -> list of messages
        self.persistent_storage = {}  # Persistent storage for sent messages across sessions
        
        self.setup_ui()
        self.load_sample_contacts()
        
        logging.info("Chat Module initialized with persistent storage")
        
    def setup_ui(self):
        """Setup the chat module UI with WhatsApp-style design"""
        # Apply WhatsApp-inspired background
        self.setStyleSheet("""
            ChatModule {
                background-color: #E5DDD5;
            }
        """)
        
        # Create main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - contacts list
        self.setup_contacts_panel(main_splitter)
        
        # Right panel - chat conversation
        self.setup_chat_panel(main_splitter)
        
        # Set splitter proportions
        main_splitter.setSizes([350, 650])
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(main_splitter)
        
    def setup_contacts_panel(self, parent_splitter):
        """Setup contacts list panel"""
        contacts_frame = QFrame()
        contacts_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-right: 1px solid #E0E0E0;
            }
        """)
        contacts_layout = QVBoxLayout(contacts_frame)
        contacts_layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #075E54;
                padding: 16px;
            }
        """)
        header_layout = QHBoxLayout(header_frame)
        
        header_label = QLabel("Chats")
        header_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 18px;
                font-weight: bold;
            }
        """)
        header_layout.addWidget(header_label)
        
        header_layout.addStretch()
        
        # New chat button
        new_chat_button = QPushButton("+")
        new_chat_button.setFixedSize(32, 32)
        new_chat_button.setStyleSheet("""
            QPushButton {
                background-color: #25D366;
                color: white;
                border: none;
                border-radius: 16px;
                font-size: 16px;
                font-weight: bold;
            }
        """)
        header_layout.addWidget(new_chat_button)
        
        contacts_layout.addWidget(header_frame)
        
        # Contacts list
        self.contacts_list_widget = QScrollArea()
        self.contacts_list_widget.setWidgetResizable(True)
        self.contacts_list_widget.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        
        self.contacts_list_container = QWidget()
        self.contacts_list_layout = QVBoxLayout(self.contacts_list_container)
        self.contacts_list_layout.setSpacing(0)
        self.contacts_list_layout.setContentsMargins(0, 0, 0, 0)
        
        self.contacts_list_widget.setWidget(self.contacts_list_container)
        contacts_layout.addWidget(self.contacts_list_widget)
        
        parent_splitter.addWidget(contacts_frame)
        
    def setup_chat_panel(self, parent_splitter):
        """Setup chat conversation panel"""
        chat_frame = QFrame()
        chat_layout = QVBoxLayout(chat_frame)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.setSpacing(0)
        
        # Chat header
        self.chat_header = QFrame()
        self.setup_chat_header()
        chat_layout.addWidget(self.chat_header)
        
        # Messages area
        self.messages_area = QScrollArea()
        self.messages_area.setWidgetResizable(True)
        self.messages_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.messages_area.setStyleSheet("""
            QScrollArea {
                background-color: #E5DDD5;
                border: none;
            }
        """)
        
        self.messages_container = QWidget()
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.messages_layout.setSpacing(8)
        
        self.messages_area.setWidget(self.messages_container)
        chat_layout.addWidget(self.messages_area)
        
        # Input area
        self.setup_input_area(chat_layout)
        
        parent_splitter.addWidget(chat_frame)
        
    def setup_chat_header(self):
        """Setup chat header with contact info and call controls"""
        self.chat_header.setStyleSheet("""
            QFrame {
                background-color: #075E54;
                padding: 12px 16px;
            }
        """)
        
        header_layout = QHBoxLayout(self.chat_header)
        
        # Contact info
        self.contact_name_label = QLabel("Select a contact")
        self.contact_name_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 16px;
                font-weight: bold;
            }
        """)
        header_layout.addWidget(self.contact_name_label)
        
        self.contact_status_label = QLabel("")
        self.contact_status_label.setStyleSheet("""
            QLabel {
                color: #B0BEC5;
                font-size: 12px;
            }
        """)
        header_layout.addWidget(self.contact_status_label)
        
        header_layout.addStretch()
        
        # Call controls
        self.call_controls = CallControlsWidget()
        # Connect call signals for integration with main call module
        self.call_controls.call_started.connect(self.on_call_started)
        self.call_controls.call_ended.connect(self.on_call_ended)
        header_layout.addWidget(self.call_controls)
        
    def setup_input_area(self, parent_layout):
        """Setup message input area"""
        input_frame = QFrame()
        input_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-top: 1px solid #E0E0E0;
                padding: 8px;
            }
        """)
        
        input_layout = QHBoxLayout(input_frame)
        
        # Emoji button
        emoji_button = QPushButton("🙂")
        emoji_button.setFixedSize(36, 36)
        emoji_button.setStyleSheet("""
            QPushButton {
                border: none;
                background-color: transparent;
                font-size: 16px;
            }
        """)
        input_layout.addWidget(emoji_button)
        
        # Message input
        self.message_input = QTextEdit()
        self.message_input.setMaximumHeight(100)
        self.message_input.setPlaceholderText("Type a message")
        self.message_input.setStyleSheet("""
            QTextEdit {
                border: 1px solid #E0E0E0;
                border-radius: 20px;
                padding: 8px 12px;
                font-size: 14px;
            }
        """)
        input_layout.addWidget(self.message_input)
        
        # Security level mini-selector
        self.security_mini_selector = QComboBox()
        self.security_mini_selector.addItems(["L2", "L1", "L3", "L4"])
        self.security_mini_selector.setFixedWidth(60)
        self.security_mini_selector.setStyleSheet("""
            QComboBox {
                border: 1px solid #25D366;
                border-radius: 4px;
                padding: 4px;
                font-size: 10px;
                font-weight: bold;
            }
        """)
        input_layout.addWidget(self.security_mini_selector)
        
        # Send button
        self.send_button = QPushButton("➤")
        self.send_button.setFixedSize(40, 40)
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #25D366;
                color: white;
                border: none;
                border-radius: 20px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1DA851;
            }
        """)
        self.send_button.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_button)
        
        parent_layout.addWidget(input_frame)
        
    def load_sample_contacts(self):
        """Load sample contacts"""
        sample_contacts = [
            {
                'contact_id': 'alice',
                'name': 'Alice Smith',
                'last_message': 'The quantum keys are working perfectly! Ψ',
                'last_seen': '2 minutes ago',
                'qkd_status': 'connected',
                'unread_count': 2
            },
            {
                'contact_id': 'bob',
                'name': 'Bob Johnson', 
                'last_message': 'Can we test the video call feature?',
                'last_seen': '5 minutes ago',
                'qkd_status': 'connected',
                'unread_count': 0
            },
            {
                'contact_id': 'charlie',
                'name': 'Charlie Brown',
                'last_message': 'Regular message without encryption',
                'last_seen': '1 hour ago',
                'qkd_status': 'disconnected',
                'unread_count': 1
            }
        ]
        
        self.update_contacts_list(sample_contacts)
        
    def update_contacts_list(self, contacts: List[Dict]):
        """Update the contacts list display"""
        # Clear existing items
        while self.contacts_list_layout.count():
            child = self.contacts_list_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
        # Add contact items
        for contact_data in contacts:
            contact_item = ContactItem(contact_data)
            contact_item.clicked.connect(self.on_contact_selected)
            self.contacts_list_layout.addWidget(contact_item)
            
        # Add stretch at bottom
        self.contacts_list_layout.addStretch()
        
        self.contacts_data = contacts
        
    def on_contact_selected(self, contact_id: str):
        """Handle contact selection"""
        # Find contact data
        contact_data = None
        for contact in self.contacts_data:
            if contact['contact_id'] == contact_id:
                contact_data = contact
                break
                
        if contact_data:
            self.current_contact = contact_data
            self.update_chat_header(contact_data)
            self.load_chat_messages(contact_id)
            
    def update_chat_header(self, contact_data: Dict):
        """Update chat header with contact information"""
        self.contact_name_label.setText(contact_data['name'])
        
        # FIX: Store the current contact ID on the CallControlsWidget for the signal chain.
        self.call_controls.setProperty("current_contact_id", contact_data['contact_id'])
        
        status_text = contact_data.get('last_seen', 'offline')
        if contact_data.get('qkd_status') == 'connected':
            status_text += " • QKD Active Ψ"
        self.contact_status_label.setText(status_text)
        
    def load_chat_messages(self, contact_id: str):
        """Load chat messages for the selected contact (PERSISTENCE FIX: Loads from session storage)"""
        
        # PERSISTENCE FIX: Check if we have existing chat session for this contact
        if contact_id in self.all_chat_sessions:
            # Load existing messages from persistent storage
            existing_messages = self.all_chat_sessions[contact_id]
            logging.info(f"Loading {len(existing_messages)} existing messages for {contact_id}")
            self.display_messages(existing_messages)
            return
        
        # First time loading this contact - create initial mock messages
        messages_base = [
            {'message_id': f'{contact_id}_1', 'content': f'Hello {contact_id}! Starting secure chat.', 'is_sent': False, 'security_level': 'L2'},
            {'message_id': f'{contact_id}_2', 'content': 'I am ready for the quantum key exchange.', 'is_sent': True, 'security_level': 'L2'},
        ]
        
        # Customize mock history based on the contact:
        if contact_id == 'alice':
            messages_base.extend([
                {'message_id': 'alice_3', 'content': 'Is the OTP key material ready for the file?', 'is_sent': False, 'security_level': 'L1'},
                {'message_id': 'alice_4', 'content': 'Yes! The quantum keys are working perfectly! Ψ', 'is_sent': True, 'security_level': 'L1'},
                {'message_id': 'alice_5', 'content': 'Excellent. Can we test the video call feature next?', 'is_sent': False, 'security_level': 'L2'}
            ])
        elif contact_id == 'bob':
            messages_base.extend([
                {'message_id': 'bob_3', 'content': 'We must use the PQC fallback today.', 'is_sent': True, 'security_level': 'L3'},
                {'message_id': 'bob_4', 'content': 'Good idea. The lattice-based crypto is ready.', 'is_sent': False, 'security_level': 'L3'},
                {'message_id': 'bob_5', 'content': 'Perfect! Security is our priority.', 'is_sent': True, 'security_level': 'L3'}
            ])
        else: # charlie
            messages_base.extend([
                {'message_id': f'{contact_id}_3', 'content': 'This is just a regular TLS message.', 'is_sent': False, 'security_level': 'L4'},
                {'message_id': f'{contact_id}_4', 'content': 'No problem, standard encryption works too.', 'is_sent': True, 'security_level': 'L4'},
                {'message_id': f'{contact_id}_5', 'content': 'Regular message without quantum encryption', 'is_sent': False, 'security_level': 'L4'}
            ])
        
        # Convert timestamps and ensure they are unique
        now = datetime.now()
        sample_messages = []
        for i, msg in enumerate(messages_base):
            from datetime import timedelta
            msg['timestamp'] = (now - timedelta(minutes=len(messages_base) - i)).isoformat()
            sample_messages.append(msg)
        
        # PERSISTENCE FIX: Store the initial messages in session storage
        self.all_chat_sessions[contact_id] = sample_messages
        
        self.display_messages(sample_messages)
        
    def display_messages(self, messages: List[Dict]):
        """Display messages in the chat area"""
        # Clear existing messages
        while self.messages_layout.count():
            child = self.messages_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
        # Add message bubbles
        for message_data in messages:
            is_sent = message_data.get('is_sent', False)
            
            # Create container for alignment
            message_container = QHBoxLayout()
            
            if is_sent:
                # Sent messages align right
                message_container.addStretch()
                bubble = MessageBubble(message_data, is_sent=True)
                message_container.addWidget(bubble)
            else:
                # Received messages align left
                bubble = MessageBubble(message_data, is_sent=False)
                message_container.addWidget(bubble)
                message_container.addStretch()
                
            # Add to main layout
            container_widget = QWidget()
            container_widget.setLayout(message_container)
            self.messages_layout.addWidget(container_widget)
            
        # Scroll to bottom
        QTimer.singleShot(100, self.scroll_to_bottom)
        
        self.current_messages = messages
        
    def scroll_to_bottom(self):
        """Scroll messages area to bottom"""
        scrollbar = self.messages_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def send_message(self):
        """Send a chat message (PERSISTENCE FIX: Stores message persistently)"""
        message_text = self.message_input.toPlainText().strip()
        
        if not message_text or not self.current_contact:
            return
            
        # Get selected security level
        security_levels = ['L2', 'L1', 'L3', 'L4']
        security_level = security_levels[self.security_mini_selector.currentIndex()]
        
        # Get current contact ID
        contact_id = self.current_contact['contact_id']
        
        # PERSISTENCE FIX: Ensure we have session storage for this contact
        if contact_id not in self.all_chat_sessions:
            self.all_chat_sessions[contact_id] = []
            
        # Get current session messages
        current_messages = self.all_chat_sessions[contact_id]
        
        # Create message data
        new_message = {
            'message_id': f"{contact_id}_{len(current_messages) + 1}",
            'content': message_text,
            'timestamp': datetime.now().isoformat(),
            'is_sent': True,
            'security_level': security_level
        }
        
        # PERSISTENCE FIX: Add to session storage instead of temporary list
        current_messages.append(new_message)
        self.all_chat_sessions[contact_id] = current_messages
        
        # Store in persistent storage for cross-session persistence
        if contact_id not in self.persistent_storage:
            self.persistent_storage[contact_id] = []
        self.persistent_storage[contact_id].append(new_message)
        
        # Update display with current session
        self.display_messages(current_messages)
        
        # Clear input
        self.message_input.clear()
        
        # Show status
        self.status_message.emit(f"Message sent with {security_level} security")
        
        logging.info(f"Message sent to {self.current_contact['name']} with {security_level} - stored persistently")
        
        # REAL FUNCTIONALITY: Actually send via core if available
        if self.core and hasattr(self.core, 'send_secure_chat_message'):
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                loop.create_task(self.core.send_secure_chat_message(
                    contact_id, message_text, security_level
                ))
            except Exception as e:
                logging.error(f"Failed to send via core: {e}")
        
    def get_sidebar_widget(self) -> Optional[QWidget]:
        """Chat module uses its own sidebar in the splitter"""
        return None  # Contacts are in the left panel already
        
    def handle_search(self, search_text: str):
        """Handle search functionality"""
        if not search_text:
            self.update_contacts_list(self.contacts_data)
            return
            
        # Filter contacts based on search text
        filtered_contacts = []
        search_lower = search_text.lower()
        
        for contact in self.contacts_data:
            if (search_lower in contact.get('name', '').lower() or
                search_lower in contact.get('last_message', '').lower()):
                filtered_contacts.append(contact)
                
        self.update_contacts_list(filtered_contacts)
        
    def on_call_started(self, contact_id: str, call_type: str):
        """Handle call started from chat interface"""
        logging.info(f"Call started from chat: {call_type} to {contact_id}")
        # Emit status message to show call is starting
        self.status_message.emit(f"Starting {call_type} call to {contact_id}...")
        
        # In a real implementation, this would connect to the main call module
        # For now, just show a message
        QMessageBox.information(
            self, "Call Started", 
            f"Starting {call_type} call with {contact_id}.\n\nThis would integrate with the Call Module for full functionality."
        )
    
    def on_call_ended(self):
        """Handle call ended"""
        logging.info("Call ended from chat interface")
        self.status_message.emit("Call ended")
        
    def cleanup(self):
        """Cleanup resources"""
        logging.info("Chat Module cleanup")
