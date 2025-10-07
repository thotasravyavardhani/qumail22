#!/usr/bin/env python3
"""
Call Module - Audio/Video Calling Interface
Implements audio and video calling functionality with quantum-secured SRTP
"""

import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QFrame, QScrollArea, QListWidget, QListWidgetItem, QSplitter,
    QProgressBar, QSlider, QComboBox, QDialog, QDialogButtonBox,
    QMessageBox, QTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QThread, pyqtSlot, QSize
from PyQt6.QtGui import QFont, QPalette, QColor, QIcon, QPainter, QPen
from datetime import datetime, timedelta

class CallHistoryItem(QFrame):
    """Individual call history item"""
    
    call_selected = pyqtSignal(str)  # call_id
    
    def __init__(self, call_data: Dict):
        super().__init__()
        self.call_data = call_data
        self.call_id = call_data.get('call_id', '')
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup call history item UI"""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setMinimumHeight(70)
        self.setMaximumHeight(70)
        
        # Style based on call status
        call_type = self.call_data.get('type', 'missed')
        if call_type == 'missed':
            border_color = '#FF4444'
        elif call_type == 'incoming':
            border_color = '#25D366'
        else:  # outgoing
            border_color = '#4285F4'
            
        self.setStyleSheet(f"""
            CallHistoryItem {{
                border: 1px solid #E0E0E0;
                border-left: 4px solid {border_color};
                border-radius: 4px;
                padding: 8px;
                background-color: white;
            }}
            CallHistoryItem:hover {{
                background-color: #F8F9FA;
                border-color: {border_color};
            }}
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        
        # Call type icon
        call_icon = "📞" if self.call_data.get('call_type') == 'audio' else "📹"
        icon_label = QLabel(call_icon)
        icon_label.setFixedSize(40, 40)
        icon_label.setStyleSheet(f"""
            QLabel {{
                background-color: {border_color};
                color: white;
                border-radius: 20px;
                font-size: 16px;
            }}
        """)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        
        # Call info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(4)
        
        # Contact and status
        top_line = QHBoxLayout()
        
        contact_label = QLabel(self.call_data.get('contact_name', 'Unknown'))
        contact_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        top_line.addWidget(contact_label)
        
        # Security indicator
        if self.call_data.get('quantum_secured'):
            security_icon = QLabel("Ψ")
            security_icon.setStyleSheet("color: #61FF00; font-weight: bold; font-size: 14px;")
            security_icon.setToolTip("Quantum Secured SRTP")
            top_line.addWidget(security_icon)
            
        top_line.addStretch()
        
        # Duration or status
        duration = self.call_data.get('duration', 0)
        if duration > 0:
            minutes = duration // 60
            seconds = duration % 60
            duration_text = f"{minutes:02d}:{seconds:02d}"
        else:
            duration_text = self.call_data.get('status', 'No answer')
            
        duration_label = QLabel(duration_text)
        duration_label.setStyleSheet("color: #666; font-size: 11px;")
        top_line.addWidget(duration_label)
        
        info_layout.addLayout(top_line)
        
        # Timestamp and type
        bottom_line = QHBoxLayout()
        
        timestamp = self.call_data.get('timestamp', '')
        time_label = QLabel(self._format_time(timestamp))
        time_label.setStyleSheet("color: #666; font-size: 10px;")
        bottom_line.addWidget(time_label)
        
        bottom_line.addStretch()
        
        type_label = QLabel(f"{self.call_data.get('call_type', 'audio').title()}")
        type_label.setStyleSheet("color: #999; font-size: 10px;")
        bottom_line.addWidget(type_label)
        
        info_layout.addLayout(bottom_line)
        layout.addLayout(info_layout)
        
        # Action buttons
        action_layout = QVBoxLayout()
        
        callback_button = QPushButton("📞")
        callback_button.setFixedSize(32, 32)
        callback_button.setStyleSheet("""
            QPushButton {
                background-color: #25D366;
                color: white;
                border: none;
                border-radius: 16px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #1DA851;
            }
        """)
        callback_button.setToolTip("Call Back")
        callback_button.clicked.connect(lambda: self.call_selected.emit(self.call_data.get('contact_id', '')))
        action_layout.addWidget(callback_button)
        
        layout.addLayout(action_layout)
        
    def _format_time(self, timestamp_str: str) -> str:
        """Format timestamp for display"""
        try:
            if not timestamp_str:
                return "Unknown"
            # Simple formatting - in real implementation would be more sophisticated
            return "2 hours ago"
        except:
            return "Unknown"

class VideoCallWidget(QWidget):
    """Video call display widget with PiP capability"""
    
    call_ended = pyqtSignal()
    
    def __init__(self, contact_name: str, is_pip: bool = False):
        super().__init__()
        self.contact_name = contact_name
        self.is_pip = is_pip
        self.call_duration = 0
        self.call_timer = QTimer()
        self.call_timer.timeout.connect(self.update_duration)
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup video call UI"""
        if self.is_pip:
            self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowStaysOnTopHint)
            self.setWindowTitle("QuMail Call - PiP")
            self.resize(320, 240)
        else:
            self.resize(800, 600)
            
        layout = QVBoxLayout(self)
        
        # Video area
        video_frame = QFrame()
        video_frame.setStyleSheet("""
            QFrame {
                background-color: #1a1a1a;
                border-radius: 8px;
            }
        """)
        video_layout = QVBoxLayout(video_frame)
        
        # Main video (remote)
        main_video = QLabel("📹 Video Call Active")
        main_video.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_video.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 24px;
                background-color: #333;
                border-radius: 8px;
                padding: 40px;
            }
        """)
        video_layout.addWidget(main_video)
        
        # Self video (small overlay)
        if not self.is_pip:
            self_video = QLabel("You")
            self_video.setFixedSize(120, 90)
            self_video.setStyleSheet("""
                QLabel {
                    background-color: #555;
                    color: white;
                    border: 2px solid white;
                    border-radius: 8px;
                    font-size: 12px;
                }
            """)
            self_video.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            # Position self video in corner
            overlay_layout = QHBoxLayout()
            overlay_layout.addStretch()
            overlay_layout.addWidget(self_video)
            overlay_layout.setContentsMargins(0, 0, 16, 16)
            video_layout.addLayout(overlay_layout)
            
        layout.addWidget(video_frame, 1)
        
        # Call info bar
        info_bar = QFrame()
        info_bar.setStyleSheet("""
            QFrame {
                background-color: rgba(7, 94, 84, 0.9);
                border-radius: 6px;
                padding: 8px;
            }
        """)
        info_layout = QHBoxLayout(info_bar)
        
        # Contact name
        name_label = QLabel(f"📞 {self.contact_name}")
        name_label.setStyleSheet("""
            QLabel {
                color: white;
                font-weight: bold;
                font-size: 14px;
            }
        """)
        info_layout.addWidget(name_label)
        
        # Security indicator
        security_label = QLabel("🔒 SRTP Quantum Secured Ψ")
        security_label.setStyleSheet("""
            QLabel {
                color: #61FF00;
                font-size: 11px;
                font-weight: bold;
            }
        """)
        info_layout.addWidget(security_label)
        
        info_layout.addStretch()
        
        # Duration
        self.duration_label = QLabel("00:00")
        self.duration_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 12px;
                font-weight: bold;
            }
        """)
        info_layout.addWidget(self.duration_label)
        
        layout.addWidget(info_bar)
        
        # Controls
        controls_frame = QFrame()
        controls_layout = QHBoxLayout(controls_frame)
        controls_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Mute button
        self.mute_button = QPushButton("🎤")
        self.mute_button.setFixedSize(50, 50)
        self.mute_button.setCheckable(True)
        self.mute_button.setStyleSheet("""
            QPushButton {
                background-color: #4285F4;
                color: white;
                border: none;
                border-radius: 25px;
                font-size: 18px;
            }
            QPushButton:checked {
                background-color: #FF4444;
            }
        """)
        self.mute_button.setToolTip("Mute/Unmute")
        controls_layout.addWidget(self.mute_button)
        
        # Video toggle
        if not self.is_pip:
            self.video_button = QPushButton("📹")
            self.video_button.setFixedSize(50, 50)
            self.video_button.setCheckable(True)
            self.video_button.setChecked(True)
            self.video_button.setStyleSheet("""
                QPushButton {
                    background-color: #4285F4;
                    color: white;
                    border: none;
                    border-radius: 25px;
                    font-size: 16px;
                }
                QPushButton:checked {
                    background-color: #FF4444;
                }
            """)
            self.video_button.setToolTip("Camera On/Off")
            controls_layout.addWidget(self.video_button)
        
        # End call button
        end_button = QPushButton("📞")
        end_button.setFixedSize(60, 60)
        end_button.setStyleSheet("""
            QPushButton {
                background-color: #FF4444;
                color: white;
                border: none;
                border-radius: 30px;
                font-size: 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #CC3333;
            }
        """)
        end_button.setToolTip("End Call")
        end_button.clicked.connect(self.end_call)
        controls_layout.addWidget(end_button)
        
        # PiP toggle (for main window)
        if not self.is_pip:
            pip_button = QPushButton("📌")
            pip_button.setFixedSize(40, 40)
            pip_button.setStyleSheet("""
                QPushButton {
                    background-color: #666;
                    color: white;
                    border: none;
                    border-radius: 20px;
                    font-size: 14px;
                }
            """)
            pip_button.setToolTip("Picture in Picture")
            pip_button.clicked.connect(self.toggle_pip)
            controls_layout.addWidget(pip_button)
        
        layout.addWidget(controls_frame)
        
    def start_call(self):
        """Start the call timer"""
        self.call_timer.start(1000)
        
    def update_duration(self):
        """Update call duration"""
        self.call_duration += 1
        minutes = self.call_duration // 60
        seconds = self.call_duration % 60
        self.duration_label.setText(f"{minutes:02d}:{seconds:02d}")
        
    def toggle_pip(self):
        """Toggle picture-in-picture mode"""
        # Create PiP window
        pip_widget = VideoCallWidget(self.contact_name, is_pip=True)
        pip_widget.call_duration = self.call_duration
        pip_widget.call_timer.start(1000)
        pip_widget.show()
        
        # Hide main window
        self.hide()
        
    def end_call(self):
        """End the call"""
        self.call_timer.stop()
        self.call_ended.emit()
        self.close()

class SRTPKeyManager:
    """Manages SRTP key derivation from quantum material"""
    
    def __init__(self, kme_client):
        self.kme_client = kme_client
        
    async def derive_srtp_master_key(self, contact_id: str, call_id: str) -> Optional[Dict]:
        """Derive SRTP master key from quantum material"""
        try:
            # Request quantum key material from KME
            key_request = await self.kme_client.request_key(
                sender_sae_id=f"qumail_caller",
                receiver_sae_id=f"qumail_{contact_id}",
                key_length=256,  # 256 bits for SRTP master key
                key_type='seed'
            )
            
            if not key_request:
                return None
                
            # In real implementation, use HKDF to derive SRTP keys
            # HKDF(quantum_key, salt="SRTP-QuMail", info="master_key")
            
            srtp_keys = {
                'master_key': key_request['key_data'][:32],  # 256 bits
                'master_salt': key_request['key_data'][32:46],  # 112 bits
                'key_id': key_request['key_id'],
                'call_id': call_id,
                'algorithm': 'AES_CM_128_HMAC_SHA1_80'  # SRTP crypto suite
            }
            
            logging.info(f"SRTP master key derived for call {call_id}")
            return srtp_keys
            
        except Exception as e:
            logging.error(f"Failed to derive SRTP master key: {e}")
            return None

class CallModule(QWidget):
    """Main call module implementing audio/video calling with quantum SRTP"""
    
    status_message = pyqtSignal(str)
    
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.call_history = []
        self.active_call = None
        self.srtp_manager = SRTPKeyManager(core.kme_client if core else None)
        
        self.setup_ui()
        self.load_call_history()
        
        logging.info("Call Module initialized with quantum SRTP support")
        
    def _submit_async_call(self, call_type: str, contact_id: str = None):
        """Synchronous wrapper to safely submit async call to the running asyncio loop."""
        try:
            # CRITICAL FIX: Explicitly get the current loop and submit the task to it.
            loop = asyncio.get_event_loop()
            loop.create_task(self.start_call(call_type, contact_id))
            
        except Exception as e:
            logging.error(f"Error submitting async call: {e}") 
            QMessageBox.critical(self, "Core Error", 
                                 f"Call system initialization error: {e}")
        
    def setup_ui(self):
        """Setup the call module UI"""
        # Create main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - call history and contacts
        self.setup_call_list_panel(main_splitter)
        
        # Right panel - call controls and status
        self.setup_call_control_panel(main_splitter)
        
        # Set splitter proportions
        main_splitter.setSizes([400, 400])
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(main_splitter)
        
    def setup_call_list_panel(self, parent_splitter):
        """Setup call history and contacts panel"""
        list_frame = QFrame()
        list_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        list_layout = QVBoxLayout(list_frame)
        
        # Header with tabs
        header_frame = QFrame()
        header_layout = QVBoxLayout(header_frame)
        
        title_label = QLabel("📞 Calls & Contacts")
        title_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #25D366; padding: 12px;")
        header_layout.addWidget(title_label)
        
        # Tab buttons
        tab_layout = QHBoxLayout()
        
        self.history_tab = QPushButton("Recent")
        self.history_tab.setCheckable(True)
        self.history_tab.setChecked(True)
        self.history_tab.clicked.connect(lambda: self.switch_tab('history'))
        
        self.contacts_tab = QPushButton("Contacts")
        self.contacts_tab.setCheckable(True)
        self.contacts_tab.clicked.connect(lambda: self.switch_tab('contacts'))
        
        tab_style = """
            QPushButton {
                padding: 8px 16px;
                border: none;
                background-color: #F0F2F5;
                font-weight: bold;
            }
            QPushButton:checked {
                background-color: #25D366;
                color: white;
            }
        """
        
        self.history_tab.setStyleSheet(tab_style)
        self.contacts_tab.setStyleSheet(tab_style)
        
        tab_layout.addWidget(self.history_tab)
        tab_layout.addWidget(self.contacts_tab)
        tab_layout.addStretch()
        
        header_layout.addLayout(tab_layout)
        list_layout.addWidget(header_frame)
        
        # Scrollable list
        self.call_list_widget = QScrollArea()
        self.call_list_widget.setWidgetResizable(True)
        self.call_list_widget.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        
        self.call_list_container = QWidget()
        self.call_list_layout = QVBoxLayout(self.call_list_container)
        self.call_list_layout.setSpacing(2)
        
        self.call_list_widget.setWidget(self.call_list_container)
        list_layout.addWidget(self.call_list_widget)
        
        parent_splitter.addWidget(list_frame)
        
    def setup_call_control_panel(self, parent_splitter):
        """Setup call controls and status panel"""
        control_frame = QFrame()
        control_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        control_layout = QVBoxLayout(control_frame)
        
        # Status display
        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #F8F9FA;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        status_layout = QVBoxLayout(status_frame)
        
        # Connection status
        connection_label = QLabel("📡 WebRTC Connection Status")
        connection_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        status_layout.addWidget(connection_label)
        
        self.webrtc_status = QLabel("Ready for calls")
        self.webrtc_status.setStyleSheet("color: #25D366; font-size: 12px;")
        status_layout.addWidget(self.webrtc_status)
        
        # Quantum security status
        security_label = QLabel("🔒 Quantum SRTP Security")
        security_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        status_layout.addWidget(security_label)
        
        self.srtp_status = QLabel("KME connected - SRTP keys ready Ψ")
        self.srtp_status.setStyleSheet("color: #61FF00; font-size: 12px; font-weight: bold;")
        status_layout.addWidget(self.srtp_status)
        
        control_layout.addWidget(status_frame)
        
        # Quick call section
        quick_call_frame = QFrame()
        quick_call_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 2px solid #E0E0E0;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        quick_call_layout = QVBoxLayout(quick_call_frame)
        
        quick_label = QLabel("Quick Call")
        quick_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        quick_call_layout.addWidget(quick_label)
        
        # Contact selector
        self.contact_selector = QComboBox()
        self.contact_selector.addItems([
            "Alice Smith (QKD Active Ψ)",
            "Bob Johnson (QKD Active Ψ)",
            "Charlie Brown (Standard)"
        ])
        self.contact_selector.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                font-size: 12px;
            }
        """)
        quick_call_layout.addWidget(self.contact_selector)
        
        # Call buttons
        call_buttons_layout = QHBoxLayout()
        
        audio_call_button = QPushButton("📞 Audio Call")
        audio_call_button.setStyleSheet("""
            QPushButton {
                background-color: #25D366;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1DA851;
            }
        """)
        # FIXED: Use synchronous wrapper to safely submit async call
        audio_call_button.clicked.connect(lambda: self._submit_async_call('audio'))
        call_buttons_layout.addWidget(audio_call_button)
        
        video_call_button = QPushButton("📹 Video Call")
        video_call_button.setStyleSheet("""
            QPushButton {
                background-color: #4285F4;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3367D6;
            }
        """)
        # FIXED: Use synchronous wrapper to safely submit async call
        video_call_button.clicked.connect(lambda: self._submit_async_call('video'))
        call_buttons_layout.addWidget(video_call_button)
        
        quick_call_layout.addLayout(call_buttons_layout)
        control_layout.addWidget(quick_call_frame)
        
        # SRTP Key info
        key_info_frame = QFrame()
        key_info_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(97, 255, 0, 0.1);
                border: 1px solid #61FF00;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        key_info_layout = QVBoxLayout(key_info_frame)
        
        key_title = QLabel("🔐 Quantum Key Pool Status")
        key_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        key_title.setStyleSheet("color: #61FF00;")
        key_info_layout.addWidget(key_title)
        
        self.key_pool_bar = QProgressBar()
        self.key_pool_bar.setMaximum(100)
        self.key_pool_bar.setValue(87)
        self.key_pool_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #61FF00;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #61FF00;
            }
        """)
        key_info_layout.addWidget(self.key_pool_bar)
        
        key_status_label = QLabel("Available keys: 234 | Used today: 12 | Quality: Excellent")
        key_status_label.setStyleSheet("color: #333; font-size: 10px;")
        key_info_layout.addWidget(key_status_label)
        
        control_layout.addWidget(key_info_frame)
        
        control_layout.addStretch()
        
        parent_splitter.addWidget(control_frame)
        
    def switch_tab(self, tab_name: str):
        """Switch between history and contacts tabs"""
        if tab_name == 'history':
            self.history_tab.setChecked(True)
            self.contacts_tab.setChecked(False)
            self.load_call_history()
        else:
            self.history_tab.setChecked(False)
            self.contacts_tab.setChecked(True)
            self.load_contacts()
            
    def load_call_history(self):
        """Load and display call history"""
        # Clear existing items
        while self.call_list_layout.count():
            child = self.call_list_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
        # Sample call history
        sample_calls = [
            {
                'call_id': 'call_1',
                'contact_id': 'alice',
                'contact_name': 'Alice Smith',
                'type': 'outgoing',
                'call_type': 'video',
                'duration': 245,  # seconds
                'timestamp': datetime.utcnow().isoformat(),
                'quantum_secured': True,
                'status': 'completed'
            },
            {
                'call_id': 'call_2',
                'contact_id': 'bob',
                'contact_name': 'Bob Johnson',
                'type': 'incoming',
                'call_type': 'audio',
                'duration': 128,
                'timestamp': (datetime.utcnow() - timedelta(hours=1)).isoformat(),
                'quantum_secured': True,
                'status': 'completed'
            },
            {
                'call_id': 'call_3',
                'contact_id': 'charlie',
                'contact_name': 'Charlie Brown',
                'type': 'missed',
                'call_type': 'audio',
                'duration': 0,
                'timestamp': (datetime.utcnow() - timedelta(hours=3)).isoformat(),
                'quantum_secured': False,
                'status': 'missed'
            }
        ]
        
        for call_data in sample_calls:
            call_item = CallHistoryItem(call_data)
            call_item.call_selected.connect(self.initiate_callback)
            self.call_list_layout.addWidget(call_item)
            
        self.call_list_layout.addStretch()
        self.call_history = sample_calls
        
    def load_contacts(self):
        """Load and display contacts for calling"""
        # Clear existing items
        while self.call_list_layout.count():
            child = self.call_list_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
        # This would integrate with chat module contacts
        contacts_label = QLabel("Contact integration with Chat module")
        contacts_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        contacts_label.setStyleSheet("color: #666; padding: 20px;")
        self.call_list_layout.addWidget(contacts_label)
        
        self.call_list_layout.addStretch()
        
    async def start_call(self, call_type: str, contact_id: str = None):
        """Start a new call with quantum SRTP - FIXED ASYNC CALL"""
        try:
            if not contact_id:
                # Get contact from quick selector (original intent)
                selected_text = self.contact_selector.currentText()
                contact_name = selected_text.split(' (')[0]
                contact_id = contact_name.lower().replace(' ', '_')
            else:
                # Infer name from ID (used for history callback)
                contact_name = contact_id.replace('_', ' ').title()

            logging.info(f"Starting {call_type} call to {contact_name}")
            self.status_message.emit(f"Starting {call_type} call...")
            
            # Generate call ID
            call_id = f"call_{int(datetime.utcnow().timestamp())}"
            
            # Derive SRTP keys using quantum material (Logic is largely kept, but context is fixed)
            if self.srtp_manager:
                srtp_keys = await self.srtp_manager.derive_srtp_master_key(contact_id, call_id)
                if not srtp_keys:
                    QMessageBox.warning(
                        self, "Call Failed", 
                        "Could not establish quantum-secured connection. Try again."
                    )
                    return
                    
                logging.info(f"SRTP keys derived: Key ID {srtp_keys['key_id']}")
                
            # Create call window based on type
            if call_type == 'video':
                # Existing logic to show VideoCallWidget
                self.active_call = VideoCallWidget(contact_name)
                self.active_call.call_ended.connect(self.on_call_ended)
                self.active_call.show()
                self.active_call.start_call()
            else:
                # For audio calls, show a simpler dialog (Existing logic)
                self.show_audio_call_dialog(contact_name, call_id)
                
            # Add to call history
            new_call = {
                'call_id': call_id,
                'contact_id': contact_id,
                'contact_name': contact_name,
                'type': 'outgoing',
                'call_type': call_type,
                'duration': 0,
                'timestamp': datetime.utcnow().isoformat(),
                'quantum_secured': True,
                'status': 'active'
            }
            self.call_history.insert(0, new_call)
            
            self.status_message.emit(f"Call started with quantum SRTP security")
            
        except Exception as e:
            logging.error(f"Failed to start call: {e}")
            QMessageBox.critical(self, "Call Error", f"Failed to start call: {str(e)}")
            
    def show_audio_call_dialog(self, contact_name: str, call_id: str):
        """Show audio call dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Audio Call - {contact_name}")
        dialog.setModal(True)
        dialog.resize(400, 300)
        
        layout = QVBoxLayout(dialog)
        
        # Call info
        info_label = QLabel(f"📞 Audio call with {contact_name}")
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(info_label)
        
        # Security status
        security_label = QLabel("🔒 Quantum Secured SRTP Ψ")
        security_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        security_label.setStyleSheet("color: #61FF00; font-weight: bold; font-size: 14px;")
        layout.addWidget(security_label)
        
        # Duration
        duration_label = QLabel("00:00")
        duration_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        duration_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        duration_label.setStyleSheet("color: #25D366;")
        layout.addWidget(duration_label)
        
        layout.addStretch()
        
        # Controls
        controls_layout = QHBoxLayout()
        
        mute_button = QPushButton("🎤 Mute")
        mute_button.setStyleSheet("""
            QPushButton {
                background-color: #4285F4;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
            }
        """)
        controls_layout.addWidget(mute_button)
        
        end_button = QPushButton("📞 End Call")
        end_button.setStyleSheet("""
            QPushButton {
                background-color: #FF4444;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
            }
        """)
        end_button.clicked.connect(dialog.accept)
        controls_layout.addWidget(end_button)
        
        layout.addLayout(controls_layout)
        
        # Start call timer
        call_duration = 0
        call_timer = QTimer()
        
        def update_duration():
            nonlocal call_duration
            call_duration += 1
            minutes = call_duration // 60
            seconds = call_duration % 60
            duration_label.setText(f"{minutes:02d}:{seconds:02d}")
            
        call_timer.timeout.connect(update_duration)
        call_timer.start(1000)
        
        # Show dialog
        dialog.exec()
        call_timer.stop()
        
        # Update call history with actual duration
        for call in self.call_history:
            if call['call_id'] == call_id:
                call['duration'] = call_duration
                call['status'] = 'completed'
                break
                
        self.load_call_history()  # Refresh display
        
    def initiate_callback(self, contact_id: str):
        """Initiate callback to contact - now starts an async task"""
        logging.info(f"Initiating callback to: {contact_id}")
        self.status_message.emit(f"Calling {contact_id}...")
        
        # Use the synchronous wrapper
        self._submit_async_call('audio', contact_id)
        
    def on_call_ended(self):
        """Handle call end"""
        self.active_call = None
        self.status_message.emit("Call ended")
        self.load_call_history()  # Refresh history
        
    def get_sidebar_widget(self) -> Optional[QWidget]:
        """Call module uses its own layout"""
        return None
        
    def handle_search(self, search_text: str):
        """Handle search functionality"""
        # Filter call history based on search
        pass
        
    def cleanup(self):
        """Cleanup resources"""
        if self.active_call:
            self.active_call.close()
        logging.info("Call Module cleanup")