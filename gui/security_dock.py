#!/usr/bin/env python3
"""
Security Dock Widget - Real-time Security Status Monitor
Provides comprehensive security status and key management information
"""

import asyncio
import logging
from typing import Dict, Optional, List
from PyQt6.QtWidgets import (
    QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar, 
    QPushButton, QFrame, QScrollArea, QListWidget, QListWidgetItem,
    QComboBox, QSpinBox, QMessageBox, QDialog, QDialogButtonBox, QTextEdit
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt6.QtGui import QFont, QPalette, QColor, QPixmap, QPainter
from datetime import datetime, timedelta

class SecurityMetricsWidget(QFrame):
    """Widget displaying security metrics and KME status"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup security metrics UI"""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            SecurityMetricsWidget {
                background-color: rgba(97, 255, 0, 0.05);
                border: 2px solid #61FF00;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("🔐 Quantum Security Status")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #61FF00; border: none;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # QKD Link Status
        qkd_frame = QFrame()
        qkd_layout = QVBoxLayout(qkd_frame)
        
        qkd_title = QLabel("QKD Link Status")
        qkd_title.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        qkd_layout.addWidget(qkd_title)
        
        self.qkd_status_label = QLabel("🔗 Connected")
        self.qkd_status_label.setStyleSheet("color: #61FF00; font-weight: bold;")
        qkd_layout.addWidget(self.qkd_status_label)
        
        self.qkd_rate_label = QLabel("Rate: 10,000 bps")
        self.qkd_rate_label.setStyleSheet("color: #333; font-size: 10px;")
        qkd_layout.addWidget(self.qkd_rate_label)
        
        layout.addWidget(qkd_frame)
        
        # Key Pool Status
        pool_frame = QFrame()
        pool_layout = QVBoxLayout(pool_frame)
        
        pool_title = QLabel("Key Pool Status")
        pool_title.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        pool_layout.addWidget(pool_title)
        
        self.key_pool_progress = QProgressBar()
        self.key_pool_progress.setMaximum(100)
        self.key_pool_progress.setValue(87)
        self.key_pool_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #61FF00;
                border-radius: 4px;
                text-align: center;
                font-size: 10px;
            }
            QProgressBar::chunk {
                background-color: #61FF00;
                border-radius: 3px;
            }
        """)
        pool_layout.addWidget(self.key_pool_progress)
        
        self.key_pool_details = QLabel("Available: 234 keys | Used: 12")
        self.key_pool_details.setStyleSheet("color: #333; font-size: 9px;")
        pool_layout.addWidget(self.key_pool_details)
        
        layout.addWidget(pool_frame)
        
        # Active Sessions
        sessions_frame = QFrame()
        sessions_layout = QVBoxLayout(sessions_frame)
        
        sessions_title = QLabel("Active Sessions")
        sessions_title.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        sessions_layout.addWidget(sessions_title)
        
        self.active_sessions_label = QLabel("📧 Email: 2 | 💬 Chat: 1 | 📞 Calls: 0")
        self.active_sessions_label.setStyleSheet("color: #333; font-size: 10px;")
        sessions_layout.addWidget(self.active_sessions_label)
        
        layout.addWidget(sessions_frame)
        
    def update_qkd_status(self, connected: bool, rate: int):
        """Update QKD connection status"""
        if connected:
            self.qkd_status_label.setText("🔗 Connected Ψ")
            self.qkd_status_label.setStyleSheet("color: #61FF00; font-weight: bold;")
            self.qkd_rate_label.setText(f"Rate: {rate:,} bps")
        else:
            self.qkd_status_label.setText("❌ Disconnected")
            self.qkd_status_label.setStyleSheet("color: #FF4444; font-weight: bold;")
            self.qkd_rate_label.setText("Rate: 0 bps")
            
    def update_key_pool(self, available: int, used: int, total: int):
        """Update key pool status"""
        percentage = int((available / total) * 100) if total > 0 else 0
        self.key_pool_progress.setValue(percentage)
        self.key_pool_details.setText(f"Available: {available} keys | Used: {used}")
        
        # Change color based on availability
        if percentage > 50:
            color = "#61FF00"
        elif percentage > 20:
            color = "#FFA500"
        else:
            color = "#FF4444"
            
        self.key_pool_progress.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {color};
                border-radius: 4px;
                text-align: center;
                font-size: 10px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 3px;
            }}
        """)
        
    def update_sessions(self, email_count: int, chat_count: int, call_count: int):
        """Update active sessions count"""
        self.active_sessions_label.setText(
            f"📧 Email: {email_count} | 💬 Chat: {chat_count} | 📞 Calls: {call_count}"
        )

class KeyManagementWidget(QFrame):
    """Widget for key management operations"""
    
    key_request_signal = pyqtSignal(dict)  # Request new keys
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup key management UI"""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            KeyManagementWidget {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("🔑 Key Management")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: #333; border: none;")
        layout.addWidget(title)
        
        # Key request controls
        request_frame = QFrame()
        request_layout = QVBoxLayout(request_frame)
        
        # Key type selector
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Type:"))
        
        self.key_type_combo = QComboBox()
        self.key_type_combo.addItems(["seed", "otp", "symmetric"])
        self.key_type_combo.setStyleSheet("""
            QComboBox {
                padding: 4px;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                font-size: 11px;
            }
        """)
        type_layout.addWidget(self.key_type_combo)
        request_layout.addLayout(type_layout)
        
        # Key length
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Length:"))
        
        self.key_length_spin = QSpinBox()
        self.key_length_spin.setRange(128, 8192)
        self.key_length_spin.setValue(256)
        self.key_length_spin.setSuffix(" bits")
        self.key_length_spin.setStyleSheet("""
            QSpinBox {
                padding: 4px;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                font-size: 11px;
            }
        """)
        length_layout.addWidget(self.key_length_spin)
        request_layout.addLayout(length_layout)
        
        # Request button
        self.request_button = QPushButton("Request Keys")
        self.request_button.setStyleSheet("""
            QPushButton {
                background-color: #4285F4;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #3367D6;
            }
        """)
        self.request_button.clicked.connect(self.request_keys)
        request_layout.addWidget(self.request_button)
        
        layout.addWidget(request_frame)
        
        # Recent keys list
        recent_frame = QFrame()
        recent_layout = QVBoxLayout(recent_frame)
        
        recent_title = QLabel("Recent Keys")
        recent_title.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        recent_layout.addWidget(recent_title)
        
        self.keys_list = QListWidget()
        self.keys_list.setMaximumHeight(120)
        self.keys_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                font-size: 9px;
            }
            QListWidgetItem {
                padding: 4px;
                border-bottom: 1px solid #F0F0F0;
            }
        """)
        recent_layout.addWidget(self.keys_list)
        
        layout.addWidget(recent_frame)
        
    def request_keys(self):
        """Request new quantum keys"""
        key_request = {
            'key_type': self.key_type_combo.currentText(),
            'key_length': self.key_length_spin.value(),
            'count': 1
        }
        self.key_request_signal.emit(key_request)
        
    def add_recent_key(self, key_id: str, key_type: str, length: int, timestamp: str):
        """Add key to recent keys list"""
        key_text = f"{key_id[:16]}... | {key_type} | {length}b | {timestamp}"
        item = QListWidgetItem(key_text)
        self.keys_list.insertItem(0, item)
        
        # Keep only last 10 keys
        if self.keys_list.count() > 10:
            self.keys_list.takeItem(self.keys_list.count() - 1)

class SecurityAlertWidget(QFrame):
    """Widget for displaying security alerts and warnings"""
    
    def __init__(self):
        super().__init__()
        self.alerts = []
        self.setup_ui()
        
    def setup_ui(self):
        """Setup security alerts UI"""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            SecurityAlertWidget {
                background-color: #FFF8E1;
                border: 1px solid #FFB74D;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("⚠️ Security Alerts")
        title.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        title.setStyleSheet("color: #E65100; border: none;")
        layout.addWidget(title)
        
        # Alerts list
        self.alerts_list = QListWidget()
        self.alerts_list.setMaximumHeight(100)
        self.alerts_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #FFB74D;
                border-radius: 4px;
                background-color: white;
                font-size: 9px;
            }
            QListWidgetItem {
                padding: 4px;
                border-bottom: 1px solid #FFF3E0;
            }
        """)
        layout.addWidget(self.alerts_list)
        
        # Add sample alert
        self.add_alert("INFO", "KME connection established", "low")
        
    def add_alert(self, alert_type: str, message: str, severity: str):
        """Add security alert"""
        timestamp = datetime.now().strftime("%H:%M")
        alert_text = f"[{timestamp}] {alert_type}: {message}"
        
        item = QListWidgetItem(alert_text)
        
        # Color code by severity
        if severity == "high":
            item.setBackground(QColor("#FFEBEE"))
        elif severity == "medium":
            item.setBackground(QColor("#FFF3E0"))
        else:
            item.setBackground(QColor("#E8F5E8"))
            
        self.alerts_list.insertItem(0, item)
        
        # Keep only last 20 alerts
        if self.alerts_list.count() > 20:
            self.alerts_list.takeItem(self.alerts_list.count() - 1)
            
        self.alerts.append({
            'type': alert_type,
            'message': message,
            'severity': severity,
            'timestamp': timestamp
        })

class SecurityStatusWorker(QThread):
    """Background worker for fetching security status"""
    
    status_updated = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.running = True
        
    def run(self):
        """Main worker loop"""
        while self.running:
            try:
                # Get status from core
                if self.core:
                    status = self.core.get_qkd_status()
                    self.status_updated.emit(status)
                else:
                    # Mock status for testing
                    mock_status = {
                        'kme_connected': True,
                        'qkd_rate': 10000,
                        'available_keys': 234,
                        'used_keys': 12,
                        'total_keys': 300,
                        'active_sessions': {
                            'email': 2,
                            'chat': 1,
                            'calls': 0
                        }
                    }
                    self.status_updated.emit(mock_status)
                    
                self.msleep(5000)  # Update every 5 seconds
                
            except Exception as e:
                self.error_occurred.emit(str(e))
                self.msleep(10000)  # Wait longer on error
                
    def stop(self):
        """Stop the worker"""
        self.running = False

class SecurityDockWidget(QDockWidget):
    """Main security dock widget with comprehensive monitoring"""
    
    def __init__(self, core):
        super().__init__("Security Monitor")
        self.core = core
        self.status_worker = None
        
        # Configure dock widget
        self.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable | 
            QDockWidget.DockWidgetFeature.DockWidgetFloatable |
            QDockWidget.DockWidgetFeature.DockWidgetClosable
        )
        
        self.setup_ui()
        self.start_monitoring()
        
        logging.info("Security Dock Widget initialized")
        
    def setup_ui(self):
        """Setup the complete security dock UI"""
        # Main container
        container = QWidget()
        main_layout = QVBoxLayout(container)
        main_layout.setSpacing(8)
        main_layout.setContentsMargins(8, 8, 8, 8)
        
        # Create scrollable area for all widgets
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_layout.setSpacing(8)
        
        # Security Metrics Widget
        self.metrics_widget = SecurityMetricsWidget()
        scroll_layout.addWidget(self.metrics_widget)
        
        # Key Management Widget
        self.key_management_widget = KeyManagementWidget()
        self.key_management_widget.key_request_signal.connect(self.handle_key_request)
        scroll_layout.addWidget(self.key_management_widget)
        
        # Security Alerts Widget
        self.alerts_widget = SecurityAlertWidget()
        scroll_layout.addWidget(self.alerts_widget)
        
        # Advanced Options Button
        self.advanced_button = QPushButton("⚙️ Advanced Options")
        self.advanced_button.setStyleSheet("""
            QPushButton {
                background-color: #666;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #555;
            }
        """)
        self.advanced_button.clicked.connect(self.show_advanced_options)
        scroll_layout.addWidget(self.advanced_button)
        
        # KME Status Details Button
        self.kme_details_button = QPushButton("📊 KME Details")
        self.kme_details_button.setStyleSheet("""
            QPushButton {
                background-color: #61FF00;
                color: black;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #50E000;
            }
        """)
        self.kme_details_button.clicked.connect(self.show_kme_details)
        scroll_layout.addWidget(self.kme_details_button)
        
        scroll_layout.addStretch()
        
        scroll_area.setWidget(scroll_widget)
        main_layout.addWidget(scroll_area)
        
        self.setWidget(container)
        
        # Set minimum and preferred sizes
        self.setMinimumWidth(280)
        self.setMaximumWidth(350)
        
    def start_monitoring(self):
        """Start background monitoring of security status"""
        if not self.status_worker:
            self.status_worker = SecurityStatusWorker(self.core)
            self.status_worker.status_updated.connect(self.update_security_status)
            self.status_worker.error_occurred.connect(self.handle_monitoring_error)
            self.status_worker.start()
            
            logging.info("Security monitoring started")
            
    def stop_monitoring(self):
        """Stop background monitoring"""
        if self.status_worker:
            self.status_worker.stop()
            self.status_worker.wait()
            self.status_worker = None
            
            logging.info("Security monitoring stopped")
            
    @pyqtSlot(dict)
    def update_security_status(self, status: Dict):
        """Update security status display"""
        try:
            # Update metrics widget
            self.metrics_widget.update_qkd_status(
                connected=status.get('kme_connected', False),
                rate=status.get('qkd_rate', 0)
            )
            
            self.metrics_widget.update_key_pool(
                available=status.get('available_keys', 0),
                used=status.get('used_keys', 0),
                total=status.get('total_keys', 100)
            )
            
            sessions = status.get('active_sessions', {})
            self.metrics_widget.update_sessions(
                email_count=sessions.get('email', 0),
                chat_count=sessions.get('chat', 0),
                call_count=sessions.get('calls', 0)
            )
            
            # Check for alerts
            available_keys = status.get('available_keys', 0)
            total_keys = status.get('total_keys', 100)
            
            if available_keys < total_keys * 0.2:  # Less than 20%
                self.alerts_widget.add_alert(
                    "WARNING", 
                    f"Key pool low: {available_keys} keys remaining", 
                    "high"
                )
            elif available_keys < total_keys * 0.5:  # Less than 50%
                self.alerts_widget.add_alert(
                    "INFO", 
                    f"Key pool moderate: {available_keys} keys remaining", 
                    "medium"
                )
                
        except Exception as e:
            logging.error(f"Error updating security status: {e}")
            
    @pyqtSlot(str)
    def handle_monitoring_error(self, error_message: str):
        """Handle monitoring errors"""
        logging.error(f"Security monitoring error: {error_message}")
        self.alerts_widget.add_alert("ERROR", f"Monitoring error: {error_message}", "high")
        
    @pyqtSlot(dict)
    def handle_key_request(self, request: Dict):
        """Handle key request from key management widget"""
        try:
            logging.info(f"Key request: {request}")
            
            # In real implementation, this would call the KME
            # For now, simulate successful key generation
            
            key_id = f"QK_{int(datetime.now().timestamp())}"
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            self.key_management_widget.add_recent_key(
                key_id=key_id,
                key_type=request['key_type'],
                length=request['key_length'],
                timestamp=timestamp
            )
            
            self.alerts_widget.add_alert(
                "INFO", 
                f"Key generated: {request['key_type']} ({request['key_length']} bits)", 
                "low"
            )
            
        except Exception as e:
            logging.error(f"Error handling key request: {e}")
            self.alerts_widget.add_alert("ERROR", f"Key request failed: {str(e)}", "high")
            
    def show_advanced_options(self):
        """Show advanced security options dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Advanced Security Options")
        dialog.setModal(True)
        dialog.resize(500, 400)
        
        layout = QVBoxLayout(dialog)
        
        # Options content
        options_text = QTextEdit()
        options_text.setReadOnly(True)
        options_text.setHtml("""
        <h3>🔧 Advanced Security Configuration</h3>
        <p><b>Quantum Key Distribution Settings:</b></p>
        <ul>
            <li>Key refresh interval: 30 minutes</li>
            <li>Maximum key age: 24 hours</li>
            <li>Key pool minimum threshold: 50 keys</li>
        </ul>
        
        <p><b>Security Levels Configuration:</b></p>
        <ul>
            <li>Level 1 (OTP): Maximum message size 50KB</li>
            <li>Level 2 (Q-AES): Default security level</li>
            <li>Level 3 (PQC): CRYSTALS-Kyber enabled</li>
            <li>Level 4 (TLS): Standard transport security</li>
        </ul>
        
        <p><b>Audit & Logging:</b></p>
        <ul>
            <li>Key usage logging: Enabled</li>
            <li>Security event logging: Enabled</li>
            <li>Performance monitoring: Enabled</li>
        </ul>
        
        <p><b>Network Settings:</b></p>
        <ul>
            <li>KME Server: 127.0.0.1:8080</li>
            <li>Connection timeout: 30 seconds</li>
            <li>Heartbeat interval: 10 seconds</li>
        </ul>
        """)
        layout.addWidget(options_text)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        button_box.accepted.connect(dialog.accept)
        layout.addWidget(button_box)
        
        dialog.exec()
        
    def show_kme_details(self):
        """Show detailed KME statistics"""
        dialog = QDialog(self)
        dialog.setWindowTitle("KME Status Details")
        dialog.setModal(True)
        dialog.resize(600, 500)
        
        layout = QVBoxLayout(dialog)
        
        # KME details content
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        
        # Get current stats (mock for now)
        stats_html = """
        <h2>🔐 Key Management Entity (KME) Status</h2>
        
        <h3>Connection Status</h3>
        <table border="1" style="border-collapse: collapse; width: 100%;">
            <tr><td><b>Status</b></td><td style="color: green;">✅ Connected</td></tr>
            <tr><td><b>Server</b></td><td>127.0.0.1:8080</td></tr>
            <tr><td><b>Uptime</b></td><td>2h 34m 12s</td></tr>
            <tr><td><b>Last Heartbeat</b></td><td>2 seconds ago</td></tr>
        </table>
        
        <h3>Key Statistics</h3>
        <table border="1" style="border-collapse: collapse; width: 100%;">
            <tr><td><b>Total Keys Generated</b></td><td>1,247</td></tr>
            <tr><td><b>Keys Available</b></td><td>234</td></tr>
            <tr><td><b>Keys Consumed</b></td><td>12</td></tr>
            <tr><td><b>Keys Expired</b></td><td>23</td></tr>
            <tr><td><b>Average Key Size</b></td><td>256 bits</td></tr>
        </table>
        
        <h3>Performance Metrics</h3>
        <table border="1" style="border-collapse: collapse; width: 100%;">
            <tr><td><b>QKD Generation Rate</b></td><td>10,000 bps</td></tr>
            <tr><td><b>Key Request Latency</b></td><td>12ms (avg)</td></tr>
            <tr><td><b>Success Rate</b></td><td>99.8%</td></tr>
            <tr><td><b>Error Rate</b></td><td>0.2%</td></tr>
        </table>
        
        <h3>Security Events (Last 24h)</h3>
        <ul>
            <li>✅ 15:42 - Key pool refilled (250 new keys)</li>
            <li>ℹ️ 14:23 - L1 OTP key requested (alice_smith)</li>
            <li>⚠️ 12:15 - Key pool low warning (threshold reached)</li>
            <li>✅ 11:30 - KME connection restored</li>
            <li>❌ 11:28 - KME connection lost (network timeout)</li>
        </ul>
        """
        
        details_text.setHtml(stats_html)
        layout.addWidget(details_text)
        
        # Refresh button
        refresh_button = QPushButton("🔄 Refresh Statistics")
        refresh_button.clicked.connect(lambda: self.alerts_widget.add_alert(
            "INFO", "Statistics refreshed", "low"
        ))
        layout.addWidget(refresh_button)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        button_box.accepted.connect(dialog.accept)
        layout.addWidget(button_box)
        
        dialog.exec()
        
    def closeEvent(self, event):
        """Handle dock widget close event"""
        self.stop_monitoring()
        event.accept()
        
    def cleanup(self):
        """Cleanup security dock resources"""
        self.stop_monitoring()
        logging.info("Security Dock Widget cleanup completed")