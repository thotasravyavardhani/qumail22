#!/usr/bin/env python3
"""
QuMail Main Window - Unified Quantum Communication Interface

Implements the hybrid Gmail + WhatsApp interface design with KME heartbeat integration
"""

import asyncio
import logging
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QToolBar, QDockWidget, QComboBox, QLabel, QLineEdit, QPushButton,
    QSplitter, QFrame, QStackedWidget, QStatusBar, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QIcon, QPixmap, QAction, QPalette, QColor

# Core imports
from ..core.app_core import QuMailCore
from ..utils.styles import load_style_sheet
from ..utils.config import load_config

from .email_module import EmailModule
from .chat_module import ChatModule
from .call_module import CallModule
from .security_dock import SecurityDockWidget
from ..utils.styles import get_main_window_stylesheet

class QuMailMainWindow(QMainWindow):
    """Main application window with KME heartbeat integration"""
    
    # Signals
    security_level_changed = pyqtSignal(int)
    theme_changed = pyqtSignal(str)
    
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.current_theme = "light"
        self.modules = {}
        
        # KME ROBUSTNESS: Heartbeat monitoring timer
        self.kme_status_timer = QTimer()
        self.kme_status_timer.timeout.connect(self.update_kme_status)
        self.kme_status_timer.start(5000)  # Update every 5 seconds
        
        # Initialize UI
        self.init_ui()
        self.setup_connections()
        self.update_ui_state()
        
        # KME ROBUSTNESS: Start KME heartbeat monitoring in UI
        self.start_kme_heartbeat_monitoring()
        
        logging.info("QuMail Main Window initialized with KME monitoring")
        
    def init_ui(self):
        """Initialize the user interface"""
        # Set window properties
        self.setWindowTitle("QuMail - Quantum Secure Communications")
        self.setMinimumSize(QSize(1280, 720))
        self.resize(1440, 900)
        
        # Apply stylesheet
        self.setStyleSheet(get_main_window_stylesheet())
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Setup toolbar
        self.setup_toolbar()
        
        # Create main splitter for layout
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(main_splitter)
        
        # Setup sidebar dock
        self.setup_sidebar(main_splitter)
        
        # Setup central tab widget
        self.setup_main_tabs(main_splitter)
        
        # Setup security dock
        self.setup_security_dock()
        
        # Setup status bar with KME heartbeat indicators
        self.setup_enhanced_status_bar()
        
    def setup_toolbar(self):
        """Setup the main application toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.addToolBar(toolbar)
        
        # Search bar
        search_widget = QWidget()
        search_layout = QHBoxLayout(search_widget)
        search_layout.setContentsMargins(0, 0, 0, 0)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search mail, contacts, or chats...")
        self.search_input.setMinimumWidth(300)
        self.search_input.setStyleSheet("""
            QLineEdit {
                padding: 8px 12px;
                border: 1px solid #E0E0E0;
                border-radius: 20px;
                background-color: #F8F9FA;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #4285F4;
                background-color: white;
            }
        """)
        
        search_layout.addWidget(self.search_input)
        toolbar.addWidget(search_widget)
        
        # Add stretch to push security controls to right
        toolbar.addSeparator()
        
        # Security Level Selector (The most important shared component)
        security_label = QLabel("Security Level:")
        toolbar.addWidget(security_label)
        
        self.security_selector = QComboBox()
        self.security_selector.setObjectName("SecuritySelector")
        self.security_selector.addItems([
            "Level 2: Quantum-aided AES (Default)",
            "Level 1: Quantum OTP (Advanced)", 
            "Level 3: Post-Quantum Crypto + Files",
            "Level 4: Standard TLS Only"
        ])
        self.security_selector.setMinimumWidth(300)  # Increased width for PQC text
        toolbar.addWidget(self.security_selector)
        
        toolbar.addSeparator()
        
        # KME ROBUSTNESS: KME status indicator in toolbar
        self.kme_status_indicator = QPushButton("🔴 KME")
        self.kme_status_indicator.setToolTip("KME Connection Status (Click for details)")
        self.kme_status_indicator.setFixedSize(60, 30)
        self.kme_status_indicator.clicked.connect(self.show_kme_details)
        toolbar.addWidget(self.kme_status_indicator)
        
        # Theme toggle
        self.theme_button = QPushButton("🌙")
        self.theme_button.setToolTip("Toggle Dark Mode")
        self.theme_button.setFixedSize(40, 40)
        toolbar.addWidget(self.theme_button)
        
        # Notifications
        self.notifications_button = QPushButton("🔔")
        self.notifications_button.setToolTip("Notifications")
        self.notifications_button.setFixedSize(40, 40)
        toolbar.addWidget(self.notifications_button)
        
        # Profile/Settings
        self.profile_button = QPushButton("👤")
        self.profile_button.setToolTip("Profile & Settings")
        self.profile_button.setFixedSize(40, 40)
        toolbar.addWidget(self.profile_button)
        
    def setup_sidebar(self, parent_splitter):
        """Setup the contextual sidebar"""
        # Create sidebar frame
        self.sidebar_frame = QFrame()
        self.sidebar_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        self.sidebar_frame.setMinimumWidth(250)
        self.sidebar_frame.setMaximumWidth(350)
        
        sidebar_layout = QVBoxLayout(self.sidebar_frame)
        
        # Sidebar content will be managed by active module
        self.sidebar_stack = QStackedWidget()
        sidebar_layout.addWidget(self.sidebar_stack)
        
        parent_splitter.addWidget(self.sidebar_frame)
        
    def setup_main_tabs(self, parent_splitter):
        """Setup the main application tabs"""
        # Create tab widget
        self.main_tabs = QTabWidget()
        self.main_tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.main_tabs.setTabsClosable(False)
        self.main_tabs.setMovable(False)
        
        # Tab styling
        self.main_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #F8F9FA;
                border: none;
                padding: 12px 24px;
                margin-right: 2px;
                font-size: 14px;
                font-weight: bold;
                min-width: 100px;
            }
            QTabBar::tab:selected {
                background-color: #4285F4;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background-color: #E8F0FE;
                color: #4285F4;
            }
        """)
        
        # Initialize modules
        self.email_module = EmailModule(self.core)
        self.chat_module = ChatModule(self.core)
        self.call_module = CallModule(self.core)
        
        self.modules = {
            'email': self.email_module,
            'chat': self.chat_module,
            'calls': self.call_module
        }
        
        # Add tabs
        self.main_tabs.addTab(self.email_module, "📧 Email")
        self.main_tabs.addTab(self.chat_module, "💬 Chats")
        self.main_tabs.addTab(self.call_module, "📞 Calls")
        
        # Add tabs to splitter
        parent_splitter.addWidget(self.main_tabs)
        
        # Set splitter proportions (sidebar:main = 1:3)
        parent_splitter.setSizes([300, 900])
        
    def setup_security_dock(self):
        """Setup the security status dock"""
        self.security_dock = SecurityDockWidget(self.core)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.security_dock)
        
        # Initially hide - can be toggled
        self.security_dock.setVisible(False)
        
    def setup_enhanced_status_bar(self):
        """Setup the application status bar with KME heartbeat monitoring"""
        status_bar = QStatusBar()
        self.setStatusBar(status_bar)
        
        # QKD Status with heartbeat info
        self.qkd_status_label = QLabel("QKD Link: INITIALIZING...")
        self.qkd_status_label.setObjectName("QKDStatusLabel")
        status_bar.addPermanentWidget(self.qkd_status_label)
        
        # KME ROBUSTNESS: Heartbeat indicator
        self.heartbeat_label = QLabel("♥ Heartbeat: --")
        self.heartbeat_label.setStyleSheet("""
            QLabel {
                color: #666;
                padding: 4px 8px;
                font-size: 11px;
            }
        """)
        status_bar.addPermanentWidget(self.heartbeat_label)
        
        # Connection Status
        self.connection_status_label = QLabel("Connecting...")
        self.connection_status_label.setStyleSheet("""
            QLabel {
                color: #FF9800;
                padding: 4px 8px;
            }
        """)
        status_bar.addPermanentWidget(self.connection_status_label)
        
        # PQC Statistics
        self.pqc_stats_label = QLabel("PQC: Ready")
        self.pqc_stats_label.setStyleSheet("""
            QLabel {
                color: #9C27B0;
                padding: 4px 8px;
                font-size: 11px;
            }
        """)
        status_bar.addPermanentWidget(self.pqc_stats_label)
        
    def start_kme_heartbeat_monitoring(self):
        """KME ROBUSTNESS: Start heartbeat monitoring in the UI"""
        # Update KME status immediately
        self.update_kme_status()
        
        # Schedule periodic updates
        self.kme_status_timer.start(3000)  # Update every 3 seconds
        
    def update_kme_status(self):
        """KME ROBUSTNESS: Update KME status indicators"""
        try:
            if self.core and hasattr(self.core, 'get_qkd_status'):
                qkd_status = self.core.get_qkd_status()
                
                # Update main QKD status
                if qkd_status['kme_connected']:
                    status_text = f"QKD Link: ACTIVE Ψ ({qkd_status['success_rate']:.1f}%)"
                    self.qkd_status_label.setStyleSheet("color: #61FF00; font-weight: bold;")
                    self.kme_status_indicator.setText("🟢 KME")
                    self.kme_status_indicator.setStyleSheet("background-color: #4CAF50; color: white;")
                else:
                    status_text = "QKD Link: DEGRADED"
                    self.qkd_status_label.setStyleSheet("color: #FF5722; font-weight: bold;")
                    self.kme_status_indicator.setText("🔴 KME")
                    self.kme_status_indicator.setStyleSheet("background-color: #F44336; color: white;")
                
                self.qkd_status_label.setText(status_text)
                
                # Update heartbeat indicator
                if qkd_status.get('heartbeat_enabled'):
                    uptime_mins = qkd_status.get('uptime_seconds', 0) // 60
                    self.heartbeat_label.setText(f"♥ Heartbeat: {uptime_mins}m")
                    self.heartbeat_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
                else:
                    self.heartbeat_label.setText("♥ Heartbeat: OFF")
                    self.heartbeat_label.setStyleSheet("color: #999;")
                    
                # Update PQC statistics
                pqc_stats = qkd_status.get('pqc_stats', {})
                if pqc_stats.get('files_encrypted', 0) > 0:
                    total_mb = pqc_stats.get('total_size_encrypted', 0) / (1024 * 1024)
                    self.pqc_stats_label.setText(f"PQC: {pqc_stats['files_encrypted']} files, {total_mb:.1f}MB")
                else:
                    self.pqc_stats_label.setText("PQC: Ready")
                    
        except Exception as e:
            logging.warning(f"Error updating KME status: {e}")
            self.qkd_status_label.setText("QKD Link: ERROR")
            self.qkd_status_label.setStyleSheet("color: #FF5722; font-weight: bold;")
            
    def show_kme_details(self):
        """Show detailed KME connection information"""
        try:
            if self.core and hasattr(self.core, 'get_qkd_status'):
                qkd_status = self.core.get_qkd_status()
                pqc_stats = self.core.get_pqc_statistics() if hasattr(self.core, 'get_pqc_statistics') else {}
                
                details = (
                    f"**KME Connection Details**\n\n"
                    f"• Status: {'Connected' if qkd_status['kme_connected'] else 'Disconnected'}\n"
                    f"• Security Level: {qkd_status['security_level']}\n"
                    f"• Success Rate: {qkd_status.get('success_rate', 0):.1f}%\n"
                    f"• Connection Failures: {qkd_status.get('connection_failures', 0)}\n"
                    f"• Heartbeat: {'Enabled' if qkd_status.get('heartbeat_enabled') else 'Disabled'}\n"
                    f"• Uptime: {qkd_status.get('uptime_seconds', 0) // 60} minutes\n\n"
                    f"**PQC File Encryption Stats**\n"
                    f"• Files Encrypted: {pqc_stats.get('files_encrypted', 0)}\n"
                    f"• Total Size: {pqc_stats.get('total_size_mb', 0):.2f} MB\n"
                    f"• FEK Operations: {pqc_stats.get('fek_operations', 0)}\n"
                    f"• Kyber Encapsulations: {pqc_stats.get('kyber_encapsulations', 0)}"
                )
                
                QMessageBox.information(self, "KME & PQC Status", details)
            else:
                QMessageBox.warning(self, "KME Status", "KME status information not available.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to retrieve KME status: {e}")
        
    def setup_connections(self):
        """Setup signal-slot connections"""
        # Tab change handling
        self.main_tabs.currentChanged.connect(self.on_tab_changed)
        
        # Security level changes
        self.security_selector.currentIndexChanged.connect(self.on_security_level_changed)
        
        # Theme toggle
        self.theme_button.clicked.connect(self.toggle_theme)
        
        # Search
        self.search_input.textChanged.connect(self.on_search_text_changed)
        
        # Profile/Logout button
        self.profile_button.clicked.connect(self.show_profile_dialog)
        
        # Module connections
        for module in self.modules.values():
            if hasattr(module, 'status_message'):
                module.status_message.connect(self.show_status_message)
                
    def on_tab_changed(self, index):
        """Handle tab change events"""
        # Update sidebar content based on active module
        current_widget = self.main_tabs.widget(index)
        
        # Clear sidebar stack
        while self.sidebar_stack.count() > 0:
            widget = self.sidebar_stack.widget(0)
            self.sidebar_stack.removeWidget(widget)
            
        # Add current module's sidebar
        if hasattr(current_widget, 'get_sidebar_widget'):
            sidebar_widget = current_widget.get_sidebar_widget()
            if sidebar_widget:
                self.sidebar_stack.addWidget(sidebar_widget)
                
        # Update theme based on module
        if index == 0:  # Email
            self.apply_gmail_theme()
        elif index == 1 or index == 2:  # Chat/Calls
            self.apply_whatsapp_theme()
            
    def apply_gmail_theme(self):
        """Apply Gmail-inspired theme to the current tab"""
        self.main_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background-color: white;
            }
            QTabBar::tab:selected {
                background-color: #4285F4;
                color: white;
            }
        """)
        
    def apply_whatsapp_theme(self):
        """Apply WhatsApp-inspired theme to the current tab"""
        self.main_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background-color: #E5DDD5;
            }
            QTabBar::tab:selected {
                background-color: #25D366;
                color: white;
            }
        """)
        
    def on_security_level_changed(self, index):
        """Handle security level changes with PQC support"""
        security_levels = ['L2', 'L1', 'L3', 'L4']
        level = security_levels[index]
        
        logging.info(f"Security level changed to: {level}")
        
        # Update core security level
        if self.core:
            self.core.set_security_level(level)
        
        # Emit signal for modules
        self.security_level_changed.emit(index)
        
        # Update status with PQC info
        if level == 'L1':
            self.qkd_status_label.setText("QKD OTP: ACTIVE Ψ")
            self.qkd_status_label.setStyleSheet("color: #61FF00; font-weight: bold;")
        elif level == 'L2':
            self.qkd_status_label.setText("QKD AES: ACTIVE Ψ")
            self.qkd_status_label.setStyleSheet("color: #61FF00; font-weight: bold;")
        elif level == 'L3':
            self.qkd_status_label.setText("PQC + Files: ACTIVE 🔐")
            self.qkd_status_label.setStyleSheet("color: #FFA500; font-weight: bold;")
            # Show PQC info
            self.show_status_message("Level 3: Post-Quantum Crypto enabled with file encryption support")
        elif level == 'L4':
            self.qkd_status_label.setText("Standard TLS")
            self.qkd_status_label.setStyleSheet("color: #999; font-weight: bold;")
            
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        if self.current_theme == "light":
            self.current_theme = "dark"
            self.theme_button.setText("☀️")
            self.apply_dark_theme()
        else:
            self.current_theme = "light"
            self.theme_button.setText("🌙")
            self.apply_light_theme()
            
        self.theme_changed.emit(self.current_theme)
        
    def apply_dark_theme(self):
        """Apply dark theme"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #121212;
                color: white;
            }
        """)
        
    def apply_light_theme(self):
        """Apply light theme"""
        self.setStyleSheet(get_main_window_stylesheet())
        
    def on_search_text_changed(self, text):
        """Handle search text changes"""
        # Forward search to active module
        current_widget = self.main_tabs.currentWidget()
        if hasattr(current_widget, 'handle_search'):
            current_widget.handle_search(text)
            
    def show_status_message(self, message, timeout=3000):
        """Show status bar message"""
        self.statusBar().showMessage(message, timeout)
        
    def show_profile_dialog(self):
        """Show profile/settings dialog with proper logout integration"""
        # Check authentication state
        is_authenticated = (self.core and 
                          hasattr(self.core, 'current_user') and 
                          self.core.current_user is not None)
        
        if is_authenticated:
            # Show user profile information with logout option
            user_info = (f"Logged in as: {self.core.current_user.email}\n"
                        f"Display Name: {self.core.current_user.display_name}\n"
                        f"SAE ID: {self.core.current_user.sae_id}\n"
                        f"Password: {'***Protected***' if self.core.current_user.password_hash else 'Not Set'}\n"
                        f"Last Login: {self.core.current_user.last_login.strftime('%Y-%m-%d %H:%M')}\n\n"
                        "Would you like to log out?")
            
            reply = QMessageBox.question(self, "User Profile", user_info,
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                self.show_status_message("Logging out and stopping KME heartbeat...")
                QTimer.singleShot(100, self.perform_logout)
        else:
            # Show authentication dialog
            reply = QMessageBox.question(self, "Authentication Required", 
                                       "No user is currently authenticated. Would you like to log in?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                self.show_status_message("Starting authentication...")
                QTimer.singleShot(100, self.perform_authentication)
                    
    def perform_logout(self):
        """Perform logout with KME cleanup"""
        try:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    task = asyncio.create_task(self.handle_logout())
                    
                    def check_task_completion():
                        if task.done():
                            self.logout_timer.stop()
                            try:
                                task.result()
                                self.show_status_message("Logout successful. KME heartbeat stopped.")
                                QTimer.singleShot(2000, self.close)
                            except Exception as e:
                                logging.error(f"Logout task error: {e}")
                                self.show_status_message("Logout completed with errors.")
                                QTimer.singleShot(2000, self.close)
                    
                    self.logout_timer = QTimer()
                    self.logout_timer.timeout.connect(check_task_completion)
                    self.logout_timer.start(100)
                else:
                    loop.run_until_complete(self.handle_logout())
                    self.show_status_message("Logout successful.")
                    QTimer.singleShot(2000, self.close)
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self.handle_logout())
                self.show_status_message("Logout successful.")
                QTimer.singleShot(2000, self.close)
        except Exception as e:
            logging.error(f"Logout error: {e}")
            self.show_status_message("Logout completed. Please restart the application.")
            QTimer.singleShot(2000, self.close)
    
    def perform_authentication(self):
        """Perform authentication with KME setup"""
        try:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    task = asyncio.create_task(self.handle_authentication())
                    
                    def check_auth_completion():
                        if task.done():
                            self.auth_timer.stop()
                            try:
                                result = task.result()
                                if result:
                                    self.show_status_message(f"Welcome back, {self.core.current_user.email}!")
                                    self.update_ui_state()
                                else:
                                    self.show_status_message("Authentication failed")
                            except Exception as e:
                                logging.error(f"Authentication task error: {e}")
                                self.show_status_message("Authentication error occurred")
                    
                    self.auth_timer = QTimer()
                    self.auth_timer.timeout.connect(check_auth_completion)
                    self.auth_timer.start(100)
                else:
                    result = loop.run_until_complete(self.handle_authentication())
                    if result:
                        self.show_status_message(f"Welcome back, {self.core.current_user.email}!")
                        self.update_ui_state()
                    else:
                        self.show_status_message("Authentication failed")
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(self.handle_authentication())
                if result:
                    self.show_status_message(f"Welcome back, {self.core.current_user.email}!")
                    self.update_ui_state()
                else:
                    self.show_status_message("Authentication failed")
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            self.show_status_message("Authentication error occurred")

    async def handle_logout(self):
        """Handle user logout process with KME cleanup"""
        try:
            await self.core.logout_user()
            return True
        except Exception as e:
            logging.error(f"Logout process error: {e}")
            return False
            
    async def handle_authentication(self):
        """Handle user authentication process"""
        try:
            auth_success = await self.core.authenticate_user("qumail_native")
            return auth_success
        except Exception as e:
            logging.error(f"Authentication process error: {e}")
            return False
        
    def update_ui_state(self):
        """Update UI state based on application state"""
        is_authenticated = bool(self.core and self.core.current_user)
        
        # Update profile button tooltip based on authentication state
        if is_authenticated:
            self.profile_button.setToolTip(f"Profile: {self.core.current_user.email} (Click to logout)")
            self.connection_status_label.setText("Authenticated & Connected")
            self.connection_status_label.setStyleSheet("""
                QLabel {
                    color: #00C853;
                    padding: 4px 8px;
                    font-weight: bold;
                }
            """)
        else:
            self.profile_button.setToolTip("Profile & Settings (Click to login)")
            self.connection_status_label.setText("Not Authenticated")
            self.connection_status_label.setStyleSheet("""
                QLabel {
                    color: #FF5722;
                    padding: 4px 8px;
                    font-weight: bold;
                }
            """)
        
        # FIXED: Disable main functionality for unauthenticated users  
        self.main_tabs.setEnabled(is_authenticated)
        self.search_input.setEnabled(is_authenticated)
        self.security_selector.setEnabled(is_authenticated)
        
        if not is_authenticated:
            # Show authentication message in main area
            self.show_status_message("Authentication required to access QuMail features")
        
        # Update modules with current user state
        for module in self.modules.values():
            if hasattr(module, 'update_user_state'):
                module.update_user_state(self.core.current_user if self.core else None)
        
    def closeEvent(self, event):
        """Handle application close event with KME cleanup"""
        logging.info("QuMail main window closing - stopping KME monitoring")
        
        # Stop KME status timer
        if self.kme_status_timer:
            self.kme_status_timer.stop()
        
        # Cleanup modules
        for module in self.modules.values():
            if hasattr(module, 'cleanup'):
                module.cleanup()
                
        event.accept()