#!/usr/bin/env python3
"""
QuMail - Quantum Secure Email Client
ISRO-Grade Quantum Communications Application

Main Application Entry Point
"""

import sys
import asyncio
import logging
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon, QPalette, QColor

# Imports corrected in the previous step
from gui.main_window import QuMailMainWindow
from core.app_core import QuMailCore
from crypto.kme_simulator import KMESimulator
from utils.config import load_config
from utils.logger import setup_logging

class QuMailApplication:
    """Main QuMail Application Class"""
    
    def __init__(self):
        self.app = None
        self.main_window = None
        self.core = None
        self.kme_simulator = None
        self.config = None
        
    def setup_application(self):
        """Initialize the PyQt6 application"""
        # FIX: The problematic line below has been REMOVED.
        # QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling)
        self.app = QApplication(sys.argv)
        
        # Set application properties
        self.app.setApplicationName("QuMail")
        self.app.setApplicationVersion("1.0.0")
        self.app.setOrganizationName("ISRO Quantum Communications")
        
        # Set application icon (requires resource file or system icon, placeholder)
        app_icon = QIcon(":/icons/qumail_logo.png")
        self.app.setWindowIcon(app_icon)
        
        # Setup dark/light theme capability
        self.setup_theme()
        
    def setup_theme(self):
        """Configure application theme"""
        palette = QPalette()
        
        # Light theme (default)
        palette.setColor(QPalette.ColorRole.Window, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(0, 0, 0))
        palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(240, 240, 240))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 220))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
        palette.setColor(QPalette.ColorRole.Text, QColor(0, 0, 0))
        palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(0, 0, 0))
        palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
        palette.setColor(QPalette.ColorRole.Link, QColor(66, 133, 244))  # Gmail Blue
        palette.setColor(QPalette.ColorRole.Highlight, QColor(66, 133, 244))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        
        self.app.setPalette(palette)
        
    async def setup_backend_services(self):
        """Initialize backend services"""
        try:
            # Load configuration
            self.config = load_config()
            
            # Start KME Simulator
            self.kme_simulator = KMESimulator()
            
            # Only run KME if the launcher passed the --simulate-kme argument.
            # However, since the launcher handles this, we rely on the main loop 
            # to conditionally start/stop the simulator based on config/launcher.
            # In this context, we assume the launcher has prepared the KME if needed.
            
            # NOTE: We keep the original logic for completeness, as the flask thread is managed externally.
            # For this context, we only initialize KME if the external launcher didn't handle it.
            # The launcher's logic ensures the KME is running before main() is called.
            
            # The simulator logic relies on the config having been loaded, which is correct here.
            # We skip the synchronous start/stop logic here as the launcher handles the background thread.
            
            # Initialize application core
            self.core = QuMailCore(self.config)
            await self.core.initialize()
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to initialize backend services: {e}")
            return False
            
    def setup_main_window(self):
        """Initialize the main application window"""
        try:
            self.main_window = QuMailMainWindow(self.core)
            self.main_window.show()
            return True
        except Exception as e:
            logging.error(f"Failed to create main window: {e}")
            QMessageBox.critical(None, "QuMail Error", 
                               f"Failed to initialize QuMail GUI: {e}")
            return False
            
    async def run_async_setup(self):
        """Run async initialization with authentication"""
        success = await self.setup_backend_services()
        if not success:
            QMessageBox.critical(None, "QuMail Error", 
                               "Failed to initialize QuMail backend services.")
            return False
            
        # AUTHENTICATION FIX: Check if user needs to authenticate
        if not self.core.current_user:
            logging.info("No authenticated user found, prompting for login")
            auth_success = await self.core.authenticate_user("qumail_native")
            if not auth_success:
                QMessageBox.critical(None, "Authentication Required", 
                                   "Authentication failed. QuMail requires user authentication to proceed.")
                return False
        else:
            logging.info(f"User already authenticated: {self.core.current_user.email}")
            
        return True
        
    def run(self):
        """Main application run method"""
        try:
            # Setup PyQt6 application
            self.setup_application()
            
            # Run async setup with authentication enforcement
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # FIXED: Ensure authentication is completed before proceeding
            auth_success = loop.run_until_complete(self.run_async_setup())
            if not auth_success:
                logging.error("Authentication required but failed - application cannot start")
                return 1
            
            # Setup main window only after successful authentication
            if not self.setup_main_window():
                return 1
                
            # Start the Qt event loop
            return self.app.exec()
            
        except Exception as e:
            logging.error(f"Critical application error: {e}")
            return 1
        
        finally:
            # Cleanup - KME stop relies on the application being aware of the simulator thread
            # Since the launcher handles the start, we rely on the system exiting properly.
            pass
                
def main():
    """Application entry point"""
    # Setup logging
    setup_logging()
    
    logging.info("Starting QuMail Quantum Secure Email Client")
    
    # Create and run application
    app = QuMailApplication()
    exit_code = app.run()
    
    logging.info(f"QuMail exiting with code: {exit_code}")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()