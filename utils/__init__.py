#!/usr/bin/env python3
"""
Utility Modules for QuMail
"""

# Configuration loader
def load_config():
    """Load application configuration"""
    return {
        'kme_url': 'http://127.0.0.1:8080',
        'app_name': 'QuMail',
        'version': '1.0.0',
        'debug': True
    }

# Logging setup
import logging
import sys
from pathlib import Path

def setup_logging():
    """Setup application logging"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Create logs directory
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_dir / 'qumail.log')
        ]
    )
    
    # Reduce noise from some libraries
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

# Styles
def get_main_window_stylesheet():
    """Get main window stylesheet"""
    return """
    QMainWindow {
        background-color: #FFFFFF;
    }
    
    QToolBar {
        background-color: #F8F9FA;
        border: none;
        spacing: 8px;
        padding: 8px;
    }
    
    QStatusBar {
        background-color: #F8F9FA;
        border-top: 1px solid #E0E0E0;
    }
    
    QDockWidget {
        titlebar-close-icon: none;
        titlebar-normal-icon: none;
    }
    
    QDockWidget::title {
        background-color: #4285F4;
        color: white;
        padding: 8px;
        text-align: center;
    }
    """
