#!/usr/bin/env python3
"""
Styles and theming for QuMail - Material Design Overhaul
ISRO-Grade UI/UX Implementation
"""
import os
import logging

def load_style_sheet(file_name="style.qss"):
    """
    Loads a QSS (Qt Style Sheet) file from the assets directory.
    
    This function is required by main_window.py and should not be removed.
    """
    # Assuming 'style.qss' is located in the same directory as this module,
    # or a known 'assets' folder relative to the project root.
    
    # Determine the path to the styles.py file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    style_path = os.path.join(base_dir, 'assets', file_name) 

    # Fallback path if assets is structured differently (e.g., in the project root)
    if not os.path.exists(style_path):
        style_path = os.path.join(base_dir, '..', 'assets', file_name)

    try:
        if os.path.exists(style_path):
            with open(style_path, 'r') as f:
                return f.read()
        else:
            logging.warning(f"Style sheet file not found: {style_path}. Using default system style.")
            return ""
    except Exception as e:
        logging.error(f"Failed to load style sheet: {e}")
        return ""
def get_main_window_stylesheet() -> str:
    """Get main window stylesheet - Material Design Overhaul"""
    # New Material-inspired theme colors
    PRIMARY_BLUE = "#1E88E5" 
    SECONDARY_GREEN = "#00C853"
    QUANTUM_CYAN = "#00BCD4"
    BACKGROUND_FA = "#FAFAFA"
    SURFACE_WHITE = "#FFFFFF"
    
    return f"""
    /* --- I. Global Window & Typography (Material / HCI) --- */
    QMainWindow {{
        background-color: {BACKGROUND_FA};
        color: #212121;
        font-family: 'Roboto', 'Arial', sans-serif;
        font-size: 10pt;
    }}
    
    /* --- II. Toolbar & Header (Material Elevation) --- */
    QToolBar {{
        background-color: {SURFACE_WHITE};
        border: none;
        border-bottom: 1px solid #E0E0E0; /* Subtle elevation */
        spacing: 12px; 
        padding: 8px 16px;
        min-height: 56px;
    }}
    
    /* Security Selector (Prominent Chip/Badge Design) - Targets QComboBox with objectName="SecuritySelector" */
    QComboBox#SecuritySelector {{
        padding: 6px 16px;
        border: 2px solid {PRIMARY_BLUE};
        border-radius: 20px; /* Pill shape - Android UX */
        background-color: {SURFACE_WHITE};
        font-weight: bold;
        color: {PRIMARY_BLUE};
        min-width: 250px;
        /* box-shadow is tricky in standard QSS, relying on border/background for visual depth */
    }}
    
    QComboBox#SecuritySelector::drop-down {{
        border: none;
    }}
    
    QComboBox#SecuritySelector::down-arrow {{
        width: 12px;
        height: 12px;
    }}
    
    /* --- III. Status Bar & Indicators (HCI Feedback) --- */
    QStatusBar {{
        background-color: {SURFACE_WHITE};
        border-top: 1px solid #E0E0E0;
        color: #757575;
        font-size: 9pt;
        padding: 4px;
    }}
    
    /* QKD Status Label (Custom Cyan for Quantum Distinction) */
    QLabel#QKDStatusLabel {{
        color: {QUANTUM_CYAN};
        font-weight: bold;
        padding: 4px 8px;
        background-color: rgba(0, 188, 212, 0.1);
        border-radius: 4px;
    }}

    /* --- IV. Dock & Panels (Material Cards) --- */
    QDockWidget::title {{
        background-color: #EEEEEE; 
        color: #424242;
        padding: 8px;
        font-size: 11pt;
        font-weight: 500;
        border-bottom: 1px solid #E0E0E0;
    }}
    
    QFrame[frameShape="4"] {{ 
        border: none;
        border-radius: 8px;
        background-color: {SURFACE_WHITE};
        /* Simulating Material Elevation */
        border: 1px solid #E0E0E0; 
    }}

    /* --- V. Tabs (Hybrid Theming) --- */
    QTabWidget::pane {{
        border: none;
        background-color: white;
    }}
    
    QTabBar::tab {{
        background-color: #F8F9FA;
        border: none;
        padding: 12px 24px;
        margin-right: 2px;
        font-size: 14px;
        font-weight: bold;
        min-width: 100px;
    }}
    
    QTabBar::tab:selected {{
        background-color: {PRIMARY_BLUE};
        color: white;
    }}
    
    QTabBar::tab:hover:!selected {{
        background-color: #E8F0FE;
        color: {PRIMARY_BLUE};
    }}

    /* Chat and Call tabs use WhatsApp green when selected */
    QTabBar::tab:selected[title*="Chat"], 
    QTabBar::tab:selected[title*="Call"] {{ 
        background-color: {SECONDARY_GREEN};
        color: white;
    }}
    
    /* Compose Button (Floating Action Button style - Android UX) */
    QPushButton#ComposeButton {{
        background-color: {PRIMARY_BLUE};
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 28px;
        font-weight: bold;
        font-size: 14px;
        min-width: 120px;
    }}
    QPushButton#ComposeButton:hover {{
        background-color: #1976D2;
    }}
    
    /* --- VI. Input Fields (Material Design) --- */
    QLineEdit {{
        padding: 8px 12px;
        border: 1px solid #E0E0E0;
        border-radius: 4px;
        background-color: {SURFACE_WHITE};
        font-size: 14px;
    }}
    
    QLineEdit:focus {{
        border-color: {PRIMARY_BLUE};
        background-color: white;
    }}
    
    /* --- VII. Buttons (Material Design) --- */
    QPushButton {{
        padding: 8px 16px;
        border: none;
        border-radius: 4px;
        font-weight: 500;
        font-size: 14px;
    }}
    
    QPushButton:hover {{
        background-color: rgba(30, 136, 229, 0.08);
    }}
    
    QPushButton:pressed {{
        background-color: rgba(30, 136, 229, 0.12);
    }}
    """ + get_gmail_theme_styles() + get_whatsapp_theme_styles()

def get_gmail_theme_styles() -> str:
    """Gmail-specific theme styles"""
    return """
    /* Gmail Theme Styles */
    QWidget[gmailTheme="true"] {
        background-color: #FFFFFF;
    }
    
    QWidget[gmailTheme="true"] QScrollArea {
        background-color: #F8F9FA;
    }
    """

def get_whatsapp_theme_styles() -> str:
    """WhatsApp-specific theme styles"""
    return """
    /* WhatsApp Theme Styles */
    QWidget[whatsappTheme="true"] {
        background-color: #E5DDD5;
    }
    
    QWidget[whatsappTheme="true"] QFrame {
        background-color: #FFFFFF;
    }
    """

def get_dark_theme_styles() -> str:
    """Get dark theme styles"""
    return """
    /* Dark Theme */
    .dark-theme {
        background-color: #121212;
        color: #E0E0E0;
    }
    
    .dark-theme QMainWindow {
        background-color: #121212;
        color: #E0E0E0;
    }
    
    .dark-theme QToolBar {
        background-color: #1E1E1E;
        color: #E0E0E0;
    }
    
    .dark-theme QTabWidget::pane {
        background-color: #1E1E1E;
    }
    
    .dark-theme QTabBar::tab {
        background-color: #2D2D2D;
        color: #E0E0E0;
    }
    
    .dark-theme QTabBar::tab:selected {
        background-color: #4285F4;
        color: white;
    }
    
    .dark-theme QFrame {
        background-color: #1E1E1E;
        border-color: #333333;
    }
    
    .dark-theme QScrollBar:vertical {
        background-color: #2D2D2D;
    }
    
    .dark-theme QScrollBar::handle:vertical {
        background-color: #555555;
    }
    """

def get_security_indicator_styles() -> str:
    """Get security indicator styles"""
    return """
    /* Security Indicators */
    .security-quantum {
        color: #61FF00;
        font-weight: bold;
    }
    
    .security-pqc {
        color: #FFA500;
        font-weight: bold;
    }
    
    .security-standard {
        color: #999999;
    }
    
    .security-banner-quantum {
        background-color: rgba(97, 255, 0, 0.1);
        border: 1px solid #61FF00;
        color: #61FF00;
        padding: 8px 12px;
        border-radius: 4px;
        font-weight: bold;
    }
    
    .security-banner-pqc {
        background-color: rgba(255, 165, 0, 0.1);
        border: 1px solid #FFA500;
        color: #FFA500;
        padding: 8px 12px;
        border-radius: 4px;
        font-weight: bold;
    }
    
    .security-banner-error {
        background-color: rgba(244, 67, 54, 0.1);
        border: 1px solid #F44336;
        color: #F44336;
        padding: 8px 12px;
        border-radius: 4px;
        font-weight: bold;
    }
    """
