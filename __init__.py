#!/usr/bin/env python3
"""
QuMail Package Initialization
"""

__version__ = "1.0.0"
__author__ = "ISRO Quantum Communications Team"
__description__ = "Quantum Secure Email Client with ETSI GS QKD 014 compliance"

# Package imports
from .main import main
from .core.app_core import QuMailCore
from .crypto.kme_simulator import KMESimulator
from .crypto.cipher_strategies import CipherManager
from .gui.main_window import QuMailMainWindow

__all__ = [
    'main',
    'QuMailCore', 
    'KMESimulator',
    'CipherManager',
    'QuMailMainWindow'
]
