#!/usr/bin/env python3
"""
GUI Module for QuMail
"""

from .main_window import QuMailMainWindow
from .email_module import EmailModule
from .chat_module import ChatModule
from .call_module import CallModule
from .security_dock import SecurityDockWidget

__all__ = [
    'QuMailMainWindow',
    'EmailModule', 
    'ChatModule',
    'CallModule',
    'SecurityDockWidget'
]
