#!/usr/bin/env python3
"""
GUI Module for QuMail
"""

from gui.main_window import QuMailMainWindow
from gui.email_module import EmailModule
from gui.chat_module import ChatModule
from gui.call_module import CallModule
from gui.security_dock import SecurityDockWidget

__all__ = [
    'QuMailMainWindow',
    'EmailModule', 
    'ChatModule',
    'CallModule',
    'SecurityDockWidget'
]
