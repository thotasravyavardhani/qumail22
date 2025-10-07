#!/usr/bin/env python3
"""
Configuration Module for QuMail
"""

import os
from pathlib import Path
from typing import Dict, Any

def load_config() -> Dict[str, Any]:
    """Load application configuration"""
    config = {
        # KME Configuration
        'kme_url': os.getenv('QUMAIL_KME_URL', 'http://127.0.0.1:8080'),
        'kme_timeout': int(os.getenv('QUMAIL_KME_TIMEOUT', '30')),
        
        # Application Settings
        'app_name': 'QuMail',
        'version': '1.0.0',
        'debug': os.getenv('QUMAIL_DEBUG', 'true').lower() == 'true',
        
        # Security Settings
        'default_security_level': os.getenv('QUMAIL_DEFAULT_SECURITY', 'L2'),
        'otp_size_limit': int(os.getenv('QUMAIL_OTP_LIMIT', '51200')),  # 50KB
        'max_key_lifetime_hours': int(os.getenv('QUMAIL_KEY_LIFETIME', '24')),
        
        # UI Settings
        'window_width': int(os.getenv('QUMAIL_WINDOW_WIDTH', '1440')),
        'window_height': int(os.getenv('QUMAIL_WINDOW_HEIGHT', '900')),
        'theme': os.getenv('QUMAIL_THEME', 'light'),
        
        # Storage Settings
        'storage_dir': Path.home() / '.qumail',
        'log_level': os.getenv('QUMAIL_LOG_LEVEL', 'INFO'),
        
        # Email Settings
        'email_batch_size': int(os.getenv('QUMAIL_EMAIL_BATCH', '50')),
        'chat_history_limit': int(os.getenv('QUMAIL_CHAT_HISTORY', '100')),
        
        # OAuth2 Settings - HARDCODED CREDENTIALS FIX
        'oauth2_timeout': int(os.getenv('QUMAIL_OAUTH_TIMEOUT', '60')),
        
        # OAuth2 Client Credentials from Environment Variables (Replit Secrets)
        # Note: These are required for OAuth2 email integration
        # Yahoo and Outlook can use placeholder values until real credentials are added
        'gmail_client_id': os.getenv('GMAIL_CLIENT_ID', os.getenv('QUMAIL_GMAIL_CLIENT_ID')),
        'gmail_client_secret': os.getenv('GMAIL_CLIENT_SECRET', os.getenv('QUMAIL_GMAIL_CLIENT_SECRET')),
        'yahoo_client_id': os.getenv('YAHOO_CLIENT_ID', 'dummy_yahoo_client_id'),
        'yahoo_client_secret': os.getenv('YAHOO_CLIENT_SECRET', 'dummy_yahoo_secret'),
        'outlook_client_id': os.getenv('OUTLOOK_CLIENT_ID', 'dummy_outlook_client_id'),
        'outlook_client_secret': os.getenv('OUTLOOK_CLIENT_SECRET', 'dummy_outlook_secret'),
        
        # Network Settings
        'connection_timeout': int(os.getenv('QUMAIL_CONN_TIMEOUT', '10')),
        'retry_attempts': int(os.getenv('QUMAIL_RETRY_ATTEMPTS', '3'))
    }
    
    return config

def get_log_config() -> Dict[str, Any]:
    """Get logging configuration"""
    config = load_config()
    
    return {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'detailed': {
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': config['log_level'],
                'formatter': 'standard',
                'stream': 'ext://sys.stdout'
            },
            'file': {
                'class': 'logging.FileHandler',
                'level': 'DEBUG',
                'formatter': 'detailed',
                'filename': config['storage_dir'] / 'logs' / 'qumail.log',
                'mode': 'a'
            }
        },
        'loggers': {
            'qumail': {
                'level': 'DEBUG',
                'handlers': ['console', 'file'],
                'propagate': False
            },
            'werkzeug': {
                'level': 'WARNING',
                'handlers': ['file'],
                'propagate': False
            }
        },
        'root': {
            'level': config['log_level'],
            'handlers': ['console', 'file']
        }
    }