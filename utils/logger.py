#!/usr/bin/env python3
"""
Logger Setup for QuMail
"""

import logging
import logging.config
import sys
from pathlib import Path
from .config import get_log_config

def setup_logging():
    """Setup application logging with proper configuration"""
    # Create logs directory
    log_dir = Path.home() / '.qumail' / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Get logging configuration
    log_config = get_log_config()
    
    # Ensure log file path exists
    log_file = log_dir / 'qumail.log'
    log_config['handlers']['file']['filename'] = str(log_file)
    
    try:
        # Apply logging configuration
        logging.config.dictConfig(log_config)
        
        # Create main logger
        logger = logging.getLogger('qumail')
        logger.info("QuMail logging system initialized")
        logger.info(f"Log file: {log_file}")
        
    except Exception as e:
        # Fallback to basic logging if configuration fails
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(log_file)
            ]
        )
        
        logger = logging.getLogger('qumail')
        logger.warning(f"Failed to configure logging with dict config: {e}")
        logger.info("Fallback logging configuration applied")
        
def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a specific module"""
    return logging.getLogger(f'qumail.{name}')
