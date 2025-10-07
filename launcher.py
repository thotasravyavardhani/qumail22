#!/usr/bin/env python3
"""
Application Launcher Script for QuMail

This script can be used to launch QuMail from the command line
with various options and environment setup.
"""

import sys
import os
import argparse
from pathlib import Path

# Add the qumail package to Python path
sys.path.insert(0, str(Path(__file__).parent))

def setup_environment():
    """Setup environment variables for QuMail"""
    # Set default environment variables if not already set
    env_defaults = {
        'QUMAIL_LOG_LEVEL': 'INFO',
        'QUMAIL_DEBUG': 'false',
        'QUMAIL_KME_URL': 'http://127.0.0.1:8080',
        'QUMAIL_DEFAULT_SECURITY': 'L2',
        'QUMAIL_THEME': 'light'
    }
    
    for key, value in env_defaults.items():
        if key not in os.environ:
            os.environ[key] = value

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='QuMail - Quantum Secure Email Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python launcher.py                    # Launch with default settings
  python launcher.py --debug            # Launch in debug mode
  python launcher.py --kme-url localhost:8081  # Use different KME
  python launcher.py --security L1      # Default to OTP security
  python launcher.py --theme dark       # Use dark theme
        """
    )
    
    parser.add_argument(
        '--debug', 
        action='store_true',
        help='Enable debug mode with verbose logging'
    )
    
    parser.add_argument(
        '--kme-url',
        type=str,
        help='KME (Key Management Entity) URL (default: http://127.0.0.1:8080)'
    )
    
    parser.add_argument(
        '--security',
        choices=['L1', 'L2', 'L3', 'L4'],
        help='Default security level (L1=OTP, L2=Q-AES, L3=PQC, L4=TLS)'
    )
    
    parser.add_argument(
        '--theme',
        choices=['light', 'dark'],
        help='UI theme (light or dark)'
    )
    
    parser.add_argument(
        '--window-size',
        type=str,
        help='Window size in format WIDTHxHEIGHT (e.g., 1440x900)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level'
    )
    
    parser.add_argument(
        '--simulate-kme',
        action='store_true',
        help='Start built-in KME simulator (for testing)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='QuMail 1.0.0 - Quantum Secure Email Client'
    )
    
    return parser.parse_args()

def apply_arguments(args):
    """Apply command line arguments to environment"""
    if args.debug:
        os.environ['QUMAIL_DEBUG'] = 'true'
        os.environ['QUMAIL_LOG_LEVEL'] = 'DEBUG'
    
    if args.kme_url:
        # Handle different URL formats
        kme_url = args.kme_url
        if not kme_url.startswith(('http://', 'https://')):
            kme_url = f'http://{kme_url}'
        os.environ['QUMAIL_KME_URL'] = kme_url
    
    if args.security:
        os.environ['QUMAIL_DEFAULT_SECURITY'] = args.security
    
    if args.theme:
        os.environ['QUMAIL_THEME'] = args.theme
    
    if args.log_level:
        os.environ['QUMAIL_LOG_LEVEL'] = args.log_level
    
    if args.window_size:
        try:
            width, height = args.window_size.split('x')
            os.environ['QUMAIL_WINDOW_WIDTH'] = width
            os.environ['QUMAIL_WINDOW_HEIGHT'] = height
        except ValueError:
            print(f"Warning: Invalid window size format: {args.window_size}")
            print("Expected format: WIDTHxHEIGHT (e.g., 1440x900)")

def check_dependencies():
    """Check if required dependencies are installed"""
    missing_deps = []
    
    try:
        import PyQt6
    except ImportError:
        missing_deps.append('PyQt6')
    
    try:
        import cryptography
    except ImportError:
        missing_deps.append('cryptography')
    
    try:
        import requests
    except ImportError:
        missing_deps.append('requests')
    
    try:
        import flask
    except ImportError:
        missing_deps.append('flask')
    
    if missing_deps:
        print("Error: Missing required dependencies:")
        for dep in missing_deps:
            print(f"  - {dep}")
        print("\nPlease install dependencies:")
        print(f"  pip install {' '.join(missing_deps)}")
        print("\nOr install all requirements:")
        print("  pip install -r qumail_requirements.txt")
        return False
    
    return True

def start_kme_simulator():
    """Start the KME simulator in background"""
    print("Starting KME Simulator...")
    try:
        from crypto.kme_simulator import KMESimulator
        import asyncio
        import threading
        
        def run_kme():
            kme = KMESimulator()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(kme.start())
            
        kme_thread = threading.Thread(target=run_kme, daemon=True)
        kme_thread.start()
        
        print("KME Simulator started on http://127.0.0.1:8080")
        
    except Exception as e:
        print(f"Warning: Could not start KME simulator: {e}")
        print("You may need to start it manually or use an external KME.")

def main():
    """Main launcher function"""
    print("QuMail - Quantum Secure Email Client")
    print("ISRO Quantum Communications Project")
    print("-" * 50)
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    apply_arguments(args)
    
    # Start KME simulator if requested
    if args.simulate_kme:
        start_kme_simulator()
        import time
        time.sleep(2)  # Give KME time to start
    
    # Print configuration
    print(f"KME URL: {os.environ.get('QUMAIL_KME_URL')}")
    print(f"Security Level: {os.environ.get('QUMAIL_DEFAULT_SECURITY')}")
    print(f"Theme: {os.environ.get('QUMAIL_THEME')}")
    print(f"Debug: {os.environ.get('QUMAIL_DEBUG')}")
    print(f"Log Level: {os.environ.get('QUMAIL_LOG_LEVEL')}")
    print("-" * 50)
    
    try:
        # Import and run QuMail
        from .main import main as qumail_main
        qumail_main()
    except KeyboardInterrupt:
        print("\nQuMail shutdown requested by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting QuMail: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
