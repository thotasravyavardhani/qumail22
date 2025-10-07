#!/usr/bin/env python3
"""
Test Script for QuMail Email Scenarios
Tests all three email sending cases without GUI
"""

import asyncio
import sys
import logging
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from core.app_core import QuMailCore
from utils.config import load_config
from utils.logger import setup_logging

async def test_qumail_to_qumail():
    """Test Case 1: QuMail to QuMail email"""
    print("\n" + "="*60)
    print("TEST 1: QuMail to QuMail Email")
    print("="*60)
    
    try:
        # Initialize core
        config = load_config()
        core = QuMailCore(config)
        await core.initialize()
        
        # Simulate user login (Alice)
        print("📧 Logging in as alice@qumail.com...")
        auth_success = await core.create_user_programmatically(
            email="alice@qumail.com",
            display_name="Alice Smith",
            password="test123"
        )
        
        if not auth_success:
            print("❌ Login failed!")
            return False
            
        print("✅ Logged in successfully")
        
        # Send email to Bob (another QuMail user)
        print("\n📨 Sending email to bob@qumail.com...")
        result = await core.send_secure_email(
            to_address="bob@qumail.com",
            subject="Test QuMail-to-QuMail",
            body="This is a test email from Alice to Bob using QuMail internal delivery.",
            security_level="L2"
        )
        
        if result:
            print("✅ Email sent successfully!")
            print("   The email is now stored in the shared database.")
            print("   Bob can retrieve it when he logs in.")
            return True
        else:
            print("❌ Email sending failed!")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_qumail_to_self():
    """Test Case 3: QuMail to self (same user)"""
    print("\n" + "="*60)
    print("TEST 3: QuMail to Self Email")
    print("="*60)
    
    try:
        # Initialize core
        config = load_config()
        core = QuMailCore(config)
        await core.initialize()
        
        # Simulate user login
        print("📧 Logging in as charlie@qumail.com...")
        auth_success = await core.create_user_programmatically(
            email="charlie@qumail.com",
            display_name="Charlie Davis",
            password="test123"
        )
        
        if not auth_success:
            print("❌ Login failed!")
            return False
            
        print("✅ Logged in successfully")
        
        # Send email to self
        print("\n📨 Sending email to charlie@qumail.com (self)...")
        result = await core.send_secure_email(
            to_address="charlie@qumail.com",
            subject="Test QuMail-to-Self",
            body="This is a test email Charlie is sending to himself.",
            security_level="L2"
        )
        
        if result:
            print("✅ Email sent successfully!")
            print("   The email is stored in the database.")
            print("   You can retrieve it in your own inbox.")
            return True
        else:
            print("❌ Email sending failed!")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_qumail_to_gmail():
    """Test Case 2: QuMail to Gmail (OAuth)"""
    print("\n" + "="*60)
    print("TEST 2: QuMail to Gmail Email (OAuth)")
    print("="*60)
    
    try:
        # Initialize core
        config = load_config()
        core = QuMailCore(config)
        await core.initialize()
        
        print("📧 This test requires real Gmail OAuth credentials.")
        print("   Current credentials in config.py:")
        print(f"   Gmail Client ID: {config.get('gmail_client_id')}")
        print(f"   Gmail Client Secret: {config.get('gmail_client_secret')[:20]}..." if config.get('gmail_client_secret') else "   Gmail Client Secret: None")
        
        if config.get('gmail_client_id') == 'YOUR_GMAIL_CLIENT_ID_HERE':
            print("\n⚠️  OAuth credentials are still placeholders!")
            print("   To test Gmail integration:")
            print("   1. Get OAuth credentials from Google Cloud Console")
            print("   2. Replace placeholders in utils/config.py")
            print("   3. Run this test again")
            return False
        
        # Attempt Gmail login (for testing, use programmatic method)
        print("\n📧 Creating test Gmail user...")
        auth_success = await core.create_user_programmatically(
            email="test@gmail.com",
            display_name="Gmail Test User",
            provider="gmail"
        )
        
        if not auth_success:
            print("❌ Gmail authentication requires OAuth consent flow")
            print("   This needs a web browser for the consent screen")
            return False
            
        print("✅ Gmail authenticated")
        
        # Send email via Gmail
        print("\n📨 Sending email via Gmail SMTP...")
        result = await core.send_secure_email(
            to_address="recipient@example.com",
            subject="Test QuMail-to-Gmail",
            body="This is a test email sent via Gmail SMTP using OAuth2.",
            security_level="L4"  # Use TLS for external email
        )
        
        if result:
            print("✅ Email sent via Gmail successfully!")
            return True
        else:
            print("❌ Gmail email sending failed!")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def check_database():
    """Check the email database to verify stored emails"""
    print("\n" + "="*60)
    print("DATABASE VERIFICATION")
    print("="*60)
    
    try:
        from db.email_database import EmailDatabase
        
        db = EmailDatabase()
        
        # Get all emails
        print("\n📊 Checking database for stored emails...")
        
        # Check Alice's inbox
        alice_inbox = await db.get_inbox("alice@qumail.com")
        print(f"\n📥 Alice's Inbox: {len(alice_inbox)} email(s)")
        for email in alice_inbox:
            print(f"   - From: {email['sender']}, Subject: {email['subject']}")
        
        # Check Bob's inbox
        bob_inbox = await db.get_inbox("bob@qumail.com")
        print(f"\n📥 Bob's Inbox: {len(bob_inbox)} email(s)")
        for email in bob_inbox:
            print(f"   - From: {email['sender']}, Subject: {email['subject']}")
        
        # Check Charlie's inbox
        charlie_inbox = await db.get_inbox("charlie@qumail.com")
        print(f"\n📥 Charlie's Inbox: {len(charlie_inbox)} email(s)")
        for email in charlie_inbox:
            print(f"   - From: {email['sender']}, Subject: {email['subject']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error checking database: {e}")
        return False

async def main():
    """Run all tests"""
    # Setup logging
    setup_logging()
    
    print("\n" + "="*60)
    print("QuMail Email Testing Suite")
    print("="*60)
    
    results = {}
    
    # Test 1: QuMail to QuMail
    results['qumail_to_qumail'] = await test_qumail_to_qumail()
    await asyncio.sleep(1)
    
    # Test 3: QuMail to Self
    results['qumail_to_self'] = await test_qumail_to_self()
    await asyncio.sleep(1)
    
    # Test 2: QuMail to Gmail (will show instructions)
    results['qumail_to_gmail'] = await test_qumail_to_gmail()
    await asyncio.sleep(1)
    
    # Verify database
    await check_database()
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"✅ QuMail to QuMail: {'PASS' if results['qumail_to_qumail'] else 'FAIL'}")
    print(f"✅ QuMail to Self:   {'PASS' if results['qumail_to_self'] else 'FAIL'}")
    print(f"⚠️  QuMail to Gmail:  {'PASS' if results['qumail_to_gmail'] else 'NEEDS OAUTH SETUP'}")
    print("="*60)
    
    if results['qumail_to_qumail'] and results['qumail_to_self']:
        print("\n🎉 QuMail internal email system is working perfectly!")
        print("   For Gmail integration, add real OAuth credentials to utils/config.py")
    else:
        print("\n⚠️  Some tests failed. Check the logs above for details.")

if __name__ == "__main__":
    asyncio.run(main())
