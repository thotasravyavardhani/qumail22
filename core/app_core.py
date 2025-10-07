#!/usr/bin/env python3
"""
QuMail Application Core

Central orchestrator for all QuMail functionality including:
- Security policy management
- KME client integration
- Email and chat workflow coordination
- OAuth2 authentication
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import os
import aiofiles.os 
# START OF CRITICAL IMPORT FIXES (Adding '..')
from crypto.kme_client import KMEClient
from crypto.cipher_strategies import CipherManager
from transport.email_handler import EmailHandler
from transport.chat_handler import ChatHandler
from auth.identity_manager import IdentityManager
from db.secure_storage import SecureStorage
# END OF CRITICAL IMPORT FIXES

@dataclass
class UserProfile:
    """User profile information"""
    user_id: str
    email: str
    display_name: str
    password_hash: str  # Added for realism and security
    sae_id: str  # Secure Application Entity ID for KME
    provider: str  # email provider
    created_at: datetime
    last_login: datetime

class QuMailCore:
    """Core application logic and workflow manager"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.current_user: Optional[UserProfile] = None
        self.current_security_level = "L2"  # Default to Quantum-aided AES
        
        # Initialize components with enhanced error handling
        try:
            self.kme_client = KMEClient(config.get('kme_url', 'http://127.0.0.1:8080'))
            self.cipher_manager = CipherManager()
            self.email_handler = EmailHandler()
            self.chat_handler = ChatHandler()
            self.secure_storage = SecureStorage()
            
            # ISRO-GRADE: Initialize OAuth2Manager for production token management
            from auth.oauth2_manager import OAuth2Manager # CRITICAL FIX: Absolute import
            self.oauth_manager = OAuth2Manager()
            
            # FIXED: Initialize IdentityManager with OAuth2Manager dependency injection
            self.identity_manager = IdentityManager(self.secure_storage, self.oauth_manager)
        except Exception as e:
            logging.error(f"Error initializing core components: {e}")
            raise
        
        # State tracking
        self.qkd_status = "disconnected"
        self.active_connections = {}
        self.message_queue = asyncio.Queue()
        
        # PQC FILE FEATURE: Track file encryption statistics
        self.pqc_stats = {
            'files_encrypted': 0,
            'total_size_encrypted': 0,
            'fek_operations': 0,
            'kyber_encapsulations': 0
        }
        
        logging.info("QuMail Core initialized with PQC file support")
        
    def _user_profile_to_dict(self, user_profile: UserProfile) -> Dict:
        """Convert UserProfile to dictionary for storage - PRODUCTION READY: Includes password_hash"""
        return {
            'user_id': user_profile.user_id,
            'email': user_profile.email,
            'display_name': user_profile.display_name,
            'password_hash': user_profile.password_hash,  # CRITICAL: Ensures password_hash is saved for persistence
            'sae_id': user_profile.sae_id,
            'provider': user_profile.provider,
            'created_at': user_profile.created_at.isoformat(),
            'last_login': user_profile.last_login.isoformat()  # FIXED: Changed 'updated_at' to 'last_login'
        }
        
    async def initialize(self):
        """Initialize all core components with KME robustness"""
        try:
            # Initialize secure storage
            await self.secure_storage.initialize()
            
            # KME ROBUSTNESS: Enhanced KME connection with heartbeat
            await self.initialize_kme_with_robustness()
            
            # Load saved user profile if available
            await self.load_user_profile()
            
            # Initialize transport handlers
            if self.current_user:
                await self.email_handler.initialize(self.current_user)
                await self.chat_handler.initialize(self.current_user)
            
            logging.info("QuMail Core initialization complete with KME robustness")
            
        except Exception as e:
            logging.error(f"Failed to initialize QuMail Core: {e}")
            # Continue operation even if KME fails
            self.qkd_status = "error"
            
    async def initialize_kme_with_robustness(self):
        """KME ROBUSTNESS: Initialize KME with enhanced error handling and heartbeat"""
        try:
            # Initialize KME client with heartbeat monitoring enabled
            await self.kme_client.initialize(enable_heartbeat=True)
            
            if self.kme_client.is_connected:
                self.qkd_status = "connected"
                logging.info("KME connection established with heartbeat monitoring")
                
                # Perform initial health check
                health_status = await self.kme_client.health_check()
                logging.info(f"KME health status: {health_status.get('overall_status', 'unknown')}")
            else:
                self.qkd_status = "degraded"
                logging.warning("KME connection failed - operating in degraded mode")
                
        except Exception as e:
            self.qkd_status = "error"
            logging.error(f"KME initialization failed: {e}")
            # Application continues to function without KME
            
    async def authenticate_user(self, provider: str = "qumail_native") -> bool:
        """Authenticate user with IdentityManager for persistent login."""
        try:
            # Show the Identity Dialog
            auth_result = await self.identity_manager.authenticate(provider)
            
            if auth_result:
                # Create user profile from the established identity
                self.current_user = UserProfile(
                    user_id=auth_result['user_id'],
                    email=auth_result['email'],
                    display_name=auth_result['name'],
                    password_hash=auth_result.get('password_hash', ''),
                    sae_id=f"qumail_{auth_result['user_id']}",
                    provider=provider,
                    created_at=datetime.fromisoformat(auth_result.get('authenticated_at', datetime.utcnow().isoformat())),
                    last_login=datetime.utcnow()
                )
                
                # Save profile and credentials securely
                profile_dict = self._user_profile_to_dict(self.current_user)
                await self.secure_storage.save_user_profile(profile_dict)
                await self.secure_storage.save_oauth_credentials(
                    provider, 
                    self.current_user.user_id, 
                    self.current_user.email,
                    auth_result
                )
                
                # ISRO-GRADE: Initialize transport handlers with OAuth2Manager injection
                await self.email_handler.initialize(self.current_user)
                self.email_handler.user_id = self.current_user.user_id  # CRITICAL: Set user_id for OAuth token refresh
                
                # Set up OAuth2 credentials in email handler if available
                if auth_result.get('access_token'):
                    await self.email_handler.set_credentials(
                        auth_result.get('access_token', ''),
                        auth_result.get('refresh_token', ''),
                        provider,
                        self.oauth_manager  # CRITICAL: OAuth2Manager injection
                    )
                
                await self.chat_handler.initialize(self.current_user)
                
                logging.info(f"User authenticated: {self.current_user.email}")
                return True
                
        except Exception as e:
            logging.error(f"Authentication failed: {e}")
            return False
            
    async def load_user_profile(self):
        """Load saved user profile and restore IdentityManager state"""
        try:
            profile_data = await self.secure_storage.load_user_profile()
            if profile_data:
                # Ensure datetime fields are converted correctly for dataclass
                profile_data['created_at'] = datetime.fromisoformat(profile_data['created_at'])
                profile_data['last_login'] = datetime.fromisoformat(profile_data['last_login'])
                
                # Ensure password_hash field exists for backward compatibility
                if 'password_hash' not in profile_data:
                    profile_data['password_hash'] = ''
                
                self.current_user = UserProfile(**profile_data)
                
                # FIXED: Restore IdentityManager state with loaded user
                if self.identity_manager:
                    await self.identity_manager.initialize()
                    # Restore current user state in IdentityManager
                    from auth.identity_manager import UserIdentity
                    restored_identity = UserIdentity(
                        user_id=self.current_user.user_id,
                        email=self.current_user.email,
                        display_name=self.current_user.display_name,
                        password_hash=self.current_user.password_hash,
                        sae_id=self.current_user.sae_id,
                        created_at=self.current_user.created_at,
                        last_login=self.current_user.last_login
                    )
                    self.identity_manager.current_user = restored_identity
                
                # ISRO-GRADE: Load credentials and inject OAuth2Manager for transport handler
                credentials = await self.secure_storage.load_oauth_credentials(
                    self.current_user.provider, self.current_user.user_id
                )
                if credentials and hasattr(self.email_handler, 'set_credentials'):
                    # Inject OAuth2Manager for production token refresh capability
                    await self.email_handler.set_credentials(
                        credentials.get('access_token'),
                        credentials.get('refresh_token'),
                        credentials.get('provider'),
                        self.oauth_manager  # CRITICAL: OAuth2Manager dependency injection
                    )
                    # CRITICAL: Set user_id for OAuth2Manager token refresh capabilities
                    self.email_handler.user_id = self.current_user.user_id
                logging.info(f"User profile loaded and IdentityManager restored: {self.current_user.email}")
        except Exception as e:
            logging.warning(f"Could not load user profile: {e}")
            
    async def create_user_programmatically(self, email: str, display_name: str, password: str = "test123", provider: str = "qumail_native") -> bool:
        """
        Programmatically create and authenticate a user (for testing without GUI)
        This bypasses the GUI dialog for automated testing scenarios
        """
        try:
            import hashlib
            
            # Generate user ID from email
            user_id = hashlib.md5(email.encode()).hexdigest()[:16]
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Create user profile
            self.current_user = UserProfile(
                user_id=user_id,
                email=email,
                display_name=display_name,
                password_hash=password_hash,
                sae_id=f"qumail_{user_id}",
                provider=provider,
                created_at=datetime.utcnow(),
                last_login=datetime.utcnow()
            )
            
            # Save profile securely
            profile_dict = self._user_profile_to_dict(self.current_user)
            await self.secure_storage.save_user_profile(profile_dict)
            
            # Initialize transport handlers
            await self.email_handler.initialize(self.current_user)
            # Set oauth_manager to prevent attribute errors
            self.email_handler.oauth_manager = self.oauth_manager
            self.email_handler.user_id = self.current_user.user_id
            
            await self.chat_handler.initialize(self.current_user)
            
            logging.info(f"Programmatically created and authenticated user: {email}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to create user programmatically: {e}")
            return False
    
    def set_security_level(self, level: str):
        """Set current security level"""
        if level in ['L1', 'L2', 'L3', 'L4']:
            self.current_security_level = level
            logging.info(f"Security level changed to: {level}")
        else:
            raise ValueError(f"Invalid security level: {level}")
            
    def get_security_level(self) -> str:
        """Get current security level"""
        return self.current_security_level
        
    async def send_secure_email(self, to_address: str, subject: str, 
                               body: str, attachments: List = None, 
                               security_level: str = None, 
                               file_context: Dict = None) -> bool:
        """PQC FEATURE: Send encrypted email with enhanced file attachment support"""
        try:
            if not self.current_user:
                raise ValueError("User not authenticated")
                
            # Use provided security level or current default
            level = security_level or self.current_security_level
            
            # PQC FILE FEATURE: Enhanced file attachment handling
            total_attachment_size = 0
            has_large_files = False
            processed_attachments = []
            
            if attachments and len(attachments) > 0:
                # Process both real files and mock files
                for attachment in attachments:
                    if isinstance(attachment, dict) and attachment.get('is_mock'):
                        # Handle mock file
                        total_attachment_size += attachment['size']
                        processed_attachments.append(attachment)
                        logging.info(f"Processing mock file: {attachment['name']} ({attachment['size'] / (1024*1024):.1f} MB)")
                    elif isinstance(attachment, str):
                        # ASYNC I/O ARCHITECTURE FIX: Use aiofiles.os.path.getsize and aiofiles.os.path.exists
                        if await aiofiles.os.path.exists(attachment): 
                            file_size = await aiofiles.os.path.getsize(attachment)
                            total_attachment_size += file_size
                            processed_attachments.append({
                                'name': os.path.basename(attachment),
                                'path': attachment,
                                'size': file_size,
                                'is_mock': False
                            })
                            logging.info(f"Processing real file: {attachment} ({file_size / (1024*1024):.1f} MB)")
                        else:
                            logging.warning(f"Skipping invalid attachment: {attachment}")
                    else:
                        logging.warning(f"Skipping invalid attachment: {attachment}")
                
                has_large_files = total_attachment_size > 10 * 1024 * 1024  # >10MB
                
                if has_large_files:
                    size_mb = total_attachment_size / (1024 * 1024)
                    logging.info(f"Large file attachments detected: {size_mb:.2f} MB")
                    
                    # Auto-upgrade to L3 for large files if not already set
                    if level not in ['L3'] and total_attachment_size > 20 * 1024 * 1024:  # >20MB
                        logging.info("Auto-upgrading to Level 3 (PQC) for very large files")
                        level = 'L3'
                        
                        # Update PQC statistics
                        self.pqc_stats['files_encrypted'] += len(processed_attachments)
                        self.pqc_stats['total_size_encrypted'] += total_attachment_size
                        self.pqc_stats['fek_operations'] += 1
                        self.pqc_stats['kyber_encapsulations'] += 1
            
            # Prepare message content with enhanced file context
            message_data = {
                'subject': subject,
                'body': body,
                'attachments': processed_attachments,
                'total_attachment_size': total_attachment_size,
                'has_large_files': has_large_files
            }
            
            # Convert to bytes for encryption
            message_bytes = self._serialize_message(message_data)
            
            # PQC FILE FEATURE: Create enhanced file context
            encryption_file_context = {
                'is_attachment': bool(processed_attachments),
                'total_size': total_attachment_size,
                'attachment_count': len(processed_attachments),
                'requires_fek': has_large_files and level == 'L3',
                'has_mock_files': any(att.get('is_mock', False) for att in processed_attachments),
                'file_list': [{
                    'name': att.get('name', 'unknown'),
                    'size': att.get('size', 0),
                    'is_mock': att.get('is_mock', False)
                } for att in processed_attachments]
            }
            
            # Check if we need quantum keys
            if level in ['L1', 'L2', 'L3']:
                # KME ROBUSTNESS: Check KME status before key request
                if not self.kme_client.is_connected:
                    logging.warning("KME not connected - attempting reconnection")
                    await self.initialize_kme_with_robustness()
                    
                    if not self.kme_client.is_connected:
                        logging.error("KME unavailable - cannot proceed with quantum encryption")
                        return False
                
                # Request quantum key from KME
                receiver_sae_id = f"qumail_{to_address.replace('@', '_').replace('.', '_')}"
                
                required_key_length = self.cipher_manager.get_required_key_length(
                    level, len(message_bytes)
                )
                
                # PQC FEATURE: For L3 with large files, request additional key material
                if level == 'L3' and has_large_files:
                    # Request additional quantum key material for Kyber KEM
                    required_key_length = max(required_key_length, 512)  # Enhanced for Kyber-1024
                    logging.info("Requesting enhanced quantum key material for PQC file encapsulation")
                
                # OTP Policy Enforcement - Check size limits
                if level == 'L1':
                    otp_limit_bits = 50 * 1024 * 8  # 50KB converted to bits
                    if required_key_length > otp_limit_bits:
                        logging.warning(f"Message too large for OTP ({required_key_length // 8} bytes > 50KB limit)")
                        raise ValueError(f"OTP encryption limited to 50KB. Message size: {required_key_length // 8} bytes. Please use L2 (Quantum-aided AES) or L3 (PQC) for larger messages.")
                    
                # Request key from KME with retry logic
                key_data = None
                for attempt in range(3):
                    try:
                        key_data = await self.kme_client.request_key(
                            sender_sae_id=self.current_user.sae_id,
                            receiver_sae_id=receiver_sae_id,
                            key_length=required_key_length,
                            key_type='otp' if level == 'L1' else 'seed'
                        )
                        if key_data:
                            break
                    except Exception as e:
                        logging.warning(f"Key request attempt {attempt + 1} failed: {e}")
                        if attempt < 2:
                            await asyncio.sleep(1)
                
                if not key_data:
                    logging.error("Failed to obtain quantum key after retries")
                    return False
                    
                # Encrypt message with file context
                encrypted_data = self.cipher_manager.encrypt_with_level(
                    message_bytes, key_data['key_data'], level, encryption_file_context
                )
                
                # Add key metadata
                encrypted_data['key_id'] = key_data['key_id']
                
                # PQC FEATURE: Add enhanced file encryption metadata
                if level == 'L3' and has_large_files:
                    encrypted_data['pqc_file_encryption'] = {
                        'total_size': total_attachment_size,
                        'attachment_count': len(processed_attachments),
                        'fek_used': True,
                        'kyber_kem': True,
                        'encryption_timestamp': datetime.utcnow().isoformat(),
                        'file_details': encryption_file_context['file_list'],
                        'has_mock_demonstration': encryption_file_context['has_mock_files']
                    }
                    
                    logging.info(f"PQC file encryption applied to {len(processed_attachments)} files")

            else:
                # Level 4 - no additional encryption
                encrypted_data = self.cipher_manager.encrypt_with_level(
                    message_bytes, b'', level, encryption_file_context
                )
                
            # Send via email handler
            result = await self.email_handler.send_encrypted_email(
                to_address, encrypted_data
            )
            
            if result:
                logging.info(f"Secure email sent successfully to {to_address} with {level} encryption")
                if level == 'L3' and has_large_files:
                    logging.info(f"PQC file encryption stats updated: {self.pqc_stats}")
                    
            return result
        
        except ValueError as e:
            # EDGE CASE FIX: Catch specific policy/validation errors (e.g., OTP size, Auth)
            logging.error(f"Policy/Validation Error during send: {e}")
            return False
           
        except Exception as e:
            # CRITICAL FIX: This will catch any remaining sync or async exceptions and give a traceback
            logging.critical(f"CRITICAL FAILURE: QuMail Core failed to send secure email. Error: {e}", exc_info=True)
            return False
            
    async def receive_secure_email(self, email_id: str) -> Optional[Dict]:
        """Receive and decrypt secure email with PQC file support"""
        try:
            if not self.current_user:
                raise ValueError("User not authenticated")
                
            # Fetch encrypted email
            encrypted_email = await self.email_handler.fetch_email(email_id, self.current_user.email)
            if not encrypted_email:
                return None
                
            # Extract encrypted data
            encrypted_data = encrypted_email['encrypted_payload']
            security_level = encrypted_data.get('security_level')
            
            if not security_level:
                logging.warning("No security level in encrypted email")
                return None
                
            # Get decryption key if needed
            key_data = b''
            if security_level in ['L1', 'L2', 'L3']:
                # KME ROBUSTNESS: Check KME connection before key retrieval
                if not self.kme_client.is_connected:
                    logging.warning("KME not connected during email decryption")
                    await self.initialize_kme_with_robustness()
                    
                    if not self.kme_client.is_connected:
                        logging.error("KME unavailable - cannot decrypt quantum-secured email")
                        return None
                
                key_id = encrypted_data.get('key_id')
                if not key_id:
                    logging.error("No key ID in encrypted email")
                    return None
                    
                # Request key from KME with retry
                key_response = None
                for attempt in range(3):
                    try:
                        key_response = await self.kme_client.get_key(
                            sae_id=self.current_user.sae_id,
                            key_id=key_id
                        )
                        if key_response:
                            break
                    except Exception as e:
                        logging.warning(f"Key retrieval attempt {attempt + 1} failed: {e}")
                        if attempt < 2:
                            await asyncio.sleep(0.5)
                
                if not key_response:
                    logging.error("Failed to obtain decryption key")
                    return None
                    
                key_data = key_response['key_data']
                
            # Decrypt message
            decrypted_bytes = self.cipher_manager.decrypt_with_level(
                encrypted_data, key_data
            )
            
            # Deserialize message
            message_data = self._deserialize_message(decrypted_bytes)
            
            # Add metadata with PQC info
            result_data = {
                'email_id': email_id,
                'security_level': security_level,
                'sender': encrypted_email['sender'],
                'received_at': encrypted_email['received_at'],
                'decrypted_at': datetime.utcnow().isoformat()
            }
            
            # Merge message data
            result_data.update(message_data)
            
            # PQC FEATURE: Add file encryption details if present
            if encrypted_data.get('pqc_file_encryption'):
                result_data['pqc_details'] = encrypted_data['pqc_file_encryption']
                logging.info(f"PQC encrypted email decrypted with file details: {encrypted_data['pqc_file_encryption']}")
            
            logging.info(f"Email decrypted successfully: {email_id}")
            return result_data
            
        except Exception as e:
            logging.error(f"Failed to decrypt email: {e}")
            return None
            
    async def send_secure_chat_message(self, contact_id: str, message: str, 
                                      security_level: str = None) -> bool:
        """Send encrypted chat message"""
        try:
            if not self.current_user:
                raise ValueError("User not authenticated")
                
            level = security_level or self.current_security_level
            message_bytes = message.encode('utf-8')
            
            # Get quantum key if needed
            key_data = b''
            key_id = None
            
            if level in ['L1', 'L2', 'L3']:
                # KME ROBUSTNESS: Check connection
                if not self.kme_client.is_connected:
                    await self.initialize_kme_with_robustness()
                    
                if not self.kme_client.is_connected:
                    logging.error("KME unavailable for chat encryption")
                    return False
                
                required_key_length = self.cipher_manager.get_required_key_length(
                    level, len(message_bytes)
                )
                
                key_response = await self.kme_client.request_key(
                    sender_sae_id=self.current_user.sae_id,
                    receiver_sae_id=f"qumail_{contact_id}",
                    key_length=required_key_length,
                    key_type='seed' if level != 'L1' else 'otp'
                )
                
                if not key_response:
                    logging.error("Failed to obtain chat encryption key")
                    return False
                    
                key_data = key_response['key_data']
                key_id = key_response['key_id']
                
            # Encrypt message
            encrypted_data = self.cipher_manager.encrypt_with_level(
                message_bytes, key_data, level
            )
            
            if key_id:
                encrypted_data['key_id'] = key_id
                
            # Send via chat handler
            return await self.chat_handler.send_message(
                contact_id, encrypted_data
            )
            
        except Exception as e:
            logging.error(f"Failed to send chat message: {e}")
            return False
            
    # ========== GROUP CHAT Multi-SAE Keying Implementation ==========
    
    async def create_group_chat(self, group_name: str, participant_emails: List[str]) -> Optional[str]:
        """Create group chat with Multi-SAE key management"""
        try:
            if not self.current_user:
                raise ValueError("User not authenticated")
                
            # Convert emails to SAE IDs
            participant_ids = []
            for email in participant_emails:
                sae_id = f"qumail_{email.replace('@', '_').replace('.', '_')}"
                participant_ids.append(sae_id)
                
            logging.info(f"Creating group '{group_name}' with Multi-SAE participants: {participant_emails}")
            
            # Create group chat via handler
            group_id = await self.chat_handler.create_group_chat(group_name, participant_ids)
            
            logging.info(f"Group chat created with Multi-SAE support: {group_id}")
            return group_id
            
        except Exception as e:
            logging.error(f"Failed to create group chat: {e}")
            return None
            
    async def send_secure_group_message(self, group_id: str, content: str, 
                                        recipient_ids: List[str], security_level: str = 'L2') -> bool:
        """
        GROUP CHAT FEATURE: Sends an encrypted message to a group using Multi-SAE Keying.
        The message content is encrypted once, and the content key is wrapped (encrypted)
        for each recipient using a unique quantum key from the KME (Multi-SAE envelope).
        """
        try:
            if not self.current_user:
                raise ValueError("User not authenticated")
            if not recipient_ids:
                raise ValueError("Recipient list cannot be empty for group chat")

            if security_level not in ['L2', 'L3']:
                logging.warning("Group chat requires L2 or L3 security. Defaulting to L2.")
                security_level = 'L2'

            # --- 1. Content Encryption (Single Operation) ---
            # Encrypt the message content once using a randomly generated Content Encryption Key (CEK).
            cek_data = self.cipher_manager.encrypt_group_content(content.encode('utf-8'))
            cek = cek_data['cek']
            encrypted_content_payload = cek_data['encrypted_payload']

            # --- 2. Multi-SAE Key Envelope Generation ---
            group_key_envelope = {}
            sae_key_metadata = []
            sender_sae_id = self.current_user.sae_id
            
            # CEK size to request KME key length (256 bits = 32 bytes)
            cek_length_bits = len(cek) * 8
            
            if not self.kme_client.is_connected:
                await self.initialize_kme_with_robustness()
                if not self.kme_client.is_connected:
                    logging.error("KME unavailable - cannot proceed with quantum encryption for group chat")
                    return False
            
            # Loop through all recipients to create the key envelope
            for contact_id in recipient_ids:
                recipient_sae_id = f"qumail_{contact_id}"
                
                # a. Request unique quantum key for recipient (with retry logic)
                key_response = None
                for attempt in range(3):
                    try:
                        key_response = await self.kme_client.request_key(
                            sender_sae_id=sender_sae_id,
                            receiver_sae_id=recipient_sae_id,
                            key_length=cek_length_bits,  # Request quantum key to wrap the CEK
                            key_type='seed'
                        )
                        if key_response:
                            break
                    except Exception as e:
                        logging.warning(f"Key request for {contact_id} attempt {attempt + 1} failed: {e}")
                        if attempt < 2:
                            await asyncio.sleep(1)

                if key_response:
                    # b. Wrap (Encrypt) the CEK using the unique quantum key (L2/L3)
                    wrapped_cek_payload = self.cipher_manager.wrap_key_with_level(
                        cek, key_response['key_data'], security_level
                    )
                    
                    # Store the wrapped CEK and its quantum key ID in the envelope
                    group_key_envelope[recipient_sae_id] = {
                        'wrapped_cek': wrapped_cek_payload['wrapped_key'],
                        'key_id': key_response['key_id'],
                        'security_level': security_level
                    }
                    sae_key_metadata.append({
                        'recipient_id': contact_id,
                        'key_id': key_response['key_id'],
                        'status': 'wrapped'
                    })
                else:
                    logging.error(f"Failed to obtain quantum key for recipient {contact_id}")

            if not group_key_envelope:
                logging.error("Failed to generate key envelope for any recipient.")
                return False

            # --- 3. Send Group Message via Chat Handler ---
            final_group_payload = {
                'encrypted_content_payload': encrypted_content_payload,
                'group_key_envelope': group_key_envelope,
                'sender_sae_id': sender_sae_id,
                'security_level': security_level,
                'content_encryption_algorithm': cek_data['algorithm'],
                'key_wrap_algorithm': security_level  # L2_QAES or L3_PQC
            }

            result = await self.chat_handler.send_group_message(
                group_id=group_id,
                encrypted_payload=final_group_payload,
                recipient_ids=recipient_ids,
                sae_key_metadata=sae_key_metadata
            )
            
            # Secure cleanup of the CEK in core
            self.cipher_manager.secure_zero(cek)

            if result:
                logging.info(f"Group message sent successfully to {len(recipient_ids)} recipients with Multi-SAE keying ({security_level})")
            return result
        except ValueError as e:
            # EDGE CASE FIX: Catch specific policy/validation errors (e.g., Empty Recipients)
            logging.error(f"Group Policy/Validation Error: {e}")
            return False
            
        except Exception as e:
            # Catch all other unexpected system/transport errors
            logging.error(f"System/Transport Failure: {e}")
            return False
            
    async def get_group_chat_list(self) -> List[Dict]:
        """Get list of group chats with Multi-SAE info"""
        try:
            return await self.chat_handler.get_group_list()
        except Exception as e:
            logging.error(f"Failed to get group chat list: {e}")
            return []
            
    async def get_group_chat_history(self, group_id: str, limit: int = 100) -> List[Dict]:
        """Get group chat history"""
        try:
            return await self.chat_handler.get_group_chat_history(group_id, limit)
        except Exception as e:
            logging.error(f"Failed to get group chat history: {e}")
            return []
            
    def _serialize_message(self, message_data: Dict) -> bytes:
        """Serialize message data to bytes"""
        import json
        return json.dumps(message_data, ensure_ascii=False).encode('utf-8')
        
    def _deserialize_message(self, message_bytes: bytes) -> Dict:
        """Deserialize message data from bytes"""
        import json
        return json.loads(message_bytes.decode('utf-8'))
        
    async def get_email_list(self, folder: str = "INBOX", limit: int = 50) -> List[Dict]:
        """Get list of emails from specified folder"""
        try:
            return await self.email_handler.get_email_list(folder, limit)
        except Exception as e:
            logging.error(f"Failed to get email list: {e}")
            return []
            
    async def get_chat_history(self, contact_id: str, limit: int = 100) -> List[Dict]:
        """Get chat history with contact"""
        try:
            return await self.chat_handler.get_chat_history(contact_id, limit)
        except Exception as e:
            logging.error(f"Failed to get chat history: {e}")
            return []
            
    def get_qkd_status(self) -> Dict:
        """Get current QKD status with KME robustness info"""
        kme_stats = self.kme_client.get_connection_statistics()
        
        return {
            'status': self.qkd_status,
            'security_level': self.current_security_level,
            'kme_connected': self.kme_client.is_connected,
            'available_levels': list(self.cipher_manager.strategies.keys()),
            'heartbeat_enabled': self.kme_client.heartbeat_enabled,
            'connection_failures': self.kme_client.connection_failures,
            'success_rate': kme_stats.get('success_rate', 0),
            'uptime_seconds': kme_stats.get('uptime_seconds', 0),
            'pqc_stats': self.pqc_stats
        }
        
    def get_pqc_statistics(self) -> Dict:
        """Get PQC file encryption statistics"""
        return {
            'files_encrypted': self.pqc_stats['files_encrypted'],
            'total_size_mb': self.pqc_stats['total_size_encrypted'] / (1024 * 1024),
            'fek_operations': self.pqc_stats['fek_operations'],
            'kyber_encapsulations': self.pqc_stats['kyber_encapsulations'],
            'average_file_size_mb': (
                self.pqc_stats['total_size_encrypted'] / (1024 * 1024) / max(1, self.pqc_stats['files_encrypted'])
            )
        }
        
    async def logout_user(self):
        """Clear current user session and perform cleanup with KME heartbeat stop"""
        if not self.current_user:
            logging.info("No user logged in to logout")
            return
            
        user_email = self.current_user.email
        logging.info(f"User {user_email} logging out. Stopping KME heartbeat and cleaning up.")
        
        # KME ROBUSTNESS: Stop heartbeat monitoring
        try:
            await self.kme_client.stop_heartbeat()
        except Exception as e:
            logging.warning(f"Error stopping KME heartbeat: {e}")
        
        # FIXED: Properly logout user from IdentityManager
        if self.identity_manager:
            try:
                await self.identity_manager.logout_user()
            except Exception as e:
                logging.warning(f"Error logging out from IdentityManager: {e}")
        
        # Clear user state
        self.current_user = None
        
        # Run all cleanup tasks
        await self.cleanup() 

        logging.info(f"QuMail session reset and core modules cleaned up for {user_email}.")
        return True
    
    async def cleanup(self):
        """Cleanup resources including KME client"""
        logging.info("Cleaning up QuMail Core")
        
        # KME ROBUSTNESS: Cleanup KME client
        try:
            if self.kme_client:
                await self.kme_client.close()
        except Exception as e:
            logging.warning(f"Error cleaning up KME client: {e}")
        
        # Cleanup handlers
        if self.email_handler:
            await self.email_handler.cleanup()
        if self.chat_handler:
            await self.chat_handler.cleanup()
            
        # Close storage
        if self.secure_storage:
            await self.secure_storage.close()