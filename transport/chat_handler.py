#!/usr/bin/env python3
"""
Chat Transport Handler - Real-time Messaging
Implements WebSocket-based chat with quantum encryption
"""

import asyncio
import logging
import json
import websockets
import ssl
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict

@dataclass
class ChatMessage:
    """Chat message data structure"""
    message_id: str
    sender_id: str
    receiver_id: str
    content: str
    timestamp: datetime
    security_level: str
    key_id: Optional[str] = None
    message_type: str = 'text'  # text, image, file, call_invite
    encrypted_payload: Optional[Dict] = None

@dataclass
class GroupChatMessage:
    """Group chat message data structure with Multi-SAE support"""
    message_id: str
    group_id: str
    sender_id: str
    recipient_ids: List[str]  # Multiple recipients
    content: str
    timestamp: datetime
    security_level: str
    group_key_envelope: Dict[str, str]  # recipient_sae_id -> encrypted_group_key
    message_type: str = 'group_text'
    encrypted_payload: Optional[Dict] = None
    sae_key_metadata: Optional[Dict] = None  # Multi-SAE key management info

class ChatHandler:
    """Real-time chat transport handler with WebSocket and quantum encryption"""
    
    def __init__(self):
        self.websocket = None
        self.is_connected = False
        self.user_id = None
        self.active_chats = {}
        self.message_handlers = []
        self.chat_server_url = "wss://qumail-chat.example.com/ws"  # Mock server
        
        # Connection settings
        self.reconnect_interval = 5  # seconds
        self.max_reconnect_attempts = 10
        self.reconnect_attempts = 0
        
        # Message queue for offline messages
        self.message_queue = asyncio.Queue()
        
        # PRODUCTION: Background task references for proper cleanup
        self.listener_task = None
        self.heartbeat_task = None
        self.queue_processor_task = None
        
        logging.info("Chat Handler initialized")
        
    async def initialize(self, user_profile=None):
        """Initialize chat handler"""
        try:
            # Create SSL context for secure WebSocket connections
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE  # For development
            
            logging.info("Chat handler SSL context initialized")
            
        except Exception as e:
            logging.error(f"Failed to initialize chat handler: {e}")
            raise
            
    async def connect(self, user_id: str, access_token: str) -> bool:
        """Connect to chat server with authentication"""
        try:
            self.user_id = user_id
            
            # In real implementation, this would:
            # 1. Establish WebSocket connection to chat server
            # 2. Send authentication message with JWT/OAuth token
            # 3. Handle server response and maintain connection
            # 4. Set up message listening loop
            
            # For simulation, just mark as connected
            logging.info(f"Chat: Connecting user {user_id} to {self.chat_server_url}")
            await asyncio.sleep(0.3)  # Simulate connection delay
            
            self.is_connected = True
            self.reconnect_attempts = 0
            
            # PRODUCTION: Start background tasks and store references for cleanup
            self.listener_task = asyncio.create_task(self._message_listener())
            self.heartbeat_task = asyncio.create_task(self._heartbeat_task())
            self.queue_processor_task = asyncio.create_task(self._process_message_queue())
            
            logging.info("Chat connection established successfully")
            return True
            
        except Exception as e:
            logging.error(f"Failed to connect to chat server: {e}")
            self.is_connected = False
            return False
            
    async def disconnect(self):
        """Disconnect from chat server"""
        try:
            if self.websocket:
                await self.websocket.close()
                
            self.is_connected = False
            self.websocket = None
            
            logging.info("Disconnected from chat server")
            
        except Exception as e:
            logging.error(f"Error disconnecting from chat server: {e}")
            
    async def send_message(self, contact_id: str, encrypted_data: Dict[str, Any]) -> bool:
        """Send encrypted chat message"""
        try:
            if not self.is_connected:
                logging.warning("Chat not connected, queuing message")
                await self.message_queue.put({
                    'action': 'send_message',
                    'contact_id': contact_id,
                    'encrypted_data': encrypted_data
                })
                return False
                
            # Create chat message
            message = ChatMessage(
                message_id=f"msg_{int(datetime.utcnow().timestamp() * 1000)}",
                sender_id=self.user_id,
                receiver_id=contact_id,
                content="[Encrypted Content]",
                timestamp=datetime.utcnow(),
                security_level=encrypted_data.get('security_level', 'L4'),
                key_id=encrypted_data.get('key_id'),
                encrypted_payload=encrypted_data
            )
            
            # In real implementation, this would send via WebSocket:
            # {
            #   "type": "message",
            #   "message": message.to_dict(),
            #   "signature": "digital_signature_here"
            # }
            
            # For simulation, just log the message
            logging.info(f"Chat: Sending {encrypted_data.get('security_level')} message to {contact_id}")
            logging.info(f"Chat: Message ID: {message.message_id}")
            logging.info(f"Chat: Key ID: {message.key_id}")
            
            # Simulate network delay
            await asyncio.sleep(0.2)
            
            # Add to active chat
            if contact_id not in self.active_chats:
                self.active_chats[contact_id] = []
            self.active_chats[contact_id].append(message)
            
            logging.info("Chat message sent successfully")
            return True
            
        except Exception as e:
            logging.error(f"Failed to send chat message: {e}")
            return False
            
    async def get_chat_history(self, contact_id: str, limit: int = 100) -> List[Dict]:
        """Get chat history with contact"""
        try:
            logging.info(f"Chat: Getting history with {contact_id} (limit: {limit})")
            
            # In real implementation:
            # 1. Query chat database/server for message history
            # 2. Decrypt messages using stored keys or KME
            # 3. Return sorted message list
            
            # For simulation, return mock chat history
            mock_messages = []
            
            # Add some existing messages if they exist
            if contact_id in self.active_chats:
                for msg in self.active_chats[contact_id][-limit:]:
                    mock_messages.append({
                        'message_id': msg.message_id,
                        'sender_id': msg.sender_id,
                        'receiver_id': msg.receiver_id,
                        'content': f"Message content for {msg.message_id}",
                        'timestamp': msg.timestamp.isoformat(),
                        'security_level': msg.security_level,
                        'is_sent': msg.sender_id == self.user_id,
                        'key_id': msg.key_id
                    })
                    
            # Add some mock history messages
            base_time = datetime.utcnow() - timedelta(hours=2)
            for i in range(min(5, limit - len(mock_messages))):
                is_sent = i % 2 == 0
                mock_messages.insert(0, {
                    'message_id': f'history_{i}',
                    'sender_id': self.user_id if is_sent else contact_id,
                    'receiver_id': contact_id if is_sent else self.user_id,
                    'content': f"Historical message {i+1} - quantum encrypted",
                    'timestamp': (base_time + timedelta(minutes=i*10)).isoformat(),
                    'security_level': ['L2', 'L1', 'L3'][i % 3],
                    'is_sent': is_sent,
                    'key_id': f'QK_hist_{i}' if i % 2 == 0 else None
                })
                
            logging.info(f"Retrieved {len(mock_messages)} chat messages")
            return mock_messages
            
        except Exception as e:
            logging.error(f"Failed to get chat history: {e}")
            return []
            
    async def get_contact_list(self) -> List[Dict]:
        """Get list of chat contacts"""
        try:
            logging.info("Chat: Getting contact list")
            
            # Mock contact list
            mock_contacts = [
                {
                    'contact_id': 'alice_smith',
                    'name': 'Alice Smith',
                    'status': 'online',
                    'last_seen': datetime.utcnow().isoformat(),
                    'qkd_status': 'connected',
                    'avatar_url': None,
                    'public_key': 'mock_public_key_alice'
                },
                {
                    'contact_id': 'bob_johnson',
                    'name': 'Bob Johnson',
                    'status': 'offline',
                    'last_seen': (datetime.utcnow() - timedelta(minutes=30)).isoformat(),
                    'qkd_status': 'connected',
                    'avatar_url': None,
                    'public_key': 'mock_public_key_bob'
                },
                {
                    'contact_id': 'charlie_brown',
                    'name': 'Charlie Brown',
                    'status': 'away',
                    'last_seen': (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                    'qkd_status': 'disconnected',
                    'avatar_url': None,
                    'public_key': None
                }
            ]
            
            logging.info(f"Retrieved {len(mock_contacts)} contacts")
            return mock_contacts
            
        except Exception as e:
            logging.error(f"Failed to get contact list: {e}")
            return []
            
    # ========== GROUP CHAT Multi-SAE Keying Implementation ==========
    
    async def create_group_chat(self, group_name: str, participant_ids: List[str]) -> str:
        """Create a new group chat with Multi-SAE key management"""
        try:
            import uuid
            group_id = f"group_{uuid.uuid4().hex[:8]}"
            
            # Add sender to participants
            all_participants = [self.user_id] + participant_ids
            
            logging.info(f"Creating group chat '{group_name}' with {len(all_participants)} participants")
            logging.info(f"Participants: {all_participants}")
            
            # Initialize group in active chats
            self.active_chats[group_id] = {
                'type': 'group',
                'group_name': group_name,
                'participants': all_participants,
                'created_at': datetime.utcnow(),
                'created_by': self.user_id,
                'sae_key_envelope': {}  # Will store per-participant encrypted keys
            }
            
            # In real implementation, this would register the group on the chat server
            logging.info(f"Group chat created: {group_id}")
            return group_id
            
        except Exception as e:
            logging.error(f"Failed to create group chat: {e}")
            raise
            
    async def send_group_message(self, group_id: str, encrypted_payload: Dict, 
                                 recipient_ids: List[str], sae_key_metadata: List[Dict]) -> bool:
        """
        Send encrypted message to group using Multi-SAE keying
        
        Accepts the full, encrypted payload and key envelope from the QuMailCore.
        """
        try:
            if group_id not in self.active_chats:
                raise ValueError(f"Group {group_id} not found")
                
            _group_info = self.active_chats[group_id]  # Retrieved for validation
            
            # Create the final GroupChatMessage object
            import uuid
            message_id = f"group_msg_{uuid.uuid4().hex[:8]}"
            
            group_message = GroupChatMessage(
                message_id=message_id,
                group_id=group_id,
                sender_id=self.user_id,
                recipient_ids=recipient_ids,
                content="[Quantum Secure Group Message]",  # Placeholder, content is in encrypted_payload
                timestamp=datetime.utcnow(),
                security_level=encrypted_payload.get('security_level', 'L2'),
                group_key_envelope=encrypted_payload.get('group_key_envelope', {}),
                sae_key_metadata=sae_key_metadata,
                encrypted_payload=encrypted_payload
            )
            
            # --- SIMULATION: Sending via WebSocket ---
            # In real implementation, this would format and send the JSON via WebSocket:
            # await self.websocket.send(json.dumps(asdict(group_message)))
            
            # For simulation, update the active chat list
            if group_id not in self.active_chats:
                self.active_chats[group_id] = []
            if isinstance(self.active_chats[group_id], dict):
                # Assuming dictionary structure for group metadata
                self.active_chats[group_id]['messages'] = self.active_chats[group_id].get('messages', [])
                self.active_chats[group_id]['messages'].append(group_message)
            
            logging.info(f"Group message sent successfully: {message_id} to group {group_id} with {len(group_message.group_key_envelope)} keys")
            return True
            
        except Exception as e:
            logging.error(f"Failed to send group message: {e}")
            return False
            
    async def get_group_chat_history(self, group_id: str, limit: int = 50) -> List[Dict]:
        """Get group chat message history"""
        try:
            if group_id not in self.active_chats:
                return []
                
            group_info = self.active_chats[group_id]
            
            # Mock group chat history
            mock_messages = []
            base_time = datetime.utcnow() - timedelta(hours=1)
            
            participants = group_info['participants']
            
            for i in range(min(8, limit)):
                sender = participants[i % len(participants)]
                is_sent = sender == self.user_id
                
                mock_messages.append({
                    'message_id': f'group_msg_{i}',
                    'group_id': group_id,
                    'sender_id': sender,
                    'recipient_ids': [p for p in participants if p != sender],
                    'content': f"Group message {i+1} - Multi-SAE encrypted",
                    'timestamp': (base_time + timedelta(minutes=i*5)).isoformat(),
                    'security_level': ['L2', 'L3', 'L1'][i % 3],
                    'is_sent': is_sent,
                    'message_type': 'group_text',
                    'sae_key_metadata': {
                        'total_recipients': len(participants) - 1,
                        'key_generation_method': 'multi_sae_kme'
                    }
                })
                
            logging.info(f"Retrieved {len(mock_messages)} group messages for {group_id}")
            return mock_messages
            
        except Exception as e:
            logging.error(f"Failed to get group chat history: {e}")
            return []
            
    async def get_group_list(self) -> List[Dict]:
        """Get list of active group chats"""
        try:
            group_list = []
            
            for group_id, group_info in self.active_chats.items():
                if group_info.get('type') == 'group':
                    group_list.append({
                        'group_id': group_id,
                        'group_name': group_info['group_name'],
                        'participants': group_info['participants'],
                        'participant_count': len(group_info['participants']),
                        'created_at': group_info['created_at'].isoformat(),
                        'created_by': group_info['created_by'],
                        'last_activity': datetime.utcnow().isoformat(),
                        'multi_sae_enabled': True
                    })
                    
            # Add some mock groups for demonstration
            if not group_list:
                import uuid
                mock_group_id = f"group_{uuid.uuid4().hex[:8]}"
                self.active_chats[mock_group_id] = {
                    'type': 'group',
                    'group_name': 'Quantum Team',
                    'participants': [self.user_id, 'alice_smith', 'bob_johnson'],
                    'created_at': datetime.utcnow() - timedelta(hours=2),
                    'created_by': self.user_id
                }
                
                group_list.append({
                    'group_id': mock_group_id,
                    'group_name': 'Quantum Team',
                    'participants': [self.user_id, 'alice_smith', 'bob_johnson'],
                    'participant_count': 3,
                    'created_at': (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                    'created_by': self.user_id,
                    'last_activity': datetime.utcnow().isoformat(),
                    'multi_sae_enabled': True
                })
                
            logging.info(f"Retrieved {len(group_list)} group chats")
            return group_list
            
        except Exception as e:
            logging.error(f"Failed to get group list: {e}")
            return []
            
    def add_message_handler(self, handler: Callable[[Dict], None]):
        """Add a message handler callback"""
        self.message_handlers.append(handler)
        
    def remove_message_handler(self, handler: Callable[[Dict], None]):
        """Remove a message handler callback"""
        if handler in self.message_handlers:
            self.message_handlers.remove(handler)
            
    async def _message_listener(self):
        """Background task to listen for incoming messages"""
        while self.is_connected:
            try:
                # In real implementation, this would:
                # 1. Listen for WebSocket messages
                # 2. Parse and validate incoming messages
                # 3. Decrypt message content using KME keys
                # 4. Call registered message handlers
                
                # For simulation, generate some mock incoming messages
                await asyncio.sleep(30)  # Check every 30 seconds
                
                if self.is_connected and self.active_chats:
                    # Simulate receiving a message
                    contact_ids = list(self.active_chats.keys())
                    if contact_ids:
                        contact_id = contact_ids[0]  # Use first contact
                        
                        mock_message = {
                            'message_id': f"incoming_{int(datetime.utcnow().timestamp())}",
                            'sender_id': contact_id,
                            'receiver_id': self.user_id,
                            'content': "This is a simulated incoming message",
                            'timestamp': datetime.utcnow().isoformat(),
                            'security_level': 'L2',
                            'is_sent': False
                        }
                        
                        # Notify handlers
                        for handler in self.message_handlers:
                            try:
                                handler(mock_message)
                            except Exception as e:
                                logging.error(f"Message handler error: {e}")
                                
            except Exception as e:
                logging.error(f"Message listener error: {e}")
                await asyncio.sleep(5)
                
    async def _heartbeat_task(self):
        """Background task to maintain connection with heartbeat"""
        while self.is_connected:
            try:
                # In real implementation, send WebSocket ping/pong
                # await websocket.ping()
                
                logging.debug("Chat: Heartbeat sent")
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
                
            except Exception as e:
                logging.error(f"Heartbeat error: {e}")
                # Try to reconnect
                await self._attempt_reconnect()
                
    async def _process_message_queue(self):
        """Process queued messages when connection is restored"""
        while True:
            try:
                if self.is_connected and not self.message_queue.empty():
                    queued_message = await self.message_queue.get()
                    
                    if queued_message['action'] == 'send_message':
                        await self.send_message(
                            queued_message['contact_id'],
                            queued_message['encrypted_data']
                        )
                        
                await asyncio.sleep(1)  # Check queue every second
                
            except Exception as e:
                logging.error(f"Message queue processing error: {e}")
                await asyncio.sleep(5)
                
    async def _attempt_reconnect(self):
        """Attempt to reconnect to chat server"""
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            logging.error("Max reconnection attempts reached")
            self.is_connected = False
            return
            
        self.reconnect_attempts += 1
        logging.info(f"Attempting to reconnect ({self.reconnect_attempts}/{self.max_reconnect_attempts})")
        
        try:
            # Attempt reconnection
            await asyncio.sleep(self.reconnect_interval)
            # In real implementation, re-establish WebSocket connection
            
            self.is_connected = True
            self.reconnect_attempts = 0
            logging.info("Reconnection successful")
            
        except Exception as e:
            logging.error(f"Reconnection failed: {e}")
            
    async def cleanup(self):
        """PRODUCTION: Comprehensive cleanup with background task cancellation"""
        try:
            # CRITICAL: Cancel background tasks to prevent runtime warnings/crashes
            if self.listener_task and not self.listener_task.done():
                self.listener_task.cancel()
                try:
                    await self.listener_task
                except asyncio.CancelledError:
                    logging.info("PRODUCTION: Message listener task cancelled successfully")
                    
            if self.heartbeat_task and not self.heartbeat_task.done():
                self.heartbeat_task.cancel()
                try:
                    await self.heartbeat_task
                except asyncio.CancelledError:
                    logging.info("PRODUCTION: Heartbeat task cancelled successfully")
                    
            if self.queue_processor_task and not self.queue_processor_task.done():
                self.queue_processor_task.cancel()
                try:
                    await self.queue_processor_task
                except asyncio.CancelledError:
                    logging.info("PRODUCTION: Queue processor task cancelled successfully")
            
            await self.disconnect()
            
            # Clear message queue
            while not self.message_queue.empty():
                await self.message_queue.get()
                
            self.active_chats.clear()
            self.message_handlers.clear()
            
            # Reset task references
            self.listener_task = None
            self.heartbeat_task = None
            self.queue_processor_task = None
            
            logging.info("PRODUCTION: Chat handler cleanup completed with background task cancellation")
            
        except Exception as e:
            logging.error(f"Error during chat handler cleanup: {e}")