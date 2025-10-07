#!/usr/bin/env python3
"""
KME (Key Management Entity) Simulator

Implements ETSI GS QKD 014 compliant REST API for quantum key distribution simulation
"""

import asyncio
import logging
import json
import secrets
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS
from dataclasses import dataclass, asdict
import base64

@dataclass
class QuantumKey:
    """Quantum key data structure"""
    key_id: str
    key_data: bytes
    length: int
    created_at: datetime
    expires_at: datetime
    sender_sae_id: str
    receiver_sae_id: str
    consumed: bool = False
    key_type: str = "symmetric"  # symmetric, otp, seed
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'key_id': self.key_id,
            'key_data': base64.b64encode(self.key_data).decode('utf-8'),
            'length': self.length,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'sender_sae_id': self.sender_sae_id,
            'receiver_sae_id': self.receiver_sae_id,
            'consumed': self.consumed,
            'key_type': self.key_type
        }

class KMESimulator:
    """Simulated Key Management Entity following ETSI GS QKD 014"""
    
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        CORS(self.app)  # Enable CORS for all routes
        
        # Key storage
        self.keys: Dict[str, QuantumKey] = {}
        self.sae_keys: Dict[str, List[str]] = {}  # SAE ID -> List of key IDs
        
        # Configuration
        self.max_key_lifetime = timedelta(hours=24)
        self.qkd_rate = 10000  # bits per second (simulated)
        self.max_key_size = 1024 * 1024  # 1MB max key size
        
        # Setup Flask routes
        self.setup_routes()
        
        # Thread for Flask app
        self.flask_thread = None
        self.running = False
        
        logging.info(f"KME Simulator initialized on {host}:{port}")
        
    def setup_routes(self):
        """Setup ETSI GS QKD 014 REST API routes"""
        
        @self.app.route('/api/v1/status', methods=['GET'])
        def get_status():
            """Get KME status"""
            return jsonify({
                'status': 'active',
                'qkd_rate': self.qkd_rate,
                'active_keys': len(self.keys),
                'timestamp': datetime.utcnow().isoformat()
            })
            
        @self.app.route('/api/v1/keys/<sae_id>/status', methods=['GET'])
        def get_sae_status(sae_id):
            """Get status for specific SAE"""
            sae_keys = self.sae_keys.get(sae_id, [])
            available_keys = sum(1 for key_id in sae_keys 
                               if not self.keys[key_id].consumed)
            
            return jsonify({
                'sae_id': sae_id,
                'status': 'active',
                'available_keys': available_keys,
                'total_keys': len(sae_keys),
                'qkd_link_status': 'connected'
            })
            
        @self.app.route('/api/v1/keys/<receiver_sae_id>/enc_keys', methods=['POST'])
        def request_encryption_keys(receiver_sae_id):
            """Request encryption keys (Master SAE -> Slave SAE)"""
            try:
                data = request.get_json()
                sender_sae_id = data.get('sender_sae_id', 'default_sender')
                key_length = data.get('key_length', 256)  # bits
                key_count = data.get('key_count', 1)
                key_type = data.get('key_type', 'seed')  # seed, otp, symmetric
                
                # Validate request
                if key_length > self.max_key_size * 8:  # Convert to bits
                    return jsonify({'error': 'Key length exceeds maximum'}), 400
                    
                # Generate quantum keys
                generated_keys = []
                for _ in range(key_count):
                    key = self._generate_quantum_key(
                        sender_sae_id, receiver_sae_id, key_length, key_type
                    )
                    generated_keys.append(key)
                    
                # Store keys
                for key in generated_keys:
                    self.keys[key.key_id] = key
                    
                    # Add to sender's key list
                    if sender_sae_id not in self.sae_keys:
                        self.sae_keys[sender_sae_id] = []
                    self.sae_keys[sender_sae_id].append(key.key_id)
                    
                    # Add to receiver's key list
                    if receiver_sae_id not in self.sae_keys:
                        self.sae_keys[receiver_sae_id] = []
                    self.sae_keys[receiver_sae_id].append(key.key_id)
                    
                # Return key metadata (not actual keys)
                response = {
                    'status': 'success',
                    'key_count': len(generated_keys),
                    'keys': [{
                        'key_id': key.key_id,
                        'length': key.length,
                        'key_type': key.key_type,
                        'expires_at': key.expires_at.isoformat()
                    } for key in generated_keys]
                }
                
                logging.info(f"Generated {key_count} {key_type} keys for {sender_sae_id} -> {receiver_sae_id}")
                return jsonify(response)
                
            except Exception as e:
                logging.error(f"Error generating keys: {e}")
                return jsonify({'error': str(e)}), 500
                
        @self.app.route('/api/v1/keys/<sae_id>/<key_id>/dec_keys', methods=['GET'])
        def get_decryption_key(sae_id, key_id):
            """Get decryption key (Slave SAE request)"""
            try:
                # Check if key exists
                if key_id not in self.keys:
                    return jsonify({'error': 'Key not found'}), 404
                    
                key = self.keys[key_id]
                
                # Validate SAE access
                if key.receiver_sae_id != sae_id and key.sender_sae_id != sae_id:
                    return jsonify({'error': 'Access denied'}), 403
                    
                # Check if key is expired
                if datetime.utcnow() > key.expires_at:
                    return jsonify({'error': 'Key expired'}), 410
                    
                # Check if key is already consumed (for OTP)
                if key.consumed and key.key_type == 'otp':
                    return jsonify({'error': 'Key already consumed'}), 410
                    
                # Return the actual key data
                response = {
                    'key_id': key.key_id,
                    'key_data': base64.b64encode(key.key_data).decode('utf-8'),
                    'length': key.length,
                    'key_type': key.key_type,
                    'expires_at': key.expires_at.isoformat()
                }
                
                # Mark OTP keys as consumed
                if key.key_type == 'otp':
                    key.consumed = True
                    
                logging.info(f"Key {key_id} retrieved by {sae_id}")
                return jsonify(response)
                
            except Exception as e:
                logging.error(f"Error retrieving key: {e}")
                return jsonify({'error': str(e)}), 500
                
        @self.app.route('/api/v1/keys/<sae_id>/<key_id>', methods=['DELETE'])
        def consume_key(sae_id, key_id):
            """Mark key as consumed"""
            try:
                if key_id not in self.keys:
                    return jsonify({'error': 'Key not found'}), 404
                    
                key = self.keys[key_id]
                
                # Validate SAE access
                if key.receiver_sae_id != sae_id and key.sender_sae_id != sae_id:
                    return jsonify({'error': 'Access denied'}), 403
                    
                # Mark as consumed
                key.consumed = True
                
                return jsonify({'status': 'key consumed'})
                
            except Exception as e:
                logging.error(f"Error consuming key: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/v1/keys/<sae_id>/available', methods=['GET'])
        def get_available_keys(sae_id):
            """Get list of available keys for SAE"""
            try:
                sae_keys = self.sae_keys.get(sae_id, [])
                available_keys = []
                
                for key_id in sae_keys:
                    key = self.keys.get(key_id)
                    if key and not key.consumed and datetime.utcnow() <= key.expires_at:
                        available_keys.append({
                            'key_id': key.key_id,
                            'length': key.length,
                            'key_type': key.key_type,
                            'created_at': key.created_at.isoformat(),
                            'expires_at': key.expires_at.isoformat()
                        })
                        
                return jsonify({
                    'sae_id': sae_id,
                    'available_keys': available_keys,
                    'count': len(available_keys)
                })
                
            except Exception as e:
                logging.error(f"Error getting available keys: {e}")
                return jsonify({'error': str(e)}), 500
                
    def _generate_quantum_key(self, sender_sae_id: str, receiver_sae_id: str, 
                             length_bits: int, key_type: str) -> QuantumKey:
        """Generate a quantum key"""
        # Generate cryptographically secure random key data
        key_length_bytes = (length_bits + 7) // 8  # Convert to bytes, round up
        key_data = secrets.token_bytes(key_length_bytes)
        
        # Generate unique key ID
        key_id = f"QK_{secrets.token_hex(16)}"
        
        # Calculate expiration time
        expires_at = datetime.utcnow() + self.max_key_lifetime
        
        key = QuantumKey(
            key_id=key_id,
            key_data=key_data,
            length=length_bits,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            sender_sae_id=sender_sae_id,
            receiver_sae_id=receiver_sae_id,
            key_type=key_type
        )
        
        return key
        
    def cleanup_expired_keys(self):
        """Remove expired keys"""
        current_time = datetime.utcnow()
        expired_keys = []
        
        for key_id, key in self.keys.items():
            if current_time > key.expires_at:
                expired_keys.append(key_id)
                
        for key_id in expired_keys:
            del self.keys[key_id]
            
        if expired_keys:
            logging.info(f"Cleaned up {len(expired_keys)} expired keys")
            
    async def start(self):
        """Start the KME simulator"""
        if self.running:
            return
            
        self.running = True
        
        # Start Flask app in a separate thread
        self.flask_thread = threading.Thread(
            target=lambda: self.app.run(
                host=self.host, 
                port=self.port, 
                debug=False, 
                use_reloader=False
            )
        )
        self.flask_thread.daemon = True
        self.flask_thread.start()
        
        # Start cleanup task and store reference
        self.cleanup_task = asyncio.create_task(self._cleanup_task())
        
        logging.info(f"KME Simulator started on http://{self.host}:{self.port}")
        
    async def stop(self):
        """Stop the KME simulator"""
        self.running = False
        
        # Cancel cleanup task if it exists
        if hasattr(self, 'cleanup_task') and self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        logging.info("KME Simulator stopped")
        
    async def _cleanup_task(self):
        """Background task to cleanup expired keys"""
        try:
            while self.running:
                await asyncio.sleep(300)  # Run every 5 minutes
                self.cleanup_expired_keys()
        except asyncio.CancelledError:
            logging.debug("KME cleanup task cancelled")
            
    def get_stats(self) -> Dict:
        """Get simulator statistics"""
        active_keys = sum(1 for key in self.keys.values() 
                         if not key.consumed and datetime.utcnow() <= key.expires_at)
        
        return {
            'total_keys': len(self.keys),
            'active_keys': active_keys,
            'consumed_keys': sum(1 for key in self.keys.values() if key.consumed),
            'sae_count': len(self.sae_keys),
            'qkd_rate': self.qkd_rate,
            'uptime': 'simulated'
        }
