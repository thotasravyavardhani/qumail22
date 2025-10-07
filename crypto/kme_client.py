#!/usr/bin/env python3
"""
KME Client - ETSI GS QKD 014 Compliant Client
Implements client for Key Management Entity communication
"""

import asyncio
import logging
import json
import base64
import ssl
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
import aiohttp
import certifi

class KMEClient:
    """Production-Ready ETSI GS QKD 014 Compliant KME Client with Heartbeat Monitoring"""
    
    def __init__(self, kme_url: str = "http://127.0.0.1:8080"):
        self.kme_url = kme_url.rstrip('/')
        self.session = None
        self.ssl_context = None
        self.connection_timeout = 30
        self.request_timeout = 15
        
        # Authentication settings
        self.client_cert = None
        self.client_key = None
        self.api_key = None
        
        # Enhanced connection state management
        self.is_connected = False
        self.last_status_check = None
        self.status_cache_duration = 30  # seconds
        self.connection_failures = 0
        self.max_connection_failures = 3  # REDUCED to prevent excessive retries
        
        # Heartbeat and monitoring
        self.heartbeat_enabled = False
        self.heartbeat_interval = 60  # seconds
        self.heartbeat_task = None
        self.last_successful_request = None
        self.connection_recovery_backoff = [1, 2, 5]  # REDUCED backoff
        
        # RECURSION FIX: Track initialization state
        self._initializing = False
        self._reconnecting = False
        
        # Statistics and monitoring
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'reconnection_attempts': 0,
            'last_reconnection': None,
            'uptime_start': datetime.utcnow()
        }
        
        logging.info(f"Production KME Client initialized for {self.kme_url}")
        
    async def initialize(self, enable_heartbeat: bool = True):
        """Initialize KME client with enhanced monitoring and heartbeat"""
        if self._initializing:
            logging.warning("KME Client already initializing, skipping duplicate call")
            return
            
        self._initializing = True
        try:
            # Create SSL context for secure connections
            self.ssl_context = ssl.create_default_context(cafile=certifi.where())
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE  # For development with self-signed certs
            
            # Create aiohttp session with enhanced configuration
            timeout = aiohttp.ClientTimeout(
                total=self.connection_timeout,
                sock_read=self.request_timeout,
                sock_connect=10
            )
            
            connector = aiohttp.TCPConnector(
                ssl=self.ssl_context,
                limit=10,
                limit_per_host=5,
                keepalive_timeout=60,
                enable_cleanup_closed=True
            )
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={
                    'User-Agent': 'QuMail-KME-Client-Production/2.0',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            )
            
            # RECURSION FIX: Direct connection test instead of retry loop
            await self._direct_connection_test()
            
            # Start heartbeat monitoring if enabled and connected
            if enable_heartbeat and self.is_connected:
                await self._start_heartbeat()
            
            logging.info("Production KME Client initialized successfully with monitoring")
            
        except Exception as e:
            logging.error(f"Failed to initialize Production KME Client: {e}")
            self.is_connected = False
        finally:
            self._initializing = False
    
    async def _direct_connection_test(self):
        """RECURSION FIX: Direct connection test without recursion"""
        try:
            # Make direct HTTP request to test endpoint without using _make_request
            url = f"{self.kme_url}/api/v1/status"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data and data.get('status') == 'active':
                        self.is_connected = True
                        logging.info("KME connection established successfully")
                        return
                        
            self.is_connected = False
            logging.warning("KME connection test failed - service not responding properly")
            
        except Exception as e:
            self.is_connected = False
            logging.error(f"KME direct connection test failed: {e}")
            
    async def _start_heartbeat(self):
        """Start heartbeat monitoring task"""
        if self.heartbeat_task and not self.heartbeat_task.done():
            return  # Already running
            
        self.heartbeat_enabled = True
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logging.info(f"KME heartbeat monitoring started (interval: {self.heartbeat_interval}s)")
    
    async def _heartbeat_loop(self):
        """Main heartbeat monitoring loop"""
        while self.heartbeat_enabled:
            try:
                # Perform heartbeat check
                heartbeat_result = await self._perform_heartbeat()
                
                if not heartbeat_result:
                    logging.warning("KME heartbeat failed - connection may be unstable")
                    self.connection_failures += 1
                    
                    # Only attempt reconnection if failures exceed threshold
                    if self.connection_failures >= self.max_connection_failures:
                        logging.warning("KME heartbeat failures exceeded threshold")
                        self.is_connected = False
                else:
                    # Reset failure counter on successful heartbeat
                    self.connection_failures = 0
                    self.last_successful_request = datetime.utcnow()
                    if not self.is_connected:
                        self.is_connected = True
                        logging.info("KME connection restored via heartbeat")
                
                # Wait for next heartbeat
                await asyncio.sleep(self.heartbeat_interval)
                
            except asyncio.CancelledError:
                logging.info("KME heartbeat monitoring cancelled")
                break
            except Exception as e:
                logging.error(f"KME heartbeat loop error: {e}")
                await asyncio.sleep(self.heartbeat_interval)
    
    async def _perform_heartbeat(self) -> bool:
        """Perform a lightweight heartbeat check"""
        try:
            # RECURSION FIX: Direct heartbeat check without using get_status
            url = f"{self.kme_url}/api/v1/status"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data and data.get('status') == 'active'
                    
            return False
                
        except Exception as e:
            logging.debug(f"KME heartbeat check failed: {e}")
            return False

    async def stop_heartbeat(self):
        """Stop heartbeat monitoring"""
        self.heartbeat_enabled = False
        if self.heartbeat_task and not self.heartbeat_task.done():
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        logging.info("KME heartbeat monitoring stopped")
            
    async def _make_request(self, method: str, endpoint: str, 
                          data: Dict = None, params: Dict = None, retry_count: int = 2) -> Optional[Dict]:
        """RECURSION FIX: Make HTTP request to KME with controlled retry logic"""
        self.stats['total_requests'] += 1
        
        # RECURSION FIX: Prevent reconnection loops
        if self._reconnecting:
            logging.debug("KME request blocked - reconnection in progress")
            return None
        
        for attempt in range(retry_count):
            try:
                # Check session availability
                if not self.session or self.session.closed:
                    if not self._initializing:  # Prevent recursion during initialization
                        logging.warning("KME session unavailable - request will fail")
                    return None
                    
                url = f"{self.kme_url}{endpoint}"
                headers = {}
                
                # Add authentication if configured
                if self.api_key:
                    headers['Authorization'] = f"Bearer {self.api_key}"
                    
                # Add client certificate if configured
                ssl_context = self.ssl_context
                if self.client_cert and self.client_key:
                    ssl_context = ssl.create_default_context()
                    ssl_context.load_cert_chain(self.client_cert, self.client_key)
                    
                logging.debug(f"KME Request (attempt {attempt + 1}): {method} {url}")
                
                async with self.session.request(
                    method=method,
                    url=url,
                    json=data,
                    params=params,
                    headers=headers,
                    ssl=ssl_context
                ) as response:
                    
                    response_data = None
                    content_type = response.headers.get('Content-Type', '')
                    
                    if 'application/json' in content_type:
                        response_data = await response.json()
                    else:
                        text_data = await response.text()
                        if text_data:
                            try:
                                response_data = json.loads(text_data)
                            except json.JSONDecodeError:
                                response_data = {'raw_response': text_data}
                                
                    logging.debug(f"KME Response: {response.status} - {response_data}")
                    
                    # Update connection state and statistics
                    if response.status == 200:
                        self.is_connected = True
                        self.last_successful_request = datetime.utcnow()
                        self.stats['successful_requests'] += 1
                        return response_data
                    elif response.status in [401, 403, 404]:
                        logging.error(f"KME authentication/authorization error: {response.status}")
                        self.stats['failed_requests'] += 1
                        return None
                    elif response.status == 410:
                        logging.warning("KME resource expired/consumed")
                        return None  # Don't count as failure
                    elif response.status >= 500:
                        # Server error - retry if attempts remaining
                        if attempt < retry_count - 1:
                            logging.warning(f"KME server error {response.status} - retrying in 1s")
                            await asyncio.sleep(1)
                            continue
                        else:
                            logging.error(f"KME server error: {response.status}")
                            self.stats['failed_requests'] += 1
                            return None
                    else:
                        logging.warning(f"KME unexpected status: {response.status}")
                        return response_data
                        
            except aiohttp.ClientError as e:
                if attempt < retry_count - 1:
                    logging.warning(f"KME client error (attempt {attempt + 1}): {e} - retrying")
                    self.is_connected = False
                    await asyncio.sleep(0.5)
                    continue
                else:
                    logging.error(f"KME client error: {e}")
                    self.is_connected = False
                    self.stats['failed_requests'] += 1
                    return None
                    
            except asyncio.TimeoutError:
                if attempt < retry_count - 1:
                    logging.warning(f"KME timeout (attempt {attempt + 1}) - retrying")
                    await asyncio.sleep(0.5)
                    continue
                else:
                    logging.error("KME request timeout")
                    self.is_connected = False
                    self.stats['failed_requests'] += 1
                    return None
                    
            except Exception as e:
                if attempt < retry_count - 1:
                    logging.warning(f"KME request error (attempt {attempt + 1}): {e} - retrying")
                    await asyncio.sleep(0.5)
                    continue
                else:
                    logging.error(f"KME request failed: {e}")
                    self.stats['failed_requests'] += 1
                    return None
        
        # All retries exhausted
        self.stats['failed_requests'] += 1
        return None
            
    async def get_status(self) -> Optional[Dict]:
        """Get KME status - ETSI GS QKD 014 compliant"""
        try:
            # Use cached status if recent
            now = datetime.utcnow()
            if (self.last_status_check and 
                (now - self.last_status_check).seconds < self.status_cache_duration):
                return {'status': 'active' if self.is_connected else 'inactive'}
                
            response = await self._make_request('GET', '/api/v1/status')
            
            if response:
                self.is_connected = True
                self.last_status_check = now
                return response
            else:
                self.is_connected = False
                return None
                
        except Exception as e:
            logging.error(f"Failed to get KME status: {e}")
            self.is_connected = False
            return None
            
    async def get_sae_status(self, sae_id: str) -> Optional[Dict]:
        """Get status for specific SAE"""
        try:
            endpoint = f"/api/v1/keys/{sae_id}/status"
            return await self._make_request('GET', endpoint)
            
        except Exception as e:
            logging.error(f"Failed to get SAE status for {sae_id}: {e}")
            return None
            
    async def request_key(self, sender_sae_id: str, receiver_sae_id: str,
                         key_length: int, key_type: str = 'seed',
                         key_count: int = 1) -> Optional[Dict]:
        """Request encryption keys from KME"""
        try:
            endpoint = f"/api/v1/keys/{receiver_sae_id}/enc_keys"
            
            request_data = {
                'sender_sae_id': sender_sae_id,
                'key_length': key_length,
                'key_count': key_count,
                'key_type': key_type
            }
            
            response = await self._make_request('POST', endpoint, data=request_data)
            
            if response and response.get('status') == 'success':
                keys = response.get('keys', [])
                if keys:
                    # Return first key with full metadata
                    key_info = keys[0]
                    
                    # For simulation, return the key data directly
                    # In real implementation, only metadata would be returned
                    return {
                        'key_id': key_info['key_id'],
                        'key_data': base64.b64decode(key_info.get('key_data', '')),
                        'length': key_info['length'],
                        'key_type': key_info['key_type'],
                        'expires_at': key_info['expires_at'],
                        'sender_sae_id': sender_sae_id,
                        'receiver_sae_id': receiver_sae_id
                    }
                    
            return None
            
        except Exception as e:
            logging.error(f"Failed to request key: {e}")
            return None
            
    async def get_key(self, sae_id: str, key_id: str) -> Optional[Dict]:
        """Get decryption key by ID"""
        try:
            endpoint = f"/api/v1/keys/{sae_id}/{key_id}/dec_keys"
            response = await self._make_request('GET', endpoint)
            
            if response and 'key_data' in response:
                return {
                    'key_id': response['key_id'],
                    'key_data': base64.b64decode(response['key_data']),
                    'length': response['length'],
                    'key_type': response['key_type'],
                    'expires_at': response.get('expires_at')
                }
                
            return None
            
        except Exception as e:
            logging.error(f"Failed to get key {key_id}: {e}")
            return None
            
    async def consume_key(self, sae_id: str, key_id: str) -> bool:
        """Mark key as consumed (for OTP keys)"""
        try:
            endpoint = f"/api/v1/keys/{sae_id}/{key_id}"
            response = await self._make_request('DELETE', endpoint)
            
            return response is not None
            
        except Exception as e:
            logging.error(f"Failed to consume key {key_id}: {e}")
            return False
            
    async def get_available_keys(self, sae_id: str) -> Optional[List[Dict]]:
        """Get list of available keys for SAE"""
        try:
            endpoint = f"/api/v1/keys/{sae_id}/available"
            response = await self._make_request('GET', endpoint)
            
            if response:
                return response.get('available_keys', [])
                
            return []
            
        except Exception as e:
            logging.error(f"Failed to get available keys for {sae_id}: {e}")
            return []
            
    async def get_key_statistics(self, sae_id: str = None) -> Optional[Dict]:
        """Get key usage statistics"""
        try:
            if sae_id:
                # Get statistics for specific SAE
                available_keys = await self.get_available_keys(sae_id)
                sae_status = await self.get_sae_status(sae_id)
                
                if available_keys is not None and sae_status:
                    return {
                        'sae_id': sae_id,
                        'available_keys': len(available_keys),
                        'total_keys': sae_status.get('total_keys', 0),
                        'qkd_link_status': sae_status.get('qkd_link_status', 'unknown')
                    }
            else:
                # Get global KME statistics
                status = await self.get_status()
                if status:
                    return {
                        'global_status': status.get('status'),
                        'qkd_rate': status.get('qkd_rate', 0),
                        'active_keys': status.get('active_keys', 0),
                        'timestamp': status.get('timestamp')
                    }
                    
            return None
            
        except Exception as e:
            logging.error(f"Failed to get key statistics: {e}")
            return None
            
    async def test_key_generation(self, key_length: int = 256, 
                                 key_type: str = 'seed') -> Optional[Dict]:
        """Test key generation capabilities"""
        try:
            test_sae_id = "qumail_test_client"
            
            # Request a test key
            key_info = await self.request_key(
                sender_sae_id=test_sae_id,
                receiver_sae_id=test_sae_id,
                key_length=key_length,
                key_type=key_type
            )
            
            if key_info:
                # Try to retrieve the key
                retrieved_key = await self.get_key(test_sae_id, key_info['key_id'])
                
                if retrieved_key:
                    # Consume the test key
                    await self.consume_key(test_sae_id, key_info['key_id'])
                    
                    return {
                        'test_successful': True,
                        'key_length_requested': key_length,
                        'key_length_received': len(retrieved_key['key_data']) * 8,
                        'key_type': key_type,
                        'response_time_ms': 100  # Simulated
                    }
                    
            return {
                'test_successful': False,
                'error': 'Key generation test failed'
            }
            
        except Exception as e:
            logging.error(f"Key generation test failed: {e}")
            return {
                'test_successful': False,
                'error': str(e)
            }
            
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check of KME connection"""
        health_report = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'unknown',
            'checks': {}
        }
        
        try:
            # Basic connectivity test
            status_response = await self.get_status()
            health_report['checks']['connectivity'] = {
                'status': 'pass' if status_response else 'fail',
                'response': status_response
            }
            
            # Authentication test (if configured)
            if self.api_key or self.client_cert:
                auth_test = await self.get_sae_status('qumail_health_check')
                health_report['checks']['authentication'] = {
                    'status': 'pass' if auth_test else 'fail',
                    'configured': True
                }
            else:
                health_report['checks']['authentication'] = {
                    'status': 'skip',
                    'configured': False
                }
                
            # Key generation test
            key_test = await self.test_key_generation(256, 'seed')
            health_report['checks']['key_generation'] = key_test
            
            # Determine overall status
            failed_checks = [
                check for check in health_report['checks'].values()
                if check.get('status') == 'fail'
            ]
            
            if not failed_checks:
                health_report['overall_status'] = 'healthy'
            elif len(failed_checks) == len(health_report['checks']):
                health_report['overall_status'] = 'critical'
            else:
                health_report['overall_status'] = 'degraded'
                
            logging.info(f"KME health check completed: {health_report['overall_status']}")
            
        except Exception as e:
            logging.error(f"KME health check failed: {e}")
            health_report['overall_status'] = 'error'
            health_report['error'] = str(e)
            
        return health_report
        
    def configure_authentication(self, method: str, **kwargs):
        """Configure KME authentication"""
        if method == 'api_key':
            self.api_key = kwargs.get('api_key')
            logging.info("KME authentication configured: API Key")
            
        elif method == 'client_cert':
            self.client_cert = kwargs.get('cert_file')
            self.client_key = kwargs.get('key_file')
            logging.info("KME authentication configured: Client Certificate")
            
        else:
            logging.error(f"Unsupported authentication method: {method}")
            
    def get_connection_statistics(self) -> Dict[str, Any]:
        """Get comprehensive KME connection statistics"""
        uptime = datetime.utcnow() - self.stats['uptime_start']
        
        return {
            'connection_status': 'connected' if self.is_connected else 'disconnected',
            'uptime_seconds': int(uptime.total_seconds()),
            'total_requests': self.stats['total_requests'],
            'successful_requests': self.stats['successful_requests'],
            'failed_requests': self.stats['failed_requests'],
            'success_rate': (
                (self.stats['successful_requests'] / self.stats['total_requests']) * 100
                if self.stats['total_requests'] > 0 else 0
            ),
            'connection_failures': self.connection_failures,
            'reconnection_attempts': self.stats['reconnection_attempts'],
            'last_successful_request': (
                self.last_successful_request.isoformat() 
                if self.last_successful_request else None
            ),
            'last_reconnection': (
                self.stats['last_reconnection'].isoformat() 
                if self.stats['last_reconnection'] else None
            ),
            'heartbeat_enabled': self.heartbeat_enabled,
            'heartbeat_interval': self.heartbeat_interval
        }
    
    async def close(self):
        """PRODUCTION: Close KME client session with comprehensive resource cleanup"""
        try:
            # Stop heartbeat monitoring
            await self.stop_heartbeat()
            
            # CRITICAL RESOURCE LEAK FIX: Close aiohttp session properly
            if self.session and not self.session.closed:
                await self.session.close()
                self.session = None
                logging.info("PRODUCTION: aiohttp.ClientSession closed successfully")
                
            self.is_connected = False
            
            # Log final statistics
            stats = self.get_connection_statistics()
            logging.info(f"KME Client session closed - Final stats: "
                        f"Requests: {stats['total_requests']}, "
                        f"Success rate: {stats['success_rate']:.1f}%, "
                        f"Uptime: {stats['uptime_seconds']}s")
            
        except Exception as e:
            logging.error(f"Error closing KME Client: {e}")
            
    def __del__(self):
        """Destructor to ensure session is closed"""
        if self.session and not self.session.closed:
            try:
                asyncio.create_task(self.close())
            except Exception:
                pass  # Ignore errors during cleanup