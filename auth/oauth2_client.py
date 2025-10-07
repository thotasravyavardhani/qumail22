#!/usr/bin/env python3
"""
Real OAuth2 Client Implementation for Gmail, Yahoo, and Outlook
Implements Authorization Code Flow with PKCE for enhanced security
"""

import asyncio
import logging
import base64
import hashlib
import secrets
import webbrowser
import json
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlencode, parse_qs, urlparse
import aiohttp
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

class OAuth2Client:
    """Real OAuth2 client with PKCE support"""
    
    # OAuth2 Provider Configurations
    PROVIDERS = {
        'gmail': {
            'auth_uri': 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_uri': 'https://oauth2.googleapis.com/token',
            'revoke_uri': 'https://oauth2.googleapis.com/revoke',
            'scopes': ['https://www.googleapis.com/auth/gmail.modify', 
                      'https://www.googleapis.com/auth/gmail.send'],
            'redirect_uri': 'http://localhost:8090/oauth2callback'
        },
        'yahoo': {
            'auth_uri': 'https://api.login.yahoo.com/oauth2/request_auth',
            'token_uri': 'https://api.login.yahoo.com/oauth2/get_token',
            'scopes': ['mail-r', 'mail-w'],
            'redirect_uri': 'http://localhost:8090/oauth2callback'
        },
        'outlook': {
            'auth_uri': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            'token_uri': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            'scopes': ['https://outlook.office365.com/IMAP.AccessAsUser.All',
                      'https://outlook.office365.com/SMTP.Send'],
            'redirect_uri': 'http://localhost:8090/oauth2callback'
        }
    }
    
    def __init__(self, provider: str, client_id: str, client_secret: str):
        """
        Initialize OAuth2 client
        
        Args:
            provider: Email provider (gmail, yahoo, outlook)
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret
        """
        self.provider = provider.lower()
        self.client_id = client_id
        self.client_secret = client_secret
        
        if self.provider not in self.PROVIDERS:
            raise ValueError(f"Unsupported provider: {provider}")
        
        self.config = self.PROVIDERS[self.provider]
        self.auth_code = None
        self.tokens = {}
        
    def _generate_pkce_pair(self) -> Tuple[str, str]:
        """Generate PKCE code verifier and challenge"""
        # Generate code verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        # Generate code challenge (SHA256 hash of verifier)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    def get_authorization_url(self) -> Tuple[str, str]:
        """
        Get OAuth2 authorization URL
        
        Returns:
            Tuple of (authorization_url, state)
        """
        state = secrets.token_urlsafe(32)
        code_verifier, code_challenge = self._generate_pkce_pair()
        
        # Store for later use
        self.code_verifier = code_verifier
        self.state = state
        
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.config['redirect_uri'],
            'response_type': 'code',
            'scope': ' '.join(self.config['scopes']),
            'state': state,
            'access_type': 'offline',  # Request refresh token
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        # Provider-specific parameters
        if self.provider == 'gmail':
            params['prompt'] = 'consent'  # Force consent screen to get refresh token
        elif self.provider == 'outlook':
            params['prompt'] = 'select_account'
        
        auth_url = f"{self.config['auth_uri']}?{urlencode(params)}"
        return auth_url, state
    
    async def exchange_code_for_tokens(self, auth_code: str) -> Dict:
        """
        Exchange authorization code for access/refresh tokens
        
        Args:
            auth_code: Authorization code from callback
            
        Returns:
            Token response with access_token, refresh_token, expires_in
        """
        token_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': auth_code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.config['redirect_uri'],
            'code_verifier': self.code_verifier
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.config['token_uri'],
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Token exchange failed: {error_text}")
                
                tokens = await response.json()
                
                # Calculate expiry time
                expires_in = tokens.get('expires_in', 3600)
                tokens['expires_at'] = (
                    datetime.utcnow() + timedelta(seconds=expires_in)
                ).isoformat()
                
                self.tokens = tokens
                logging.info(f"Successfully obtained OAuth2 tokens for {self.provider}")
                return tokens
    
    async def refresh_access_token(self, refresh_token: str) -> Dict:
        """
        Refresh access token using refresh token
        
        Args:
            refresh_token: OAuth2 refresh token
            
        Returns:
            New token response
        """
        token_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.config['token_uri'],
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Token refresh failed: {error_text}")
                
                tokens = await response.json()
                
                # Calculate expiry time
                expires_in = tokens.get('expires_in', 3600)
                tokens['expires_at'] = (
                    datetime.utcnow() + timedelta(seconds=expires_in)
                ).isoformat()
                
                # Preserve refresh token if not returned
                if 'refresh_token' not in tokens and refresh_token:
                    tokens['refresh_token'] = refresh_token
                
                self.tokens = tokens
                logging.info(f"Successfully refreshed OAuth2 tokens for {self.provider}")
                return tokens
    
    def is_token_expired(self, tokens: Dict) -> bool:
        """Check if access token is expired or expiring soon"""
        if 'expires_at' not in tokens:
            return True
        
        expires_at = datetime.fromisoformat(tokens['expires_at'])
        # Consider expired if less than 5 minutes remaining
        return datetime.utcnow() >= (expires_at - timedelta(minutes=5))
    
    async def get_valid_token(self, tokens: Dict) -> str:
        """
        Get a valid access token, refreshing if necessary
        
        Args:
            tokens: Current token dict
            
        Returns:
            Valid access token
        """
        if self.is_token_expired(tokens):
            if 'refresh_token' in tokens:
                new_tokens = await self.refresh_access_token(tokens['refresh_token'])
                return new_tokens['access_token']
            else:
                raise Exception("Token expired and no refresh token available")
        
        return tokens['access_token']


class OAuth2CallbackHandler(BaseHTTPRequestHandler):
    """HTTP server handler for OAuth2 callback"""
    
    auth_code = None
    state = None
    error = None
    
    def do_GET(self):
        """Handle OAuth2 callback"""
        # Parse query parameters
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)
        
        # Extract authorization code and state
        OAuth2CallbackHandler.auth_code = params.get('code', [None])[0]
        OAuth2CallbackHandler.state = params.get('state', [None])[0]
        OAuth2CallbackHandler.error = params.get('error', [None])[0]
        
        # Send response to browser
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        if OAuth2CallbackHandler.auth_code:
            html = """
            <html>
                <head><title>OAuth2 Success</title></head>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h1 style="color: #4CAF50;">✓ Authorization Successful!</h1>
                    <p>You have successfully authorized QuMail.</p>
                    <p>You can close this window and return to QuMail.</p>
                </body>
            </html>
            """
        else:
            html = f"""
            <html>
                <head><title>OAuth2 Error</title></head>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h1 style="color: #f44336;">✗ Authorization Failed</h1>
                    <p>Error: {OAuth2CallbackHandler.error or 'Unknown error'}</p>
                    <p>Please try again.</p>
                </body>
            </html>
            """
        
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        """Suppress log messages"""
        pass


def run_callback_server(port: int = 8090) -> Tuple[Optional[str], Optional[str]]:
    """
    Run OAuth2 callback server
    
    Args:
        port: Port to listen on
        
    Returns:
        Tuple of (auth_code, state)
    """
    server = HTTPServer(('localhost', port), OAuth2CallbackHandler)
    
    # Run server until callback received
    while OAuth2CallbackHandler.auth_code is None and OAuth2CallbackHandler.error is None:
        server.handle_request()
    
    auth_code = OAuth2CallbackHandler.auth_code
    state = OAuth2CallbackHandler.state
    
    # Reset for next use
    OAuth2CallbackHandler.auth_code = None
    OAuth2CallbackHandler.state = None
    OAuth2CallbackHandler.error = None
    
    return auth_code, state


async def authorize_provider(provider: str, client_id: str, client_secret: str) -> Dict:
    """
    Complete OAuth2 authorization flow for a provider
    
    Args:
        provider: Email provider (gmail, yahoo, outlook)
        client_id: OAuth2 client ID
        client_secret: OAuth2 client secret
        
    Returns:
        Token dict with access_token, refresh_token, expires_at
    """
    client = OAuth2Client(provider, client_id, client_secret)
    
    # Get authorization URL
    auth_url, state = client.get_authorization_url()
    
    logging.info(f"Opening browser for {provider} authorization...")
    logging.info(f"Authorization URL: {auth_url}")
    
    # Open browser for user authorization
    webbrowser.open(auth_url)
    
    # Run callback server to receive auth code
    logging.info("Waiting for OAuth2 callback...")
    auth_code, returned_state = await asyncio.get_event_loop().run_in_executor(
        None, run_callback_server, 8090
    )
    
    if not auth_code:
        raise Exception("Authorization failed - no auth code received")
    
    if returned_state != state:
        raise Exception("State mismatch - possible CSRF attack")
    
    # Exchange code for tokens
    tokens = await client.exchange_code_for_tokens(auth_code)
    
    return tokens
