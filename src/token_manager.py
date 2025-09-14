#!/usr/bin/env python3
"""Token persistence manager for Vivint refresh tokens."""

import json
import os
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import aiofiles
from pathlib import Path

try:
    from .config import config
except ImportError:
    # Handle case when run directly
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from config import config

logger = logging.getLogger(__name__)

class TokenManager:
    """Manages persistence and validation of Vivint refresh tokens."""
    
    def __init__(self, token_file: Optional[str] = None):
        self.token_file = Path(token_file or config.refresh_token_file)
        self._tokens: Optional[Dict[str, Any]] = None
    
    async def load_tokens(self) -> Optional[Dict[str, Any]]:
        """Load tokens from file if they exist and are valid."""
        if not self.token_file.exists():
            logger.debug(f"Token file {self.token_file} does not exist")
            return None
        
        try:
            async with aiofiles.open(self.token_file, 'r') as f:
                content = await f.read()
                tokens = json.loads(content)
            
            # Validate token structure
            if not isinstance(tokens, dict) or 'refresh_token' not in tokens:
                logger.warning("Invalid token file structure")
                return None
            
            # Check if tokens are expired
            if self._are_tokens_expired(tokens):
                logger.info("Stored tokens have expired")
                await self.clear_tokens()
                return None
            
            logger.info("Successfully loaded valid refresh tokens")
            self._tokens = tokens
            return tokens
            
        except Exception as e:
            logger.error(f"Failed to load tokens from {self.token_file}: {e}")
            return None
    
    async def save_tokens(self, tokens: Dict[str, Any]) -> bool:
        """Save tokens to file securely."""
        try:
            # Create directory if it doesn't exist
            self.token_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Add timestamp for tracking
            tokens_with_metadata = {
                **tokens,
                'saved_at': datetime.now().isoformat(),
                'username': config.username  # Associate with user
            }
            
            # Write atomically
            temp_file = self.token_file.with_suffix('.tmp')
            async with aiofiles.open(temp_file, 'w') as f:
                await f.write(json.dumps(tokens_with_metadata, indent=2))
            
            # Move to final location
            temp_file.replace(self.token_file)
            
            # Set restrictive permissions (user read/write only)
            self.token_file.chmod(0o600)
            
            logger.info(f"Successfully saved tokens to {self.token_file}")
            self._tokens = tokens_with_metadata
            return True
            
        except Exception as e:
            logger.error(f"Failed to save tokens to {self.token_file}: {e}")
            return False
    
    async def clear_tokens(self) -> None:
        """Clear stored tokens."""
        try:
            if self.token_file.exists():
                self.token_file.unlink()
                logger.info("Cleared stored tokens")
            self._tokens = None
        except Exception as e:
            logger.error(f"Failed to clear tokens: {e}")
    
    def _are_tokens_expired(self, tokens: Dict[str, Any]) -> bool:
        """Check if tokens are expired or close to expiring."""
        try:
            if 'expires_in' in tokens and 'saved_at' in tokens:
                saved_at = datetime.fromisoformat(tokens['saved_at'])
                expires_in_seconds = tokens['expires_in']
                
                # Consider tokens expired if they expire within 10 minutes
                buffer_seconds = 600  # 10 minutes
                expiry_time = saved_at + timedelta(seconds=expires_in_seconds - buffer_seconds)
                
                if datetime.now() >= expiry_time:
                    return True
            
            # Also check JWT token expiration if present
            if 'id_token' in tokens:
                import jwt
                try:
                    jwt.decode(
                        tokens['id_token'],
                        options={"verify_signature": False, "verify_exp": True},
                        leeway=-30,  # 30 second buffer
                    )
                except jwt.ExpiredSignatureError:
                    return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Could not validate token expiration: {e}")
            return True  # Consider expired if we can't validate
    
    def get_refresh_token(self) -> Optional[str]:
        """Get the refresh token if available."""
        if self._tokens and 'refresh_token' in self._tokens:
            return self._tokens['refresh_token']
        return None
    
    def get_id_token(self) -> Optional[str]:
        """Get the ID token if available."""
        if self._tokens and 'id_token' in self._tokens:
            return self._tokens['id_token']
        return None
    
    def is_token_for_user(self, username: str) -> bool:
        """Check if stored tokens are for the specified user."""
        if self._tokens and 'username' in self._tokens:
            return self._tokens['username'] == username
        return False

# Global token manager instance
token_manager = TokenManager()