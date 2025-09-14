#!/usr/bin/env python3
"""Persistent OAuth provider that extends InMemoryOAuthProvider with file-based storage."""

import json
import os
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyHttpUrl
from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from fastmcp.server.auth.auth import (
    ClientRegistrationOptions,
    RevocationOptions,
)

logger = logging.getLogger(__name__)


class PersistentOAuthProvider(InMemoryOAuthProvider):
    """
    A persistent OAuth provider that extends InMemoryOAuthProvider with file-based storage.
    All token data is automatically saved to disk and restored on startup.
    """

    def __init__(
        self,
        base_url: AnyHttpUrl | str | None = None,
        service_documentation_url: AnyHttpUrl | str | None = None,
        client_registration_options: ClientRegistrationOptions | None = None,
        revocation_options: RevocationOptions | None = None,
        required_scopes: list[str] | None = None,
        storage_file: str = ".oauth_data.json",
    ):
        """Initialize the persistent OAuth provider.
        
        Args:
            storage_file: Path to the JSON file for persisting OAuth data
        """
        # Initialize parent class first
        super().__init__(
            base_url=base_url,
            service_documentation_url=service_documentation_url,
            client_registration_options=client_registration_options,
            revocation_options=revocation_options,
            required_scopes=required_scopes,
        )
        
        self.storage_file = storage_file
        self._load_data()
        logger.info(f"✅ PersistentOAuthProvider initialized with storage file: {storage_file}")

    def _serialize_token(self, token: AccessToken | RefreshToken | AuthorizationCode) -> Dict[str, Any]:
        """Serialize a token object to dictionary."""
        return token.model_dump()

    def _deserialize_access_token(self, data: Dict[str, Any]) -> AccessToken:
        """Deserialize dictionary to AccessToken."""
        return AccessToken.model_validate(data)

    def _deserialize_refresh_token(self, data: Dict[str, Any]) -> RefreshToken:
        """Deserialize dictionary to RefreshToken."""
        return RefreshToken.model_validate(data)

    def _deserialize_auth_code(self, data: Dict[str, Any]) -> AuthorizationCode:
        """Deserialize dictionary to AuthorizationCode."""
        return AuthorizationCode.model_validate(data)

    def _serialize_client(self, client: OAuthClientInformationFull) -> Dict[str, Any]:
        """Serialize a client object to dictionary."""
        client_dict = client.model_dump()
        # Convert AnyHttpUrl objects to strings for JSON serialization
        if 'redirect_uris' in client_dict:
            client_dict['redirect_uris'] = [str(uri) for uri in client_dict['redirect_uris']]
        return client_dict

    def _deserialize_client(self, data: Dict[str, Any]) -> OAuthClientInformationFull:
        """Deserialize dictionary to OAuthClientInformationFull."""
        # Convert string URIs back to AnyHttpUrl objects
        if 'redirect_uris' in data:
            data['redirect_uris'] = [AnyHttpUrl(uri) for uri in data['redirect_uris']]
        return OAuthClientInformationFull.model_validate(data)

    def _save_data(self):
        """Save all OAuth data to the storage file."""
        try:
            data = {
                'metadata': {
                    'last_saved': datetime.now().isoformat(),
                    'version': '1.0'
                },
                'clients': {
                    client_id: self._serialize_client(client)
                    for client_id, client in self.clients.items()
                },
                'auth_codes': {
                    code: self._serialize_token(auth_code)
                    for code, auth_code in self.auth_codes.items()
                },
                'access_tokens': {
                    token: self._serialize_token(access_token)
                    for token, access_token in self.access_tokens.items()
                },
                'refresh_tokens': {
                    token: self._serialize_token(refresh_token)
                    for token, refresh_token in self.refresh_tokens.items()
                },
                'access_to_refresh_map': dict(self._access_to_refresh_map),
                'refresh_to_access_map': dict(self._refresh_to_access_map),
            }
            
            # Write to temporary file first, then rename for atomic operation
            temp_file = f"{self.storage_file}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Atomic rename
            os.rename(temp_file, self.storage_file)
            
            # Set restrictive permissions for security
            os.chmod(self.storage_file, 0o600)
            
            logger.debug(f"💾 Saved OAuth data to {self.storage_file}")
            
        except Exception as e:
            logger.error(f"❌ Failed to save OAuth data: {e}")
            # Clean up temp file if it exists
            if os.path.exists(f"{self.storage_file}.tmp"):
                os.remove(f"{self.storage_file}.tmp")

    def _load_data(self):
        """Load OAuth data from the storage file."""
        if not os.path.exists(self.storage_file):
            logger.info(f"📂 Storage file {self.storage_file} does not exist, starting fresh")
            return

        try:
            with open(self.storage_file, 'r') as f:
                data = json.load(f)
            
            # Load clients
            if 'clients' in data:
                for client_id, client_data in data['clients'].items():
                    self.clients[client_id] = self._deserialize_client(client_data)
                logger.info(f"📋 Loaded {len(self.clients)} OAuth clients")
            
            # Load auth codes (check expiry)
            if 'auth_codes' in data:
                current_time = time.time()
                for code, auth_code_data in data['auth_codes'].items():
                    auth_code = self._deserialize_auth_code(auth_code_data)
                    if auth_code.expires_at > current_time:
                        self.auth_codes[code] = auth_code
                    else:
                        logger.debug(f"🗑️ Discarded expired auth code: {code}")
                logger.info(f"🔐 Loaded {len(self.auth_codes)} valid auth codes")
            
            # Load access tokens (check expiry)
            if 'access_tokens' in data:
                current_time = time.time()
                for token, access_token_data in data['access_tokens'].items():
                    access_token = self._deserialize_access_token(access_token_data)
                    if access_token.expires_at is None or access_token.expires_at > current_time:
                        self.access_tokens[token] = access_token
                    else:
                        logger.debug(f"🗑️ Discarded expired access token: {token[:20]}...")
                logger.info(f"🎫 Loaded {len(self.access_tokens)} valid access tokens")
            
            # Load refresh tokens (check expiry)
            if 'refresh_tokens' in data:
                current_time = time.time()
                for token, refresh_token_data in data['refresh_tokens'].items():
                    refresh_token = self._deserialize_refresh_token(refresh_token_data)
                    if refresh_token.expires_at is None or refresh_token.expires_at > current_time:
                        self.refresh_tokens[token] = refresh_token
                    else:
                        logger.debug(f"🗑️ Discarded expired refresh token: {token[:20]}...")
                logger.info(f"🔄 Loaded {len(self.refresh_tokens)} valid refresh tokens")
            
            # Load token mappings
            if 'access_to_refresh_map' in data:
                self._access_to_refresh_map.update(data['access_to_refresh_map'])
            if 'refresh_to_access_map' in data:
                self._refresh_to_access_map.update(data['refresh_to_access_map'])
            
            # Clean up expired tokens from mappings
            self._cleanup_token_mappings()
            
            metadata = data.get('metadata', {})
            last_saved = metadata.get('last_saved', 'unknown')
            logger.info(f"✅ Successfully loaded OAuth data (last saved: {last_saved})")
            
        except Exception as e:
            logger.error(f"❌ Failed to load OAuth data from {self.storage_file}: {e}")
            logger.warning("🔄 Starting with empty OAuth state")

    def _cleanup_token_mappings(self):
        """Remove mappings for tokens that no longer exist."""
        # Clean access -> refresh mappings
        to_remove = []
        for access_token, refresh_token in self._access_to_refresh_map.items():
            if access_token not in self.access_tokens or refresh_token not in self.refresh_tokens:
                to_remove.append(access_token)
        for access_token in to_remove:
            del self._access_to_refresh_map[access_token]
        
        # Clean refresh -> access mappings
        to_remove = []
        for refresh_token, access_token in self._refresh_to_access_map.items():
            if refresh_token not in self.refresh_tokens or access_token not in self.access_tokens:
                to_remove.append(refresh_token)
        for refresh_token in to_remove:
            del self._refresh_to_access_map[refresh_token]

    # Override methods that modify data to trigger saves

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register a client and save to persistent storage."""
        await super().register_client(client_info)
        self._save_data()
        logger.info(f"💾 Saved client registration: {client_info.client_id}")

    async def authorize(self, client: OAuthClientInformationFull, params) -> str:
        """Generate authorization code and save to persistent storage."""
        result = await super().authorize(client, params)
        self._save_data()
        return result

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode):
        """Exchange auth code for tokens and save to persistent storage."""
        result = await super().exchange_authorization_code(client, authorization_code)
        self._save_data()
        logger.info(f"💾 Saved new token pair for client: {client.client_id}")
        return result

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]):
        """Exchange refresh token for new tokens and save to persistent storage."""
        result = await super().exchange_refresh_token(client, refresh_token, scopes)
        self._save_data()
        logger.info(f"💾 Saved refreshed token pair for client: {client.client_id}")
        return result

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoke token and save to persistent storage."""
        await super().revoke_token(token)
        self._save_data()
        logger.info(f"💾 Saved token revocation")

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about stored OAuth data."""
        return {
            'clients': len(self.clients),
            'auth_codes': len(self.auth_codes),
            'access_tokens': len(self.access_tokens),
            'refresh_tokens': len(self.refresh_tokens),
            'token_mappings': len(self._access_to_refresh_map),
        }