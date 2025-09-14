#!/usr/bin/env python3
"""Custom OAuth provider with Vivint authentication.

This provider extends FastMCP's InMemoryOAuthProvider to require Vivint
credential authentication before issuing OAuth authorization codes.
"""

import secrets
import time
import asyncio
import logging
from typing import Dict, Optional, Any, List
from urllib.parse import parse_qs, urlparse, urlencode
from datetime import datetime, timedelta

import aiohttp
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.templating import Jinja2Templates

from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, construct_redirect_uri
from mcp.shared.auth import OAuthClientInformationFull

try:
    from .vivint_client import VivintMCPClient, VivintAuthenticationError, VivintMfaRequiredError
    from .config import config
except ImportError:
    # Handle case when run directly
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from vivint_client import VivintMCPClient, VivintAuthenticationError, VivintMfaRequiredError
    from config import config

logger = logging.getLogger(__name__)

# In-memory session store
class SessionStore:
    """Simple in-memory session store for OAuth flows."""
    
    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._session_expiry: Dict[str, datetime] = {}
    
    def create_session(self) -> str:
        """Create a new session and return the session ID."""
        session_id = secrets.token_hex(32)
        self._sessions[session_id] = {}
        self._session_expiry[session_id] = datetime.now() + timedelta(minutes=30)
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by ID."""
        self._cleanup_expired()
        return self._sessions.get(session_id)
    
    def set_session(self, session_id: str, data: Dict[str, Any]) -> None:
        """Set session data."""
        if session_id in self._sessions:
            self._sessions[session_id].update(data)
            self._session_expiry[session_id] = datetime.now() + timedelta(minutes=30)
    
    def delete_session(self, session_id: str) -> None:
        """Delete a session."""
        self._sessions.pop(session_id, None)
        self._session_expiry.pop(session_id, None)
    
    def _cleanup_expired(self) -> None:
        """Clean up expired sessions."""
        now = datetime.now()
        expired_sessions = [
            session_id for session_id, expiry in self._session_expiry.items()
            if now > expiry
        ]
        for session_id in expired_sessions:
            self.delete_session(session_id)

class VivintOAuthProvider(InMemoryOAuthProvider):
    """OAuth provider that requires Vivint authentication before issuing codes."""
    
    def __init__(self, base_url: str, templates_dir: str = "src/templates"):
        """Initialize the Vivint OAuth provider.
        
        Args:
            base_url: Base URL for the OAuth server
            templates_dir: Directory containing HTML templates
        """
        super().__init__(base_url=base_url)
        self.templates = Jinja2Templates(directory=templates_dir)
        self._vivint_clients: Dict[str, VivintMCPClient] = {}  # session_id -> client
        self._session_store = SessionStore()
    
    def _get_session_id_from_request(self, request: Request) -> Optional[str]:
        """Extract session ID from request cookies."""
        return request.cookies.get("session_id")
    
    def _set_session_cookie(self, response: HTMLResponse, session_id: str) -> None:
        """Set session cookie in response."""
        response.set_cookie(
            key="session_id", 
            value=session_id, 
            max_age=1800,  # 30 minutes
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax"
        )
        
    async def get_vivint_client(self, session_id: str) -> VivintMCPClient:
        """Get or create a Vivint client for a session."""
        if session_id not in self._vivint_clients:
            self._vivint_clients[session_id] = VivintMCPClient()
        return self._vivint_clients[session_id]
    
    async def cleanup_vivint_client(self, session_id: str) -> None:
        """Clean up a Vivint client session."""
        if session_id in self._vivint_clients:
            client = self._vivint_clients.pop(session_id)
            try:
                await client.disconnect()
            except Exception as e:
                logger.debug(f"Error cleaning up Vivint client: {e}")
    
    async def authenticate_with_vivint(
        self, 
        username: str, 
        password: str, 
        mfa_code: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> tuple[bool, str, Optional[str]]:
        """Authenticate with Vivint credentials.
        
        Args:
            username: Vivint username
            password: Vivint password  
            mfa_code: Optional MFA code
            session_id: Session identifier for client management
            
        Returns:
            Tuple of (success, message, mfa_required_flag)
        """
        if not session_id:
            session_id = secrets.token_hex(16)
            
        try:
            client = await self.get_vivint_client(session_id)
            
            # Temporarily override config for this authentication
            original_username = config.username
            original_password = config.password
            original_mfa_code = config.mfa_code
            
            # Set credentials for this authentication attempt
            config.username = username
            config.password = password
            config.mfa_code = mfa_code
            
            try:
                await client.connect()
                logger.info(f"Vivint authentication successful for user: {username}")
                return True, "Authentication successful", None
                
            except VivintMfaRequiredError as e:
                logger.info(f"MFA required for user: {username}")
                return False, str(e), "mfa_required"
                
            except VivintAuthenticationError as e:
                logger.warning(f"Vivint authentication failed for user {username}: {e}")
                await self.cleanup_vivint_client(session_id)
                return False, f"Authentication failed: {str(e)}", None
                
            finally:
                # Restore original config
                config.username = original_username
                config.password = original_password
                config.mfa_code = original_mfa_code
                
        except Exception as e:
            logger.error(f"Unexpected error during Vivint authentication: {e}")
            await self.cleanup_vivint_client(session_id)
            return False, f"Authentication error: {str(e)}", None
    
    async def authorize(
        self, 
        client: OAuthClientInformationFull, 
        params: AuthorizationParams
    ) -> str:
        """Override authorize to require Vivint authentication.
        
        This method should NOT be called directly. Instead, the authorization
        flow goes through the web interface at /authorize.
        """
        # This method is called by FastMCP's OAuth framework, but we handle
        # authorization through our web interface. If we reach here without
        # proper authentication, it's an error.
        raise AuthorizeError(
            error="access_denied",
            error_description="Authorization must be completed through the web interface"
        )
    
    def get_authorize_url_params(self, request: Request) -> Dict[str, Any]:
        """Extract OAuth parameters from authorization request."""
        return {
            "response_type": request.query_params.get("response_type"),
            "client_id": request.query_params.get("client_id"), 
            "redirect_uri": request.query_params.get("redirect_uri"),
            "scope": request.query_params.get("scope"),
            "state": request.query_params.get("state"),
            "code_challenge": request.query_params.get("code_challenge"),
            "code_challenge_method": request.query_params.get("code_challenge_method"),
        }
    
    async def handle_authorization_request(self, request: Request) -> str:
        """Handle GET /authorize - show login form."""
        auth_params = self.get_authorize_url_params(request)
        client_id = auth_params.get("client_id")
        
        # Validate client
        if not client_id or client_id not in self.clients:
            return await self.render_error_page(
                request, 
                "Invalid Client", 
                f"Unknown client ID: {client_id}"
            )
        
        client_info = self.clients[client_id]
        
        # Get or create session
        session_id = self._get_session_id_from_request(request)
        if not session_id or not self._session_store.get_session(session_id):
            session_id = self._session_store.create_session()
        
        # Store auth request in session
        self._session_store.set_session(session_id, {
            "auth_request": auth_params,
            "client_info": {
                "client_id": client_info.client_id,
                "client_name": client_info.client_name,
            }
        })
        
        session_data = self._session_store.get_session(session_id)
        
        # Check if already authenticated
        if session_data and session_data.get("vivint_authenticated"):
            return await self.render_consent_page(request, client_info, auth_params, session_data.get("vivint_username", "Unknown"), auth_params.get("scope", "").split())
        
        # Show login form
        return await self.render_login_page(request, client_info, auth_params)
    
    async def handle_authorization_post(
        self, 
        request: Request,
        username: str,
        password: str,
        mfa_code: Optional[str] = None,
        action: str = "login"
    ):
        """Handle POST /authorize - process login or consent."""
        
        # Get stored auth request
        auth_params = request.session.get(SESSION_AUTH_REQUEST)
        client_info_session = request.session.get(SESSION_CLIENT_INFO)
        
        if not auth_params or not client_info_session:
            return HTMLResponse(
                content=await self.render_error_page(
                    request,
                    "Session Error", 
                    "Authorization session expired. Please try again."
                ),
                status_code=400
            )
        
        client_id = client_info_session["client_id"]
        client_info = self.clients.get(client_id)
        
        if not client_info:
            return HTMLResponse(
                content=await self.render_error_page(
                    request,
                    "Invalid Client",
                    f"Client {client_id} not found"
                ),
                status_code=400
            )
        
        if action == "login":
            # Process login
            session_id = request.session.get("session_id") or secrets.token_hex(16)
            request.session["session_id"] = session_id
            
            success, message, mfa_required = await self.authenticate_with_vivint(
                username, password, mfa_code, session_id
            )
            
            if success:
                # Authentication successful
                request.session[SESSION_VIVINT_AUTHENTICATED] = True
                request.session[SESSION_VIVINT_USERNAME] = username
                return await self.handle_consent_page(request, client_info, auth_params)
                
            elif mfa_required == "mfa_required":
                # Show MFA form
                return await self.render_login_page(
                    request, client_info, auth_params, 
                    error=message, show_mfa=True, username=username, password=password
                )
            else:
                # Authentication failed
                return await self.render_login_page(
                    request, client_info, auth_params, error=message
                )
        
        elif action == "consent":
            # Process consent (user approved authorization)
            if not request.session.get(SESSION_VIVINT_AUTHENTICATED):
                return HTMLResponse(
                    content=await self.render_error_page(
                        request,
                        "Authentication Required",
                        "You must log in before granting authorization"
                    ),
                    status_code=401
                )
            
            # Generate authorization code
            try:
                redirect_url = await self.issue_authorization_code(client_info, auth_params)
                return RedirectResponse(url=redirect_url, status_code=302)
            except Exception as e:
                logger.error(f"Failed to issue authorization code: {e}")
                return HTMLResponse(
                    content=await self.render_error_page(
                        request,
                        "Authorization Error",
                        "Failed to complete authorization. Please try again."
                    ),
                    status_code=500
                )
        
        else:
            return HTMLResponse(
                content=await self.render_error_page(
                    request,
                    "Invalid Request",
                    f"Unknown action: {action}"
                ),
                status_code=400
            )
    
    async def issue_authorization_code(
        self, 
        client_info: OAuthClientInformationFull, 
        auth_params: Dict[str, Any]
    ) -> str:
        """Issue an authorization code after successful authentication."""
        
        # Create authorization parameters object
        scopes = auth_params.get("scope", "").split() if auth_params.get("scope") else []
        
        params = AuthorizationParams(
            response_type=auth_params["response_type"],
            client_id=auth_params["client_id"],
            redirect_uri=auth_params["redirect_uri"],
            redirect_uri_provided_explicitly=True,
            scopes=scopes,
            state=auth_params.get("state"),
            code_challenge=auth_params.get("code_challenge"),
            code_challenge_method=auth_params.get("code_challenge_method", "S256")
        )
        
        # Generate authorization code
        auth_code_value = f"vivint_auth_{secrets.token_hex(32)}"
        expires_at = time.time() + 300  # 5 minute expiry
        
        # Validate and filter scopes
        scopes_list = params.scopes if params.scopes is not None else []
        if client_info.scope:
            client_allowed_scopes = set(client_info.scope.split())
            scopes_list = [s for s in scopes_list if s in client_allowed_scopes]
        
        # Store authorization code
        from mcp.server.auth.provider import AuthorizationCode
        auth_code = AuthorizationCode(
            code=auth_code_value,
            client_id=client_info.client_id,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            scopes=scopes_list,
            expires_at=expires_at,
            code_challenge=params.code_challenge,
        )
        self.auth_codes[auth_code_value] = auth_code
        
        logger.info(f"Issued authorization code for client {client_info.client_id}")
        
        # Build redirect URL
        return construct_redirect_uri(
            str(params.redirect_uri), 
            code=auth_code_value, 
            state=params.state
        )
    
    async def handle_consent_page(
        self, 
        request: Request, 
        client_info: OAuthClientInformationFull, 
        auth_params: Dict[str, Any]
    ) -> HTMLResponse:
        """Show consent/authorization page."""
        username = request.session.get(SESSION_VIVINT_USERNAME, "Unknown")
        scopes = auth_params.get("scope", "").split() if auth_params.get("scope") else []
        
        return HTMLResponse(
            content=await self.render_consent_page(
                request, client_info, auth_params, username, scopes
            )
        )
    
    async def render_login_page(
        self, 
        request: Request, 
        client_info: OAuthClientInformationFull,
        auth_params: Dict[str, Any],
        error: Optional[str] = None,
        show_mfa: bool = False,
        username: str = "",
        password: str = ""
    ) -> str:
        """Render the login page."""
        return self.templates.TemplateResponse(
            "authorize.html",
            {
                "request": request,
                "client_name": client_info.client_name,
                "client_id": client_info.client_id,
                "redirect_uri": auth_params.get("redirect_uri"),
                "scopes": auth_params.get("scope", "").split(),
                "error": error,
                "show_mfa": show_mfa,
                "username": username,
                "password": password,
                "action": "login"
            }
        ).body.decode()
    
    async def render_consent_page(
        self,
        request: Request,
        client_info: OAuthClientInformationFull, 
        auth_params: Dict[str, Any],
        username: str,
        scopes: List[str]
    ) -> str:
        """Render the consent/authorization page."""
        return self.templates.TemplateResponse(
            "authorize.html",
            {
                "request": request,
                "client_name": client_info.client_name,
                "client_id": client_info.client_id,
                "redirect_uri": auth_params.get("redirect_uri"),
                "scopes": scopes,
                "username": username,
                "action": "consent",
                "show_consent": True
            }
        ).body.decode()
    
    async def render_error_page(
        self,
        request: Request,
        title: str,
        message: str
    ) -> str:
        """Render an error page."""
        return self.templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "title": title,
                "message": message
            }
        ).body.decode()