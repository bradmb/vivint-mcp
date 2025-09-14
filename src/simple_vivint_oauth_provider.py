#!/usr/bin/env python3
"""Simplified Vivint OAuth provider for initial testing."""

import secrets
import time
import logging
import os
from typing import Dict, Optional, Any, List

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

class SimpleVivintOAuthProvider(InMemoryOAuthProvider):
    """Simplified OAuth provider that requires Vivint authentication."""
    
    def __init__(self, base_url: str, templates_dir: Optional[str] = None):
        """Initialize the Vivint OAuth provider."""
        super().__init__(base_url=base_url)
        
        # Default to templates directory relative to this file
        if templates_dir is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            templates_dir = os.path.join(current_dir, "templates")
        
        # Ensure templates directory exists
        if not os.path.exists(templates_dir):
            raise ValueError(f"Templates directory does not exist: {templates_dir}")
            
        self.templates = Jinja2Templates(directory=templates_dir)
        self._authenticated_sessions: Dict[str, str] = {}  # session_id -> username
    
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
        
        # For now, just show the login form (no session management yet)
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
        
        auth_params = self.get_authorize_url_params(request)
        client_id = auth_params.get("client_id")
        
        if not client_id or client_id not in self.clients:
            return HTMLResponse(
                content=await self.render_error_page(
                    request, "Invalid Client", f"Client {client_id} not found"
                ),
                status_code=400
            )
        
        client_info = self.clients[client_id]
        
        if action == "login":
            # Authenticate with Vivint
            success, message = await self.authenticate_with_vivint(username, password, mfa_code)
            
            if success:
                # Generate authorization code immediately (simplified flow)
                try:
                    redirect_url = await self.issue_authorization_code(client_info, auth_params)
                    return RedirectResponse(url=redirect_url, status_code=302)
                except Exception as e:
                    logger.error(f"Failed to issue authorization code: {e}")
                    return HTMLResponse(
                        content=await self.render_error_page(
                            request, "Authorization Error", str(e)
                        ),
                        status_code=500
                    )
            else:
                # Show error
                return HTMLResponse(
                    content=await self.render_login_page(
                        request, client_info, auth_params, error=message
                    )
                )
        
        else:
            return HTMLResponse(
                content=await self.render_error_page(
                    request, "Invalid Request", f"Unknown action: {action}"
                ),
                status_code=400
            )
    
    async def authenticate_with_vivint(
        self, 
        username: str, 
        password: str, 
        mfa_code: Optional[str] = None
    ) -> tuple[bool, str]:
        """Simple Vivint authentication check."""
        
        # For initial testing, just check if credentials match environment
        if username == config.username and password == config.password:
            logger.info(f"✅ Vivint authentication successful for: {username}")
            return True, "Authentication successful"
        else:
            logger.warning(f"❌ Vivint authentication failed for: {username}")
            return False, "Invalid Vivint credentials"
    
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
        
        logger.info(f"✅ Issued authorization code for client {client_info.client_id}")
        
        # Build redirect URL
        return construct_redirect_uri(
            str(params.redirect_uri), 
            code=auth_code_value, 
            state=params.state
        )
    
    async def render_login_page(
        self, 
        request: Request, 
        client_info: OAuthClientInformationFull,
        auth_params: Dict[str, Any],
        error: Optional[str] = None
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
                "show_mfa": False,
                "username": "",
                "password": "",
                "action": "login",
                "show_consent": False
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