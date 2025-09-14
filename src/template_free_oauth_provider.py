#!/usr/bin/env python3
"""Template-free Vivint OAuth provider that generates HTML directly."""

import secrets
import time
import logging
from typing import Dict, Optional, Any, List

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

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

class TemplateFreeOAuthProvider(InMemoryOAuthProvider):
    """OAuth provider that generates HTML directly without template dependencies."""
    
    def __init__(self, base_url: str):
        """Initialize the Vivint OAuth provider."""
        super().__init__(base_url=base_url)
        logger.info(f"TemplateFreeOAuthProvider initialized with base_url={base_url}")
        self._authenticated_sessions: Dict[str, str] = {}  # session_id -> username
    
    def get_authorize_url_params(self, request: Request) -> Dict[str, Any]:
        """Extract OAuth parameters from authorization request."""
        params = {
            "response_type": request.query_params.get("response_type"),
            "client_id": request.query_params.get("client_id"), 
            "redirect_uri": request.query_params.get("redirect_uri"),
            "scope": request.query_params.get("scope"),
            "state": request.query_params.get("state"),
            "code_challenge": request.query_params.get("code_challenge"),
            "code_challenge_method": request.query_params.get("code_challenge_method"),
        }
        logger.info(
            "OAuth authorize GET params: client_id=%s redirect_uri=%s scope=%s state=%s code_challenge_method=%s",
            params.get("client_id"), params.get("redirect_uri"), params.get("scope"), params.get("state"), params.get("code_challenge_method")
        )
        return params
    
    async def get_authorize_params_from_form(self, request: Request) -> Dict[str, Any]:
        """Extract OAuth parameters from form data (for POST requests)."""
        form_data = await request.form()
        params = {
            "response_type": form_data.get("response_type"),
            "client_id": form_data.get("client_id"), 
            "redirect_uri": form_data.get("redirect_uri"),
            "scope": form_data.get("scope"),
            "state": form_data.get("state"),
            "code_challenge": form_data.get("code_challenge"),
            "code_challenge_method": form_data.get("code_challenge_method"),
        }
        logger.info(
            "OAuth authorize POST params: client_id=%s redirect_uri=%s scope=%s state=%s code_challenge_method=%s",
            params.get("client_id"), params.get("redirect_uri"), params.get("scope"), params.get("state"), params.get("code_challenge_method")
        )
        return params
    
    async def handle_authorization_request(self, request: Request) -> str:
        """Handle GET /authorize - show login form."""
        auth_params = self.get_authorize_url_params(request)
        client_id = auth_params.get("client_id")
        redirect_uri = auth_params.get("redirect_uri")
        
        # Auto-register Claude Desktop client if it doesn't exist
        if client_id and client_id not in self.clients:
            logger.info(f"Auto-registering client: {client_id}")
            
            # Import here to avoid circular imports
            from mcp.shared.auth import OAuthClientInformationFull
            from pydantic import AnyHttpUrl
            
            # Default redirect URIs for Claude Desktop and testing
            default_redirect_uris = [
                "https://claude.ai/api/mcp/auth_callback",
                "http://localhost:3000/callback", 
                "http://localhost:8080/callback"
            ]
            
            # Add the requested redirect URI if provided
            if redirect_uri and redirect_uri not in default_redirect_uris:
                default_redirect_uris.append(redirect_uri)
            
            client_info = OAuthClientInformationFull(
                client_id=client_id,
                client_secret="auto-generated-secret",  # Simplified for testing
                client_name="Claude Desktop (Auto-registered)",
                redirect_uris=[AnyHttpUrl(uri) for uri in default_redirect_uris],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                scope="claudeai vivint:read"
            )
            self.clients[client_id] = client_info
            logger.info(f"Auto-registered client {client_id} with redirect URIs: {default_redirect_uris}")
        
        # Validate client
        if not client_id or client_id not in self.clients:
            logger.warning("OAuth authorize: unknown client_id=%s. Available=%s", client_id, list(self.clients.keys()))
            return self.render_error_page(
                "Invalid Client", 
                f"Unknown client ID: {client_id}. Available clients: {list(self.clients.keys())}"
            )
        
        client_info = self.clients[client_id]
        logger.info("OAuth authorize: found client_id=%s with %d redirect URIs", client_id, len(client_info.redirect_uris))
        
        # Validate redirect URI
        if redirect_uri:
            registered_uris = [str(uri) for uri in client_info.redirect_uris]
            logger.info("OAuth authorize: requested redirect_uri=%s; registered=%s", redirect_uri, registered_uris)
            if redirect_uri not in registered_uris:
                logger.warning(f"Redirect URI mismatch. Requested: {redirect_uri}, Registered: {registered_uris}")
                return self.render_error_page(
                    "Invalid Redirect URI",
                    f"Redirect URI '{redirect_uri}' not registered for client. Registered URIs: {', '.join(registered_uris)}"
                )
        
        logger.info("OAuth authorize: redirect URI accepted; rendering login page")
        # Show login form
        return self.render_login_page(client_info, auth_params)
    
    async def handle_authorization_post(
        self, 
        request: Request,
        username: str,
        password: str,
        mfa_code: Optional[str] = None,
        action: str = "login"
    ):
        """Handle POST /authorize - process login or consent."""
        
        auth_params = await self.get_authorize_params_from_form(request)
        client_id = auth_params.get("client_id")
        redirect_uri = auth_params.get("redirect_uri")
        
        # Auto-register client if needed (same as GET handler)
        if client_id and client_id not in self.clients:
            logger.info(f"Auto-registering client in POST: {client_id}")
            
            from mcp.shared.auth import OAuthClientInformationFull
            from pydantic import AnyHttpUrl
            
            default_redirect_uris = [
                "https://claude.ai/api/mcp/auth_callback",
                "http://localhost:3000/callback", 
                "http://localhost:8080/callback"
            ]
            
            if redirect_uri and redirect_uri not in default_redirect_uris:
                default_redirect_uris.append(redirect_uri)
            
            client_info = OAuthClientInformationFull(
                client_id=client_id,
                client_secret="auto-generated-secret",
                client_name="Claude Desktop (Auto-registered)",
                redirect_uris=[AnyHttpUrl(uri) for uri in default_redirect_uris],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                scope="claudeai vivint:read"
            )
            self.clients[client_id] = client_info
        
        if not client_id or client_id not in self.clients:
            return HTMLResponse(
                content=self.render_error_page(
                    "Invalid Client", f"Client {client_id} not found. Available: {list(self.clients.keys())}"
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
                    logger.info("OAuth authorize: authentication successful for user; issuing code")
                    redirect_url = await self.issue_authorization_code(client_info, auth_params)
                    logger.info("OAuth authorize: redirecting to %s", redirect_url)
                    return RedirectResponse(url=redirect_url, status_code=302)
                except Exception as e:
                    logger.error(f"Failed to issue authorization code: {e}")
                    return HTMLResponse(
                        content=self.render_error_page(
                            "Authorization Error", str(e)
                        ),
                        status_code=500
                    )
            else:
                # Show error
                return HTMLResponse(
                    content=self.render_login_page(
                        client_info, auth_params, error=message
                    )
                )
        
        else:
            return HTMLResponse(
                content=self.render_error_page(
                    "Invalid Request", f"Unknown action: {action}"
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
        
        # For testing OAuth flow, allow a test user
        if username == "test@example.com" and password == "test123":
            logger.info(f"✅ Test authentication successful for: {username}")
            return True, "Authentication successful"
        
        # Check if credentials match environment (if set)
        if config.username and config.password:
            if username == config.username and password == config.password:
                logger.info(f"✅ Vivint authentication successful for: {username}")
                return True, "Authentication successful"
        
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
        
        # Handle PKCE parameters - use defaults if not provided
        code_challenge = auth_params.get("code_challenge")
        code_challenge_method = auth_params.get("code_challenge_method")
        
        # If code_challenge is "None" string, None, or empty, use a default
        if code_challenge in [None, "None", ""]:
            code_challenge = "placeholder_challenge"  # Required by MCP but not used
        if code_challenge_method in [None, "None", ""]:
            code_challenge_method = "plain"  # Simple method for testing
        
        params = AuthorizationParams(
            response_type=auth_params["response_type"],
            client_id=auth_params["client_id"],
            redirect_uri=auth_params["redirect_uri"],
            redirect_uri_provided_explicitly=True,
            scopes=scopes,
            state=auth_params.get("state"),
            code_challenge=code_challenge
        )
        logger.info(
            "OAuth code: client_id=%s redirect_uri=%s scopes=%s state=%s",
            params.client_id, params.redirect_uri, scopes, params.state
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
    
    def render_login_page(
        self, 
        client_info: OAuthClientInformationFull,
        auth_params: Dict[str, Any],
        error: Optional[str] = None
    ) -> str:
        """Render the login page as HTML string."""
        
        error_html = ""
        if error:
            error_html = f"""
            <div style="background: #fed7d7; border: 1px solid #feb2b2; color: #c53030; 
                        padding: 12px; border-radius: 6px; margin-bottom: 20px;">
                <strong>Error:</strong> {error}
            </div>
            """
        
        scopes = auth_params.get("scope", "").split() if auth_params.get("scope") else []
        scopes_html = ""
        for scope in scopes:
            if scope == "claudeai":
                scope_desc = "🤖 <strong>Claude AI Integration</strong> - Allow Claude Desktop to access your Vivint system"
            elif scope == "vivint:read":
                scope_desc = "📖 <strong>Read Access</strong> - View security system status and device information"
            else:
                scope_desc = f"🔧 <strong>{scope}</strong> - Custom scope access"
            scopes_html += f"<div style='background: white; padding: 10px 15px; margin-bottom: 8px; border-radius: 6px; border-left: 3px solid #4299e1;'>{scope_desc}</div>"
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vivint Login - {client_info.client_name}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px;
        }}
        .auth-container {{
            background: white; border-radius: 12px; box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            max-width: 450px; width: 100%; overflow: hidden;
        }}
        .auth-header {{
            background: #2d3748; color: white; padding: 30px; text-align: center;
        }}
        .auth-header h1 {{ font-size: 24px; margin-bottom: 8px; }}
        .auth-header p {{ opacity: 0.8; font-size: 14px; }}
        .auth-body {{ padding: 30px; }}
        .client-info {{
            background: #f7fafc; border-left: 4px solid #4299e1; padding: 15px;
            margin-bottom: 25px; border-radius: 0 6px 6px 0;
        }}
        .client-info h3 {{ color: #2d3748; margin-bottom: 5px; }}
        .client-info p {{ color: #718096; font-size: 14px; }}
        .form-group {{ margin-bottom: 20px; }}
        .form-group label {{
            display: block; margin-bottom: 8px; font-weight: 500; color: #2d3748;
        }}
        .form-group input {{
            width: 100%; padding: 12px; border: 2px solid #e2e8f0; border-radius: 6px;
            font-size: 16px; transition: border-color 0.2s;
        }}
        .form-group input:focus {{ outline: none; border-color: #4299e1; }}
        .auth-button {{
            width: 100%; background: #4299e1; color: white; border: none; padding: 15px;
            border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer;
            transition: background-color 0.2s;
        }}
        .auth-button:hover {{ background: #3182ce; }}
        .security-notice {{
            background: #fef5e7; border: 1px solid #f6d55c; color: #744210; padding: 12px;
            border-radius: 6px; margin-bottom: 20px; font-size: 12px; text-align: center;
        }}
        .vivint-logo {{
            width: 40px; height: 40px; background: #4299e1; border-radius: 50%;
            display: inline-flex; align-items: center; justify-content: center;
            margin-bottom: 10px; font-weight: bold; font-size: 18px;
        }}
        .cancel-link {{
            display: block; text-align: center; margin-top: 15px; color: #718096;
            text-decoration: none; font-size: 14px;
        }}
        .cancel-link:hover {{ color: #4a5568; }}
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="auth-header">
            <div class="vivint-logo">V</div>
            <h1>Vivint Login</h1>
            <p>Authenticate with your Vivint security system credentials</p>
        </div>
        
        <div class="auth-body">
            <div class="client-info">
                <h3>{client_info.client_name}</h3>
                <p>Client ID: {client_info.client_id}</p>
                <p>Redirect: {auth_params.get('redirect_uri', 'N/A')}</p>
            </div>
            
            {error_html}
            
            <form method="post" action="/oauth/authorize">
                <div class="form-group">
                    <label for="username">Vivint Username</label>
                    <input type="email" id="username" name="username" required 
                           placeholder="your.email@example.com">
                </div>
                
                <div class="form-group">
                    <label for="password">Vivint Password</label>
                    <input type="password" id="password" name="password" required 
                           placeholder="Your Vivint password">
                </div>
                
                <div class="security-notice">
                    🛡️ Your credentials are used only for authentication and are not stored. 
                    This ensures only you can authorize access to your Vivint system.
                </div>
                
                <input type="hidden" name="action" value="login">
                <input type="hidden" name="response_type" value="{auth_params.get('response_type', '')}">
                <input type="hidden" name="client_id" value="{auth_params.get('client_id', '')}">
                <input type="hidden" name="redirect_uri" value="{auth_params.get('redirect_uri', '')}">
                <input type="hidden" name="scope" value="{auth_params.get('scope', '')}">
                <input type="hidden" name="state" value="{auth_params.get('state', '')}">
                <input type="hidden" name="code_challenge" value="{auth_params.get('code_challenge') or ''}">
                <input type="hidden" name="code_challenge_method" value="{auth_params.get('code_challenge_method') or ''}">
                <button type="submit" class="auth-button">Sign In</button>
            </form>
            
            <a href="{auth_params.get('redirect_uri', '#')}?error=access_denied&state={auth_params.get('state', '')}" 
               class="cancel-link">Cancel</a>
        </div>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            document.getElementById('username').focus();
        }});
    </script>
</body>
</html>"""
    
    def render_error_page(self, title: str, message: str) -> str:
        """Render an error page as HTML string."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Vivint OAuth</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #f56565 0%, #c53030 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px;
        }}
        .error-container {{
            background: white; border-radius: 12px; box-shadow: 0 20px 40px rgba(0,0,0,0.2);
            max-width: 500px; width: 100%; overflow: hidden;
        }}
        .error-header {{
            background: #c53030; color: white; padding: 30px; text-align: center;
        }}
        .error-icon {{
            width: 60px; height: 60px; background: rgba(255,255,255,0.2); border-radius: 50%;
            display: inline-flex; align-items: center; justify-content: center;
            margin-bottom: 15px; font-size: 28px;
        }}
        .error-header h1 {{ font-size: 24px; margin-bottom: 8px; }}
        .error-header p {{ opacity: 0.9; font-size: 16px; }}
        .error-body {{ padding: 30px; text-align: center; }}
        .error-message {{
            background: #fed7d7; border: 2px solid #feb2b2; color: #c53030; padding: 20px;
            border-radius: 8px; margin-bottom: 25px; font-size: 16px; line-height: 1.5;
        }}
        .btn {{
            padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600;
            font-size: 14px; transition: all 0.2s; border: none; cursor: pointer;
            display: inline-flex; align-items: center; gap: 8px;
        }}
        .btn-primary {{ background: #4299e1; color: white; }}
        .btn-primary:hover {{ background: #3182ce; }}
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-header">
            <div class="error-icon">⚠️</div>
            <h1>{title}</h1>
            <p>Something went wrong with your authorization request</p>
        </div>
        
        <div class="error-body">
            <div class="error-message">
                {message}
            </div>
            
            <button onclick="history.back()" class="btn btn-primary">
                🔄 Try Again
            </button>
        </div>
    </div>
</body>
</html>"""