#!/usr/bin/env python3
"""Vivint Security System MCP Server.

Provides read-only access to Vivint security system data through MCP tools.
"""

import os
import sys
import asyncio
import logging
import secrets
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from fastmcp import FastMCP

# Import authentication
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider

# Import our custom persistent OAuth provider
try:
    from .persistent_oauth_provider import PersistentOAuthProvider
except ImportError:
    # Handle case when run directly
    from persistent_oauth_provider import PersistentOAuthProvider
from mcp.shared.auth import OAuthClientInformationFull
from mcp.server.auth.provider import AuthorizationParams
from pydantic import AnyHttpUrl
import json

# Import Starlette for OAuth routes
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

# Import our custom modules
try:
    from .config import config
    from .vivint_client import vivint_client, VivintClientError, VivintMfaRequiredError, VivintAuthenticationError
    from .template_free_oauth_provider import TemplateFreeOAuthProvider
except ImportError:
    # Handle case when run directly
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from config import config
    from vivint_client import vivint_client, VivintClientError, VivintMfaRequiredError, VivintAuthenticationError
    from template_free_oauth_provider import TemplateFreeOAuthProvider

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Authentication setup
def setup_authentication():
    """Setup authentication provider based on configuration."""
    if not config.auth_enabled:
        logger.info("Authentication disabled")
        return None
    
    logger.info(f"Setting up {config.auth_type.upper()} authentication")
    
    try:
        if config.auth_type == "jwt":
            if config.jwt_algorithm.startswith("HS"):
                # HMAC-based JWT (symmetric key)
                if not config.auth_secret:
                    raise ValueError("AUTH_SECRET required for HMAC JWT algorithms")
                
                auth = JWTVerifier(
                    public_key=config.auth_secret,
                    algorithm=config.jwt_algorithm,
                    issuer=config.jwt_issuer,
                    audience=config.jwt_audience,
                    base_url=f"http://{config.host}:{config.port}"
                )
                logger.info(f"✅ HMAC JWT authentication configured ({config.jwt_algorithm})")
                
            elif config.jwt_algorithm.startswith("RS"):
                # RSA-based JWT (asymmetric key)
                if not config.jwt_public_key:
                    raise ValueError("JWT_PUBLIC_KEY required for RSA JWT algorithms")
                
                auth = JWTVerifier(
                    public_key=config.jwt_public_key,
                    algorithm=config.jwt_algorithm,
                    issuer=config.jwt_issuer,
                    audience=config.jwt_audience,
                    base_url=f"http://{config.host}:{config.port}"
                )
                logger.info(f"✅ RSA JWT authentication configured ({config.jwt_algorithm})")
            
            else:
                raise ValueError(f"Unsupported JWT algorithm: {config.jwt_algorithm}")
                
            return auth
            
        elif config.auth_type == "oauth":
            # Set up OAuth provider using FastMCP's built-in InMemoryOAuthProvider
            # Use Cloudflare tunnel URL if configured, otherwise use localhost
            if config.cloudflare_tunnel_url:
                base_url = config.cloudflare_tunnel_url
                logger.info(f"Using Cloudflare tunnel URL: {base_url}")
            elif config.is_development:
                base_url = f"https://localhost:{config.port}"
            else:
                base_url = f"https://{config.host}:{config.port}"
            
            # Create a custom OAuth provider that extends PersistentOAuthProvider
            # This ensures /authorize works with FastMCP's built-in routing and persists tokens
            class VivintOAuthProvider(PersistentOAuthProvider):
                def __init__(self, base_url: str):
                    super().__init__(base_url=base_url)
                    # Store pending authorization requests
                    self.pending_auth = {}
                    # Store authenticated sessions (in production, use a proper session store)
                    self.authenticated_sessions = {}
                
                async def register_client(self, client_info: OAuthClientInformationFull) -> None:
                    """Register a client with optional restriction for new clients."""
                    # Check if new client registration is disabled
                    if config.oauth_disable_new_clients:
                        # Check if this is an existing client
                        if client_info.client_id not in self.clients:
                            logger.warning(f"🚫 New client registration blocked: {client_info.client_id}")
                            raise ValueError("New client registration is currently disabled. Only existing clients can authenticate.")
                        else:
                            logger.info(f"✅ Existing client allowed: {client_info.client_id}")
                    
                    # Proceed with registration (existing clients can re-register)
                    await super().register_client(client_info)
                    logger.info(f"📝 Client registered: {client_info.client_id}")
                
                async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
                    """FastMCP-compatible OAuth authorization with user login."""
                    logger.info(f"🔍 VivintOAuthProvider.authorize() called for client {client.client_id}")
                    logger.info(f"🔍 Redirect URI requested: {params.redirect_uri}")
                    
                    # Check if user has an authenticated session
                    # For now, we'll check if environment credentials are available (proof of concept)
                    # In a full implementation, you'd check for a session cookie or token
                    
                    session_id = None  # In real implementation, extract from request cookies
                    
                    if session_id and session_id in self.authenticated_sessions:
                        # User is already authenticated, issue authorization code
                        logger.info("✅ User session authenticated, issuing authorization code")
                        return await self._issue_authorization_code(client, params)
                    
                    # For testing purposes, you can uncomment this to skip login form:
                    # if self._validate_environment_credentials():
                    #     logger.info("✅ Environment credentials validated, issuing authorization code")
                    #     return await self._issue_authorization_code(client, params)
                    
                    # User not authenticated - redirect to login page
                    logger.info("❌ User not authenticated, redirecting to login page")
                    
                    # Generate a temporary auth request ID
                    auth_request_id = secrets.token_urlsafe(32)
                    
                    # Store the authorization request parameters
                    self.pending_auth[auth_request_id] = {
                        'client': client,
                        'params': params,
                        'created_at': time.time()
                    }
                    
                    # FastMCP expects this method to return a redirect URL
                    # We redirect to our custom login page with the auth request ID
                    login_url = f"{base_url}/oauth/login?request_id={auth_request_id}"
                    logger.info(f"🔗 Redirecting to login page: {login_url}")
                    return login_url
                
                def _validate_environment_credentials(self) -> bool:
                    """Validate that required Vivint credentials are present in environment."""
                    try:
                        # Check if credentials exist in config
                        if not (config.username and 
                               config.password and 
                               len(config.username.strip()) > 0 and 
                               len(config.password.strip()) > 0):
                            logger.debug("❌ Vivint credentials not found in environment")
                            return False
                        
                        logger.debug("✅ Vivint credentials found in environment")
                        return True
                        
                    except Exception as e:
                        logger.error(f"Error validating credentials: {e}")
                        return False
                
                def _validate_user_credentials(self, username: str, password: str) -> bool:
                    """Validate user-provided credentials against environment."""
                    try:
                        # Validate against environment credentials
                        return (username == config.username and password == config.password)
                        
                    except Exception as e:
                        logger.error(f"Error validating user credentials: {e}")
                        return False
                
                async def _issue_authorization_code(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
                    """Issue an authorization code after successful authentication."""
                    from mcp.server.auth.provider import AuthorizationCode, construct_redirect_uri
                    
                    # Generate authorization code
                    auth_code_value = f"vivint_auth_{secrets.token_hex(32)}"
                    expires_at = time.time() + 300  # 5 minute expiry
                    
                    # Store authorization code
                    auth_code = AuthorizationCode(
                        code=auth_code_value,
                        client_id=client.client_id,
                        redirect_uri=params.redirect_uri,
                        redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                        scopes=params.scopes or [],
                        expires_at=expires_at,
                        code_challenge=params.code_challenge,
                    )
                    self.auth_codes[auth_code_value] = auth_code
                    
                    logger.info(f"✅ Issued authorization code for client {client.client_id}")
                    
                    # Build redirect URL
                    return construct_redirect_uri(
                        str(params.redirect_uri), 
                        code=auth_code_value, 
                        state=params.state
                    )
            
            oauth_provider = VivintOAuthProvider(base_url=base_url)
            
            # Register the configured client if credentials exist
            if config.oauth_client_id and config.oauth_client_secret:
                # Convert configured redirect URIs to AnyHttpUrl objects
                # Store redirect URIs as strings to match HTTP request parameter types
                redirect_uris = [uri.strip() for uri in config.oauth_redirect_uris if uri.strip()]
                
                client_info = OAuthClientInformationFull(
                    client_id=config.oauth_client_id,
                    client_secret=config.oauth_client_secret,
                    client_name="Claude Desktop",
                    redirect_uris=redirect_uris,
                    grant_types=["authorization_code", "refresh_token"],
                    response_types=["code"],
                    scope="claudeai vivint:read"  # Support both claudeai and custom scopes
                )
                
                # Register the client directly (register_client is async, we're in sync context)
                # This is exactly what InMemoryOAuthProvider.register_client() does internally
                oauth_provider.clients[config.oauth_client_id] = client_info
                logger.info(f"✅ Vivint OAuth client registered with client ID: {config.oauth_client_id}")
                
                logger.info(f"✅ Vivint OAuth authentication configured with client ID: {config.oauth_client_id}")
                logger.info(f"OAuth redirect URIs from config: {config.oauth_redirect_uris}")
                
                # Debug: verify client is actually registered
                logger.info(f"🔍 Provider clients after registration: {list(oauth_provider.clients.keys())}")
                if config.oauth_client_id in oauth_provider.clients:
                    registered_client = oauth_provider.clients[config.oauth_client_id]
                    logger.info(f"🔍 Registered client redirect URIs: {[str(uri) for uri in registered_client.redirect_uris]}")
                    logger.info(f"🔍 Redirect URI types: {[type(uri).__name__ for uri in registered_client.redirect_uris]}")
                    
                    # Test exact matching against Claude's callback
                    test_uri = "https://claude.ai/api/mcp/auth_callback"
                    logger.info(f"🔍 Testing exact match for: '{test_uri}'")
                    for i, uri in enumerate(registered_client.redirect_uris):
                        logger.info(f"🔍   [{i}] '{uri}' == '{test_uri}': {str(uri) == test_uri}")
                        logger.info(f"🔍   [{i}] repr: {repr(str(uri))} vs {repr(test_uri)}")
                    
                    # Test the EXACT validation that's failing: "if redirect_uri not in self.redirect_uris"
                    logger.info(f"🔍 Testing 'in' operator (the actual validation):")
                    logger.info(f"🔍   '{test_uri}' in redirect_uris: {test_uri in registered_client.redirect_uris}")
                    
                    # Let's also try with AnyHttpUrl objects
                    try:
                        from pydantic import AnyHttpUrl as PydanticAnyHttpUrl
                        test_url_obj = PydanticAnyHttpUrl(test_uri)
                        logger.info(f"🔍   AnyHttpUrl('{test_uri}') in redirect_uris: {test_url_obj in registered_client.redirect_uris}")
                    except Exception as e:
                        logger.warning(f"Could not test AnyHttpUrl object: {e}")
                else:
                    logger.error(f"❌ Client {config.oauth_client_id} NOT found in provider after registration!")
                
                return oauth_provider
            else:
                raise ValueError("OAuth client credentials not found - run: python src/generate_oauth_credentials.py")
            
        else:
            raise ValueError(f"Unsupported auth type: {config.auth_type}")
            
    except Exception as e:
        logger.error(f"❌ Authentication setup failed: {str(e)}")
        import traceback
        logger.error(f"Full error traceback: {traceback.format_exc()}")
        if config.is_production:
            raise  # Fail hard in production
        else:
            logger.warning("⚠️ Continuing without authentication in development mode")
            return None

# Setup authentication
auth_provider = setup_authentication()

# Initialize MCP server with authentication
mcp = FastMCP("Vivint Security System MCP Server", auth=auth_provider)

# Add custom OAuth login routes if using OAuth provider
if auth_provider and hasattr(auth_provider, 'pending_auth'):
    from starlette.responses import HTMLResponse, RedirectResponse
    
    @mcp.custom_route("/oauth/login", methods=["GET", "POST"])
    async def oauth_login_handler(request):
        """Handle OAuth login form display and submission."""
        
        if request.method == "GET":
            # Show login form
            request_id = request.query_params.get("request_id")
            if not request_id or request_id not in auth_provider.pending_auth:
                return HTMLResponse("Invalid or expired authorization request", status_code=400)
            
            # Check if login is locked out
            locked_out, seconds_remaining = is_login_locked_out()
            if locked_out:
                minutes_remaining = seconds_remaining // 60
                seconds_part = seconds_remaining % 60
                time_display = f"{minutes_remaining}m {seconds_part}s" if minutes_remaining > 0 else f"{seconds_part}s"
                
                lockout_html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Temporarily Locked</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
                        .error {{ color: red; text-align: center; }}
                        .lockout {{ background: #ffe6e6; border: 1px solid #ff9999; padding: 20px; border-radius: 8px; }}
                        .timer {{ font-size: 24px; font-weight: bold; color: #d00; }}
                    </style>
                    <meta http-equiv="refresh" content="10">
                </head>
                <body>
                    <div class="lockout">
                        <h2>🔒 Login Temporarily Locked</h2>
                        <p>Too many failed login attempts have been detected.</p>
                        <p>Please wait <span class="timer">{time_display}</span> before trying again.</p>
                        <p><small>This page will refresh automatically every 10 seconds.</small></p>
                    </div>
                </body>
                </html>
                """
                return HTMLResponse(lockout_html, status_code=429)
            
            # Create simple login form HTML
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Vivint MCP Server - Login</title>
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
                    .form-group {{ margin-bottom: 15px; }}
                    label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
                    input[type="text"], input[type="password"] {{ width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
                    button {{ background-color: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }}
                    button:hover {{ background-color: #005a87; }}
                    .error {{ color: red; margin-top: 10px; }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h2>🏠 Vivint MCP Server</h2>
                    <p>Please enter your Vivint credentials to authorize access</p>
                </div>
                <form method="post" action="/oauth/login">
                    <input type="hidden" name="request_id" value="{request_id}">
                    <div class="form-group">
                        <label for="username">Vivint Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Vivint Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit">Login & Authorize</button>
                </form>
                <p style="font-size: 12px; color: #666; margin-top: 20px; text-align: center;">
                    Your credentials are used only to verify your Vivint account access.
                </p>
            </body>
            </html>
            """
            return HTMLResponse(html_content)
        
        elif request.method == "POST":
            # Handle login form submission
            form_data = await request.form()
            request_id = form_data.get("request_id")
            username = form_data.get("username")
            password = form_data.get("password")
            
            if not request_id or request_id not in auth_provider.pending_auth:
                return HTMLResponse("Invalid or expired authorization request", status_code=400)
            
            # Check if login is locked out
            locked_out, seconds_remaining = is_login_locked_out()
            if locked_out:
                minutes_remaining = seconds_remaining // 60
                seconds_part = seconds_remaining % 60
                time_display = f"{minutes_remaining}m {seconds_part}s" if minutes_remaining > 0 else f"{seconds_part}s"
                
                lockout_html = f"""
                <!DOCTYPE html>
                <html>
                <head><title>Login Locked</title><style>body{{font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px;}} .error{{color: red; text-align: center;}} .lockout{{background: #ffe6e6; border: 1px solid #ff9999; padding: 20px; border-radius: 8px;}} .timer{{font-size: 18px; font-weight: bold; color: #d00;}}</style></head>
                <body>
                    <div class="lockout">
                        <h2>🔒 Login Locked</h2>
                        <p>Authentication is temporarily locked due to failed attempts.</p>
                        <p>Time remaining: <span class="timer">{time_display}</span></p>
                    </div>
                </body>
                </html>
                """
                return HTMLResponse(lockout_html, status_code=429)
            
            # Validate credentials
            if not auth_provider._validate_user_credentials(username, password):
                # Record failed login attempt and check for lockout
                lockout_triggered = record_failed_login()
                
                if lockout_triggered:
                    # Return lockout page
                    lockout_html = f"""
                    <!DOCTYPE html>
                    <html>
                    <head><title>Login Locked</title><style>body{{font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px;}} .error{{color: red; text-align: center;}} .lockout{{background: #ffe6e6; border: 1px solid #ff9999; padding: 20px; border-radius: 8px;}} .timer{{font-size: 18px; font-weight: bold; color: #d00;}}</style></head>
                    <body>
                        <div class="lockout">
                            <h2>🔒 Login Locked</h2>
                            <p>Too many failed login attempts. Authentication is now locked for {config.rate_limit_lockout_minutes} minutes.</p>
                            <p><strong>This affects all users until the lockout expires.</strong></p>
                        </div>
                    </body>
                    </html>
                    """
                    return HTMLResponse(lockout_html, status_code=429)
                else:
                    # Return regular error page
                    html_content = f"""
                    <!DOCTYPE html>
                    <html>
                    <head><title>Login Error</title><style>body{{font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px;}}</style></head>
                    <body>
                        <h2>❌ Authentication Failed</h2>
                        <p>Invalid Vivint credentials. Please check your username and password.</p>
                        <p><small>⚠️ Warning: Failed attempts may result in temporary lockout.</small></p>
                        <a href="/oauth/login?request_id={request_id}">← Try Again</a>
                    </body>
                    </html>
                    """
                    return HTMLResponse(html_content, status_code=401)
            
            # Login successful - reset rate limiting
            reset_login_attempts()
            
            # Get stored authorization request
            auth_request = auth_provider.pending_auth.pop(request_id)
            client = auth_request['client']
            params = auth_request['params']
            
            # Issue authorization code
            redirect_url = await auth_provider._issue_authorization_code(client, params)
            
            # Redirect to client with authorization code
            return RedirectResponse(redirect_url, status_code=302)

# Session middleware will be added when we create custom routes below

# Global connection state
_connection_initialized = False

# Rate limiting state (in-memory)
_login_lockout_until = 0  # Timestamp when lockout expires
_failed_login_count = 0   # Counter for failed login attempts

def is_login_locked_out() -> tuple[bool, int]:
    """Check if login is currently locked out.
    
    Returns:
        tuple: (is_locked_out, seconds_remaining)
    """
    if not config.rate_limit_enabled:
        return False, 0
    
    current_time = time.time()
    if current_time < _login_lockout_until:
        seconds_remaining = int(_login_lockout_until - current_time)
        return True, seconds_remaining
    return False, 0

def record_failed_login() -> bool:
    """Record a failed login attempt and check if lockout should be triggered.
    
    Returns:
        bool: True if lockout was triggered, False otherwise
    """
    global _failed_login_count, _login_lockout_until
    
    if not config.rate_limit_enabled:
        return False
    
    _failed_login_count += 1
    logger.warning(f"🚨 Failed login attempt #{_failed_login_count}")
    
    if _failed_login_count >= config.rate_limit_max_attempts:
        lockout_duration = config.rate_limit_lockout_minutes * 60  # Convert to seconds
        _login_lockout_until = time.time() + lockout_duration
        logger.error(f"🔒 LOGIN LOCKOUT TRIGGERED - Locked for {config.rate_limit_lockout_minutes} minutes")
        return True
    
    return False

def reset_login_attempts():
    """Reset failed login counter after successful login."""
    global _failed_login_count, _login_lockout_until
    
    if _failed_login_count > 0:
        logger.info("✅ Login successful - resetting failed attempt counter")
        _failed_login_count = 0
        _login_lockout_until = 0

async def ensure_vivint_connection():
    """Ensure Vivint connection is established."""
    global _connection_initialized
    
    if not _connection_initialized:
        try:
            await vivint_client.connect()
            _connection_initialized = True
            logger.info("Vivint connection established")
        except VivintMfaRequiredError as e:
            logger.error(f"MFA required for Vivint connection: {str(e)}")
            raise ValueError(
                f"MFA authentication required: {str(e)} "
                "Please set VIVINT_MFA_CODE environment variable with your current 2FA code."
            )
        except VivintAuthenticationError as e:
            logger.error(f"Vivint authentication failed: {str(e)}")
            raise ValueError(f"Authentication failed: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to establish Vivint connection: {str(e)}")
            raise ValueError(f"Connection failed: {str(e)}")

@mcp.tool(description="Get current security system status including armed state, mode, and alerts")
async def get_system_status() -> Dict[str, Any]:
    """Get the current status of the Vivint security system."""
    try:
        await ensure_vivint_connection()
        system_info = await vivint_client.get_system()
        
        # Get system object for more detailed info
        system_obj = next(s for s in vivint_client.client.systems if s.id == system_info["id"])
        
        return {
            "armed": not system_info.get("is_disarmed", True),  # True if not disarmed
            "arm_state": system_info.get("arm_state", "unknown"),
            "is_disarmed": system_info.get("is_disarmed", True),
            "is_armed_stay": system_info.get("is_armed_stay", False),
            "is_armed_away": system_info.get("is_armed_away", False),
            "panel_id": system_info.get("panel_id", system_info["id"]),
            "panel_name": system_info.get("panel_name", system_info["name"]),
            "system_name": system_info["name"],
            "system_id": system_info["id"],
            "panel_count": system_info.get("panel_count", 1),
            "user_count": system_info.get("user_count", 0),
            "is_admin": system_info.get("is_admin", False),
            "timestamp": datetime.now().isoformat()
        }
    except VivintClientError as e:
        logger.error(f"Vivint client error in get_system_status: {str(e)}")
        return {"error": str(e), "timestamp": datetime.now().isoformat()}
    except Exception as e:
        logger.error(f"Unexpected error in get_system_status: {str(e)}")
        return {"error": f"Unexpected error: {str(e)}", "timestamp": datetime.now().isoformat()}

@mcp.tool(description="Get complete inventory of all devices including type, location, and status")
async def get_all_devices() -> List[Dict[str, Any]]:
    """Get comprehensive list of all devices in the system."""
    try:
        await ensure_vivint_connection()
        devices = await vivint_client.get_all_devices()
        
        # Enhance device information
        for device in devices:
            device["timestamp"] = datetime.now().isoformat()
            
            # Add health status
            battery_level = device.get("battery_level")
            if battery_level is not None:
                try:
                    # Convert battery level to int if it's a string
                    battery_int = int(float(str(battery_level))) if battery_level != "None" else None
                    if battery_int is not None:
                        device["battery_level"] = battery_int
                        if battery_int < 20:
                            device["health_status"] = "low_battery"
                        elif battery_int < 50:
                            device["health_status"] = "medium_battery"
                        else:
                            device["health_status"] = "good"
                    else:
                        device["health_status"] = "no_battery"
                except (ValueError, TypeError):
                    device["health_status"] = "battery_unknown"
            else:
                device["health_status"] = "unknown" if not device.get("is_online", True) else "good"
        
        return devices
    except VivintClientError as e:
        logger.error(f"Vivint client error in get_all_devices: {str(e)}")
        return [{"error": str(e), "timestamp": datetime.now().isoformat()}]
    except Exception as e:
        logger.error(f"Unexpected error in get_all_devices: {str(e)}")
        return [{"error": f"Unexpected error: {str(e)}", "timestamp": datetime.now().isoformat()}]

@mcp.tool(description="Get status of security sensors (motion, door/window, glass break, smoke, etc.)")
async def get_security_sensors() -> List[Dict[str, Any]]:
    """Get status of all security-related sensors."""
    try:
        await ensure_vivint_connection()
        all_devices = await vivint_client.get_all_devices()
        
        # Filter for security sensors
        security_types = ['sensor', 'motion', 'door', 'window', 'glass', 'smoke', 'co', 'flood']
        security_sensors = []
        
        for device in all_devices:
            device_type_lower = device["type"].lower()
            if any(sensor_type in device_type_lower for sensor_type in security_types):
                sensor_info = {
                    **device,
                    "sensor_type": device["type"],
                    "triggered": device.get("state", "").lower() in ['triggered', 'open', 'motion', 'alarm'],
                    "bypassed": device.get('bypassed', False),
                    "zone_id": device.get('zone_id', None),
                    "timestamp": datetime.now().isoformat()
                }
                security_sensors.append(sensor_info)
        
        return security_sensors
    except VivintClientError as e:
        logger.error(f"Vivint client error in get_security_sensors: {str(e)}")
        return [{"error": str(e), "timestamp": datetime.now().isoformat()}]
    except Exception as e:
        logger.error(f"Unexpected error in get_security_sensors: {str(e)}")
        return [{"error": f"Unexpected error: {str(e)}", "timestamp": datetime.now().isoformat()}]

@mcp.tool(description="Get status and information about cameras in the system")
async def get_cameras() -> List[Dict[str, Any]]:
    """Get information about all cameras in the system."""
    try:
        await ensure_vivint_connection()
        camera_devices = await vivint_client.get_devices_by_type('camera')
        
        cameras = []
        for device in camera_devices:
            camera_info = {
                **device,
                "recording": device.get('recording', False),
                "motion_detection": device.get('motion_detection_enabled', True),
                "resolution": device.get('resolution', 'Unknown'),
                "has_night_vision": device.get('night_vision', False),
                "rtsp_available": 'rtsp_url' in device,
                "timestamp": datetime.now().isoformat()
            }
            cameras.append(camera_info)
        
        return cameras
    except VivintClientError as e:
        logger.error(f"Vivint client error in get_cameras: {str(e)}")
        return [{"error": str(e), "timestamp": datetime.now().isoformat()}]
    except Exception as e:
        logger.error(f"Unexpected error in get_cameras: {str(e)}")
        return [{"error": f"Unexpected error: {str(e)}", "timestamp": datetime.now().isoformat()}]

@mcp.tool(description="Get status of smart locks including lock state and battery level")
async def get_locks() -> List[Dict[str, Any]]:
    """Get information about all smart locks in the system."""
    try:
        await ensure_vivint_connection()
        lock_devices = await vivint_client.get_devices_by_type('lock')
        
        locks = []
        for device in lock_devices:
            lock_info = {
                **device,
                "locked": device.get("state", "unknown").lower() == 'locked',
                "last_operated_by": device.get('last_operated_by', 'Unknown'),
                "last_operated_at": device.get('last_operated_time', None),
                "auto_lock_enabled": device.get('auto_lock', True),
                "tamper_status": device.get('tamper', 'normal'),
                "timestamp": datetime.now().isoformat()
            }
            locks.append(lock_info)
        
        return locks
    except VivintClientError as e:
        logger.error(f"Vivint client error in get_locks: {str(e)}")
        return [{"error": str(e), "timestamp": datetime.now().isoformat()}]
    except Exception as e:
        logger.error(f"Unexpected error in get_locks: {str(e)}")
        return [{"error": f"Unexpected error: {str(e)}", "timestamp": datetime.now().isoformat()}]

@mcp.tool(description="Get thermostat data including current temperature, settings, and mode")
async def get_thermostats() -> List[Dict[str, Any]]:
    """Get information about all thermostats in the system."""
    try:
        await ensure_vivint_connection()
        thermostat_devices = await vivint_client.get_devices_by_type('thermostat')
        
        thermostats = []
        for device in thermostat_devices:
            thermostat_info = {
                **device,
                "current_temperature": device.get('current_temperature', None),
                "target_temperature": device.get('target_temperature', None),
                "heat_setpoint": device.get('heat_setpoint', None),
                "cool_setpoint": device.get('cool_setpoint', None),
                "mode": device.get('mode', 'unknown'),
                "fan_mode": device.get('fan_mode', 'auto'),
                "humidity": device.get('humidity', None),
                "schedule_active": device.get('schedule_active', False),
                "timestamp": datetime.now().isoformat()
            }
            thermostats.append(thermostat_info)
        
        return thermostats
    except VivintClientError as e:
        logger.error(f"Vivint client error in get_thermostats: {str(e)}")
        return [{"error": str(e), "timestamp": datetime.now().isoformat()}]
    except Exception as e:
        logger.error(f"Unexpected error in get_thermostats: {str(e)}")
        return [{"error": f"Unexpected error: {str(e)}", "timestamp": datetime.now().isoformat()}]

@mcp.tool(description="Get recent system events and activity log from the last 24 hours")
async def get_recent_events(hours: int = 24) -> List[Dict[str, Any]]:
    """Get recent events from the system activity log."""
    try:
        await ensure_vivint_connection()
        
        # Note: This is a placeholder implementation as vivintpy may not have direct event access
        # In a real implementation, you would access the event log through the API
        
        events = []
        
        # Get current system state as an "event"
        system_info = await vivint_client.get_system()
        current_event = {
            "id": f"status_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "type": "system_status",
            "description": f"System is {'disarmed' if system_info.get('is_disarmed', True) else 'armed'} ({system_info.get('arm_state', 'unknown')})",
            "timestamp": datetime.now().isoformat(),
            "device_id": system_info["panel_id"],
            "device_name": "Security Panel"
        }
        events.append(current_event)
        
        # Add recent device state changes (simulated - would need real event API)
        devices = await vivint_client.get_all_devices()
        for device in devices[:5]:  # Limit to recent devices
            if device.get("last_update"):
                event = {
                    "id": f"device_{device['id']}_{device['last_update']}",
                    "type": "device_update",
                    "description": f"{device['name']} state: {device['state']}",
                    "timestamp": device["last_update"] or datetime.now().isoformat(),
                    "device_id": device["id"],
                    "device_name": device["name"]
                }
                events.append(event)
        
        # Sort by timestamp (newest first)
        events.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return events[:50]  # Limit to 50 most recent events
        
    except VivintClientError as e:
        logger.error(f"Vivint client error in get_recent_events: {str(e)}")
        return [{"error": str(e), "timestamp": datetime.now().isoformat()}]
    except Exception as e:
        logger.error(f"Unexpected error in get_recent_events: {str(e)}")
        return [{"error": f"Unexpected error: {str(e)}", "timestamp": datetime.now().isoformat()}]

@mcp.tool(description="Get device health status including battery levels and connectivity issues")
async def get_device_health() -> Dict[str, Any]:
    """Get comprehensive device health status."""
    try:
        await ensure_vivint_connection()
        all_devices = await vivint_client.get_all_devices()
        
        health_summary = {
            "total_devices": len(all_devices),
            "online_devices": 0,
            "offline_devices": 0,
            "low_battery_devices": [],
            "offline_device_list": [],
            "devices_needing_attention": [],
            "timestamp": datetime.now().isoformat()
        }
        
        for device in all_devices:
            # Check online status
            if device.get("online", True):
                health_summary["online_devices"] += 1
            else:
                health_summary["offline_devices"] += 1
                health_summary["offline_device_list"].append({
                    "id": device["id"],
                    "name": device["name"],
                    "type": device["type"],
                    "last_seen": device.get("last_update")
                })
            
            # Check battery levels
            battery_level = device.get("battery_level")
            if battery_level is not None:
                try:
                    battery_int = int(float(str(battery_level))) if str(battery_level).lower() != "none" else None
                    if battery_int is not None and battery_int < 20:
                        health_summary["low_battery_devices"].append({
                            "id": device["id"],
                            "name": device["name"],
                            "type": device["type"],
                            "battery_level": battery_int
                        })
                except (ValueError, TypeError):
                    pass  # Skip invalid battery levels
            
            # Check for devices needing attention
            needs_attention = False
            reasons = []
            
            if not device.get("online", True):
                needs_attention = True
                reasons.append("offline")
            
            try:
                battery_val = device.get("battery_level", 100)
                battery_check = int(float(str(battery_val))) if str(battery_val).lower() != "none" else 100
            except (ValueError, TypeError):
                battery_check = 100
            
            if battery_check < 20:
                needs_attention = True
                reasons.append("low_battery")
            
            if device.get('tamper', False):
                needs_attention = True
                reasons.append("tamper_alert")
            
            if needs_attention:
                health_summary["devices_needing_attention"].append({
                    "id": device["id"],
                    "name": device["name"],
                    "type": device["type"],
                    "reasons": reasons,
                    "battery_level": device.get("battery_level")
                })
        
        # Sort low battery devices by battery level
        health_summary["low_battery_devices"].sort(key=lambda x: x["battery_level"])
        
        return health_summary
        
    except VivintClientError as e:
        logger.error(f"Vivint client error in get_device_health: {str(e)}")
        return {"error": str(e), "timestamp": datetime.now().isoformat()}
    except Exception as e:
        logger.error(f"Unexpected error in get_device_health: {str(e)}")
        return {"error": f"Unexpected error: {str(e)}", "timestamp": datetime.now().isoformat()}

# Debug endpoint to inspect OAuth state
if config.auth_type == "oauth":
    @mcp.custom_route("/debug/oauth", methods=["GET"])
    async def debug_oauth(request: Request):
        """Debug endpoint to inspect registered OAuth clients and redirect URIs."""
        try:
            from starlette.responses import JSONResponse
            
            # Check if debug mode is enabled
            if not config.debug_mode:
                return JSONResponse(
                    {"error": "Debug endpoints are disabled. Set DEBUG_MODE=true in .env to enable."},
                    status_code=403
                )
            
            if not auth_provider or not hasattr(auth_provider, 'clients'):
                return JSONResponse({"error": "No OAuth provider configured"}, status_code=500)
            
            data = {
                "auth_type": config.auth_type,
                "base_url": config.cloudflare_tunnel_url or f"http://{config.host}:{config.port}",
                "clients": [
                    {
                        "client_id": cid,
                        "redirect_uris": [str(u) for u in info.redirect_uris],
                        "scope": info.scope,
                    }
                    for cid, info in auth_provider.clients.items()
                ],
            }
            logger.info(f"/debug/oauth -> {data}")
            return JSONResponse(data)
        except Exception as e:
            from starlette.responses import JSONResponse
            logger.error(f"/debug/oauth error: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)

# Cleanup function
async def cleanup():
    """Cleanup resources on shutdown."""
    try:
        await vivint_client.disconnect()
        logger.info("Vivint client disconnected")
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")

if __name__ == "__main__":
    port = config.port
    host = config.host
    
    logger.info(f"Starting Vivint MCP Server on {host}:{port}")
    logger.info(f"Environment: {config.environment}")
    logger.info(f"Debug mode: {config.debug_mode}")
    
    # Authentication status logging
    if auth_provider:
        if config.auth_type == "oauth":
            logger.info("🔐 OAuth authentication enabled - server supports OAuth client flow")
        else:
            logger.info("🔐 Authentication enabled - server requires valid tokens")
    else:
        logger.warning("⚠️ Authentication disabled - server is PUBLICLY accessible!")
    
    try:
        mcp.run(
            transport="http",
            host=host,
            port=port
        )
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        sys.exit(1)
    finally:
        # Run cleanup
        try:
            asyncio.run(cleanup())
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")
