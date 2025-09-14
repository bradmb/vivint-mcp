#!/usr/bin/env python3
"""Vivint Security System MCP Server.

Provides read-only access to Vivint security system data through MCP tools.
"""

import os
import sys
import asyncio
import logging
import secrets
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from fastmcp import FastMCP

# Import authentication
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
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
            
            # Create a custom OAuth provider that extends InMemoryOAuthProvider
            # This ensures /authorize works with FastMCP's built-in routing
            class SimpleOAuthProvider(InMemoryOAuthProvider):
                async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
                    """Override to provide simple authorization without complex Vivint auth."""
                    logger.info(f"🔍 SimpleOAuthProvider.authorize() called for client {client.client_id}")
                    logger.info(f"🔍 Redirect URI requested: {params.redirect_uri}")
                    logger.info(f"🔍 Client redirect URIs: {[str(uri) for uri in client.redirect_uris]}")
                    
                    # For now, just issue an authorization code directly
                    # In a real implementation, you'd verify user credentials here
                    import secrets
                    import time
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
            
            oauth_provider = SimpleOAuthProvider(base_url=base_url)
            
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

# Session middleware will be added when we create custom routes below

# Global connection state
_connection_initialized = False

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
