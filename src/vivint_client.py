#!/usr/bin/env python3
"""Vivint client wrapper for MCP integration."""

import asyncio
import logging
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta
from vivintpy.account import Account
from vivintpy.exceptions import VivintSkyApiMfaRequiredError, VivintSkyApiAuthenticationError

try:
    from .config import config
    from .token_manager import token_manager
except ImportError:
    # Handle case when run directly
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from config import config
    from token_manager import token_manager

logger = logging.getLogger(__name__)

class VivintClientError(Exception):
    """Base exception for Vivint client errors."""
    pass

class VivintAuthenticationError(VivintClientError):
    """Authentication-related errors."""
    pass

class VivintMfaRequiredError(VivintClientError):
    """MFA code required for authentication."""
    pass

class VivintConnectionError(VivintClientError):
    """Connection-related errors."""
    pass

class VivintMCPClient:
    """Vivint client wrapper with session management and error handling."""
    
    def __init__(self):
        self.client: Optional[Account] = None
        self._connected = False
        self._last_refresh = None
        self._session_task = None
        
        # Configure logging
        if config.debug_mode:
            logging.basicConfig(level=getattr(logging, config.log_level))
    
    async def connect(self) -> None:
        """Connect to Vivint API with error handling and MFA support."""
        try:
            logger.info("Connecting to Vivint API...")
            
            # First, try to use a saved refresh token
            if await self._try_connect_with_refresh_token():
                return
            
            # If no refresh token or it failed, try password authentication
            # This will handle MFA internally if needed
            await self._connect_with_password()
            
        except Exception as e:
            logger.error(f"Failed to connect to Vivint API: {str(e)}")
            self._connected = False
            raise VivintAuthenticationError(f"Authentication failed: {str(e)}")
    
    async def disconnect(self) -> None:
        """Disconnect from Vivint API."""
        if self._session_task and not self._session_task.done():
            self._session_task.cancel()
            try:
                await self._session_task
            except asyncio.CancelledError:
                pass
        
        if self.client:
            await self.client.disconnect()
        
        self._connected = False
        logger.info("Disconnected from Vivint API")
    
    async def ensure_connected(self) -> None:
        """Ensure connection is active, reconnect if necessary."""
        if not self._connected or not self.client:
            await self.connect()
        
        # Check if session needs refresh
        if self._last_refresh:
            time_since_refresh = datetime.now() - self._last_refresh
            if time_since_refresh.total_seconds() > config.session_refresh_interval:
                await self._refresh_session()
    
    async def _refresh_session(self) -> None:
        """Refresh the session to maintain connectivity."""
        try:
            logger.debug("Refreshing Vivint session...")
            
            if self.client and hasattr(self.client, 'refresh'):
                await self.client.refresh()
            else:
                # If refresh method doesn't exist, reconnect
                await self.connect()
            
            self._last_refresh = datetime.now()
            logger.debug("Session refreshed successfully")
            
        except Exception as e:
            logger.warning(f"Session refresh failed: {str(e)}")
            # Try to reconnect
            try:
                await self.connect()
            except Exception as reconnect_error:
                logger.error(f"Reconnection failed: {str(reconnect_error)}")
                raise VivintConnectionError(f"Failed to maintain connection: {str(reconnect_error)}")
    
    async def _session_manager(self) -> None:
        """Background task to manage session lifecycle."""
        while self._connected:
            try:
                await asyncio.sleep(config.session_refresh_interval)
                if self._connected:
                    await self._refresh_session()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session manager error: {str(e)}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _try_connect_with_refresh_token(self) -> bool:
        """Try to connect using a saved refresh token."""
        try:
            tokens = await token_manager.load_tokens()
            if not tokens or not token_manager.is_token_for_user(config.username):
                logger.debug("No valid refresh token found for user")
                return False
            
            refresh_token = token_manager.get_refresh_token()
            if not refresh_token:
                logger.debug("No refresh token available")
                return False
            
            logger.info("Attempting connection with refresh token")
            # Note: vivintpy requires password even when using refresh token (library limitation)
            self.client = Account(
                username=config.username,
                password=config.password,  # Required by library assertion
                refresh_token=refresh_token
            )
            
            await self.client.connect(load_devices=True)
            
            # Connection successful, finalize connection
            await self._finalize_connection()
            logger.info("Successfully connected using refresh token")
            return True
            
        except Exception as e:
            logger.debug(f"Refresh token connection failed: {str(e)}")
            # Clear invalid tokens
            await token_manager.clear_tokens()
            return False
    
    async def _connect_with_password(self) -> None:
        """Connect using username and password, handling MFA if required."""
        logger.info("Attempting password authentication")
        
        self.client = Account(
            username=config.username,
            password=config.password
        )
        
        try:
            await self.client.connect(load_devices=True)
            
            # If we reach here, no MFA was required
            await self._finalize_connection()
            
        except VivintSkyApiMfaRequiredError:
            logger.info("MFA required for authentication")
            # Keep the same client object and handle MFA
            await self._handle_mfa_required()
    
    async def _finalize_connection(self) -> None:
        """Finalize the connection after successful authentication."""
        # Save refresh token for future use
        if hasattr(self.client.api, 'tokens') and self.client.api.tokens:
            await token_manager.save_tokens(self.client.api.tokens)
        
        self._connected = True
        self._last_refresh = datetime.now()
        
        # Start session management task
        if not self._session_task or self._session_task.done():
            self._session_task = asyncio.create_task(self._session_manager())
        
        logger.info("Successfully connected")
    
    async def _handle_mfa_required(self) -> None:
        """Handle MFA requirement during authentication."""
        mfa_code = config.mfa_code
        
        # Try interactive input if no environment variable is set
        if not mfa_code and config.mfa_auto_wait:
            try:
                import sys
                if sys.stdin.isatty():  # Check if running interactively
                    print("\n🔐 Two-Factor Authentication Required")
                    print("📱 Please check your Vivint app or email for a 6-digit code")
                    mfa_code = input("🔢 Enter your 6-digit MFA code: ").strip()
            except (EOFError, KeyboardInterrupt):
                pass
        
        if not mfa_code:
            error_msg = (
                "MFA code required but not provided. Please either:\n"
                "1. Set VIVINT_MFA_CODE environment variable with your current 2FA code, OR\n"
                "2. Use the interactive setup: python setup_mfa.py"
            )
            logger.error(error_msg)
            raise VivintMfaRequiredError(error_msg)
        
        # Validate MFA code format
        if len(mfa_code) != 6 or not mfa_code.isdigit():
            error_msg = "MFA code must be exactly 6 digits"
            logger.error(error_msg)
            raise VivintMfaRequiredError(error_msg)
        
        try:
            logger.info(f"Verifying MFA code: {mfa_code}")
            # Use the existing client object that has the proper session state
            await self.client.verify_mfa(mfa_code)
            
            # Finalize the connection after successful MFA
            await self._finalize_connection()
            logger.info("Successfully verified MFA and connected")
            
        except Exception as e:
            error_msg = str(e).lower()
            if "incorrect" in error_msg or "invalid" in error_msg:
                logger.error("MFA code was rejected - please verify you're using the most recent code")
                raise VivintMfaRequiredError("Invalid MFA code - please get a fresh code and try again")
            else:
                logger.error(f"MFA verification failed: {str(e)}")
                raise VivintAuthenticationError(f"MFA verification failed: {str(e)}")
    
    async def get_system(self) -> Dict[str, Any]:
        """Get the primary system information."""
        await self.ensure_connected()
        
        try:
            if not hasattr(self.client, 'systems') or not self.client.systems:
                raise VivintClientError("No systems found in Vivint account")
            
            systems = self.client.systems  # systems is already a list
            
            # Use specific system ID if configured, otherwise use first system
            if config.system_id:
                system = next((s for s in systems if str(s.id) == config.system_id), None)
                if not system:
                    raise VivintClientError(f"System with ID {config.system_id} not found")
            else:
                system = systems[0]
            
            # Get alarm panel information (armed state is on the panel, not system)
            panel_info = {}
            if hasattr(system, 'alarm_panels') and system.alarm_panels:
                primary_panel = system.alarm_panels[0]  # Use first panel
                try:
                    state = primary_panel.state
                    panel_info = {
                        "panel_id": primary_panel.id,
                        "panel_name": getattr(primary_panel, 'name', 'Main Panel'),
                        "arm_state": state.name.lower() if state else 'unknown',
                        "arm_state_value": state.value if state else None,
                        "is_disarmed": getattr(primary_panel, 'is_disarmed', None),
                        "is_armed_stay": getattr(primary_panel, 'is_armed_stay', None),
                        "is_armed_away": getattr(primary_panel, 'is_armed_away', None),
                        "partition_id": getattr(primary_panel, 'partition_id', None)
                    }
                except Exception as panel_error:
                    logger.warning(f"Could not get panel state: {panel_error}")
                    panel_info = {
                        "panel_id": getattr(primary_panel, 'id', 'unknown'),
                        "arm_state": 'error',
                        "error": str(panel_error)
                    }
            else:
                panel_info = {
                    "arm_state": 'no_panel',
                    "error": "No alarm panels found"
                }
            
            return {
                "id": system.id,
                "name": getattr(system, 'name', 'Unknown'),
                "is_admin": getattr(system, 'is_admin', False),
                "panel_count": len(system.alarm_panels) if hasattr(system, 'alarm_panels') else 0,
                "user_count": len(system.users) if hasattr(system, 'users') else 0,
                **panel_info  # Include all panel information
            }
            
        except Exception as e:
            logger.error(f"Failed to get system info: {str(e)}")
            raise VivintClientError(f"Failed to retrieve system information: {str(e)}")
    
    async def get_all_devices(self) -> List[Dict[str, Any]]:
        """Get all devices from the system."""
        await self.ensure_connected()
        
        try:
            systems = self.client.systems  # systems is already a list
            
            # Use specific system ID if configured, otherwise use first system
            if config.system_id:
                system_obj = next((s for s in systems if str(s.id) == config.system_id), None)
                if not system_obj:
                    raise VivintClientError(f"System with ID {config.system_id} not found")
            else:
                system_obj = systems[0]
            
            devices = []
            
            # Devices are on alarm panels, not directly on the system
            if hasattr(system_obj, 'alarm_panels') and system_obj.alarm_panels:
                for panel in system_obj.alarm_panels:
                    if hasattr(panel, 'devices') and panel.devices:
                        for device in panel.devices:
                            try:
                                device_info = {
                                    "id": getattr(device, 'id', 'unknown'),
                                    "name": getattr(device, 'name', 'Unknown Device'),
                                    "type": device.__class__.__name__,
                                    "panel_id": getattr(panel, 'id', 'unknown'),
                                    "system_id": system_obj.id,
                                }
                                
                                # Try to get common attributes safely
                                safe_attrs = {
                                    "state": "state",
                                    "is_online": "is_online", 
                                    "battery_level": "battery_level",
                                    "location": "location",
                                    "last_update_time": "last_update_time",
                                    "manufacturer": "manufacturer",
                                    "model": "model",
                                    "serial_number": "serial_number"
                                }
                                
                                for key, attr in safe_attrs.items():
                                    try:
                                        value = getattr(device, attr, None)
                                        if value is not None:
                                            # Handle special cases
                                            if key == "state" and hasattr(value, 'name'):
                                                device_info[key] = value.name.lower()
                                                device_info[f"{key}_value"] = value.value
                                            elif key == "last_update_time" and hasattr(value, 'isoformat'):
                                                device_info[key] = value.isoformat()
                                            else:
                                                device_info[key] = str(value) if value is not None else None
                                    except Exception as attr_error:
                                        logger.debug(f"Could not get {attr} for device {device_info.get('id', 'unknown')}: {attr_error}")
                                
                                # Special handling for DoorLock devices
                                if device.__class__.__name__ == "DoorLock":
                                    try:
                                        is_locked = getattr(device, 'is_locked', None)
                                        if is_locked is not None:
                                            device_info["state"] = "locked" if is_locked else "unlocked"
                                            device_info["is_locked"] = is_locked
                                        logger.debug(f"DoorLock {device_info.get('name', 'unknown')}: is_locked={is_locked}, state={device_info.get('state', 'unknown')}")
                                    except Exception as lock_error:
                                        logger.debug(f"Could not get lock state for device {device_info.get('id', 'unknown')}: {lock_error}")
                                
                                devices.append(device_info)
                                
                            except Exception as device_error:
                                logger.warning(f"Error processing device: {device_error}")
                                # Still include basic info
                                devices.append({
                                    "id": "error",
                                    "name": f"Error Device: {device.__class__.__name__}",
                                    "type": device.__class__.__name__,
                                    "error": str(device_error),
                                    "panel_id": getattr(panel, 'id', 'unknown'),
                                    "system_id": system_obj.id
                                })
            else:
                logger.warning("No alarm panels or devices found")
            
            logger.info(f"Found {len(devices)} devices across all panels")
            return devices
            
        except Exception as e:
            logger.error(f"Failed to get devices: {str(e)}")
            raise VivintClientError(f"Failed to retrieve devices: {str(e)}")
    
    async def get_devices_by_type(self, device_type: str) -> List[Dict[str, Any]]:
        """Get devices of a specific type."""
        all_devices = await self.get_all_devices()
        return [d for d in all_devices if device_type.lower() in d["type"].lower()]
    
    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected and self.client is not None

# Global client instance
vivint_client = VivintMCPClient()