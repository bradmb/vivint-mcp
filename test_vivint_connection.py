#!/usr/bin/env python3
"""Comprehensive test script for Vivint connection and data exploration."""

import asyncio
import sys
import os
import logging
import json
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from config import config
from token_manager import token_manager
from vivintpy.account import Account
from vivintpy.enums import ArmedState, DeviceType

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def print_section(title: str, char: str = "="):
    """Print a section header."""
    print(f"\n{char * 60}")
    print(f" {title}")
    print(f"{char * 60}")

def print_subsection(title: str):
    """Print a subsection header."""
    print(f"\n--- {title} ---")

def safe_get_attr(obj, attr_name: str, default="N/A"):
    """Safely get attribute from object."""
    try:
        value = getattr(obj, attr_name, default)
        if value is None:
            return "None"
        if isinstance(value, (dict, list)) and not value:
            return "Empty"
        return str(value)
    except Exception as e:
        return f"Error: {e}"

async def test_vivint_connection():
    """Comprehensive test of Vivint connection and data exploration."""
    
    print_section("🏠 Vivint Connection Test", "=")
    
    # Check credentials
    if not config.username:
        print("❌ VIVINT_USERNAME not configured")
        return False
    
    print(f"📧 Account: {config.username}")
    print(f"💾 Token file: {config.refresh_token_file}")
    
    # Check for existing tokens
    tokens = await token_manager.load_tokens()
    if not tokens or not token_manager.is_token_for_user(config.username):
        print("❌ No valid tokens found. Please run: python setup_mfa.py")
        return False
    
    print("✅ Found valid tokens")
    
    # Create account - vivintpy requires password even when using refresh token
    # This is a limitation of the library
    account = Account(
        username=config.username,
        password=config.password,  # Still needed due to library assertion
        refresh_token=token_manager.get_refresh_token()
    )
    
    try:
        print_section("🔌 Connecting to Vivint", "-")
        await account.connect(load_devices=True)
        print("✅ Connected successfully")
        
        print_section("🏡 System Information")
        
        if not account.systems:
            print("❌ No systems found")
            return False
        
        print(f"📊 Found {len(account.systems)} system(s)")
        
        for i, system in enumerate(account.systems):
            print_subsection(f"System {i+1}")
            print(f"  🆔 System ID: {system.id}")
            print(f"  🏠 Name: {safe_get_attr(system, 'name')}")
            print(f"  👤 Admin: {safe_get_attr(system, 'is_admin')}")
            print(f"  📍 Panels: {len(system.alarm_panels) if hasattr(system, 'alarm_panels') else 0}")
            print(f"  👥 Users: {len(system.users) if hasattr(system, 'users') else 0}")
            
            # Examine alarm panels
            print_subsection("Alarm Panels")
            if hasattr(system, 'alarm_panels') and system.alarm_panels:
                for j, panel in enumerate(system.alarm_panels):
                    print(f"    Panel {j+1}:")
                    print(f"      🆔 Panel ID: {safe_get_attr(panel, 'id')}")
                    print(f"      📛 Name: {safe_get_attr(panel, 'name')}")
                    print(f"      🔧 MAC Address: {safe_get_attr(panel, 'mac_address')}")
                    print(f"      🏭 Manufacturer: {safe_get_attr(panel, 'manufacturer')}")
                    print(f"      🔢 Partition ID: {safe_get_attr(panel, 'partition_id')}")
                    
                    # Get armed state
                    try:
                        state = panel.state
                        print(f"      🛡️ Armed State: {state.name} ({state.value})")
                        print(f"      🔓 Is Disarmed: {safe_get_attr(panel, 'is_disarmed')}")
                        print(f"      🏠 Is Armed Stay: {safe_get_attr(panel, 'is_armed_stay')}")
                        print(f"      🚪 Is Armed Away: {safe_get_attr(panel, 'is_armed_away')}")
                    except Exception as e:
                        print(f"      ❌ State Error: {e}")
                    
                    # List devices on this panel
                    if hasattr(panel, 'devices') and panel.devices:
                        print(f"      📱 Devices: {len(panel.devices)}")
                        
                        # Group devices by type
                        device_types = {}
                        for device in panel.devices:
                            device_type = device.__class__.__name__
                            if device_type not in device_types:
                                device_types[device_type] = []
                            device_types[device_type].append(device)
                        
                        for device_type, devices in device_types.items():
                            print(f"        📋 {device_type}: {len(devices)}")
                        
                        # Show details for some devices
                        print_subsection("Device Details (First 5)")
                        for k, device in enumerate(panel.devices[:5]):
                            print(f"        Device {k+1}: {device.__class__.__name__}")
                            print(f"          🆔 ID: {safe_get_attr(device, 'id')}")
                            print(f"          📛 Name: {safe_get_attr(device, 'name')}")
                            
                            # Try to get common attributes
                            common_attrs = ['state', 'battery_level', 'is_online', 'last_update_time', 'location']
                            for attr in common_attrs:
                                value = safe_get_attr(device, attr)
                                if value != "N/A":
                                    print(f"          📊 {attr}: {value}")
                            
                            # Show raw data keys (first few)
                            if hasattr(device, 'data') and isinstance(device.data, dict):
                                keys = list(device.data.keys())[:8]
                                print(f"          🔑 Data Keys: {', '.join(keys)}{'...' if len(device.data) > 8 else ''}")
                        
                        # Special detailed view for lock devices
                        lock_devices = [d for d in panel.devices if 'lock' in d.__class__.__name__.lower()]
                        if lock_devices:
                            print_subsection("🔐 Lock Device Detailed Analysis")
                            for lock in lock_devices:
                                print(f"        Lock: {safe_get_attr(lock, 'name')} ({lock.__class__.__name__})")
                                
                                # Check all possible lock-related attributes
                                lock_attrs = [
                                    'state', 'is_locked', 'locked', 'lock_state', 'status', 
                                    'door_state', 'lock_status', 's', 'val', 'value'
                                ]
                                
                                for attr in lock_attrs:
                                    value = safe_get_attr(lock, attr)
                                    if value != "N/A":
                                        print(f"          🔑 {attr}: {value}")
                                
                                # Show ALL raw data for lock
                                if hasattr(lock, 'data') and isinstance(lock.data, dict):
                                    print(f"          📋 ALL Raw Data:")
                                    for key, value in lock.data.items():
                                        print(f"            {key}: {value}")
                    
                    else:
                        print(f"      📱 No devices found")
            else:
                print("    ❌ No alarm panels found")
            
            # Show raw system data structure
            print_subsection("Raw System Data Structure")
            if hasattr(system, 'data') and isinstance(system.data, dict):
                def print_dict_structure(d, indent=0):
                    for key, value in d.items():
                        spaces = "  " * indent
                        if isinstance(value, dict):
                            print(f"{spaces}📁 {key}: (dict with {len(value)} keys)")
                            if indent < 2:  # Limit depth
                                print_dict_structure(value, indent + 1)
                        elif isinstance(value, list):
                            print(f"{spaces}📋 {key}: (list with {len(value)} items)")
                        else:
                            value_str = str(value)[:50]
                            if len(str(value)) > 50:
                                value_str += "..."
                            print(f"{spaces}📄 {key}: {value_str}")
                
                print_dict_structure(system.data)
        
        print_section("🧪 Testing MCP Client Wrapper")
        
        # Test our client wrapper
        from vivint_client import vivint_client
        
        try:
            # This should use the same connection
            vivint_client.client = account
            vivint_client._connected = True
            
            system_info = await vivint_client.get_system()
            print("✅ MCP Client get_system():")
            print(json.dumps(system_info, indent=2))
            
            all_devices = await vivint_client.get_all_devices()
            print(f"✅ MCP Client found {len(all_devices)} devices")
            if all_devices:
                print("First device:")
                print(json.dumps(all_devices[0], indent=2))
        
        except Exception as e:
            print(f"❌ MCP Client test failed: {e}")
            import traceback
            traceback.print_exc()
        
        print_section("✅ Test Complete", "=")
        
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        await account.disconnect()
    
    return True

async def main():
    """Main entry point."""
    success = await test_vivint_connection()
    
    if success:
        print("\n🎉 Connection test completed successfully!")
        print("\n💡 Next steps:")
        print("1. Start the server: python src/server.py")
        print("2. Test MCP tools with proper data access")
    else:
        print("\n❌ Connection test failed")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())