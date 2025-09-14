#!/usr/bin/env python3
"""Test script for MFA implementation."""

import asyncio
import os
import sys
import logging

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from config import config
from vivint_client import vivint_client, VivintMfaRequiredError, VivintAuthenticationError
from token_manager import token_manager

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def test_mfa_flow():
    """Test the MFA authentication flow."""
    
    print("🔍 Testing MFA Implementation")
    print(f"Username: {config.username}")
    print(f"MFA Code: {'***' if config.mfa_code else 'Not set'}")
    print(f"Token file: {config.refresh_token_file}")
    print()
    
    try:
        # Test token manager
        print("📂 Checking for existing tokens...")
        tokens = await token_manager.load_tokens()
        if tokens:
            print(f"✅ Found tokens for user: {tokens.get('username', 'unknown')}")
            if token_manager.is_token_for_user(config.username):
                print("✅ Tokens match current user")
            else:
                print("⚠️ Tokens are for a different user")
        else:
            print("ℹ️ No existing tokens found")
        
        print()
        print("🔐 Attempting Vivint connection...")
        
        # Attempt connection
        await vivint_client.connect()
        
        print("✅ Connection successful!")
        print(f"Connected: {vivint_client.is_connected}")
        
        # Test getting system info
        system = await vivint_client.get_system()
        print(f"System ID: {system.get('id')}")
        print(f"System Name: {system.get('name')}")
        print(f"Armed State: {system.get('arm_state')}")
        
        # Check if tokens were saved
        tokens_after = await token_manager.load_tokens()
        if tokens_after and not tokens:
            print("✅ New tokens saved successfully")
        elif tokens_after:
            print("✅ Tokens updated")
        
        await vivint_client.disconnect()
        print("✅ Disconnected successfully")
        
    except VivintMfaRequiredError as e:
        print(f"🔐 MFA Required: {str(e)}")
        print("💡 Set VIVINT_MFA_CODE environment variable with your 2FA code")
        return False
        
    except VivintAuthenticationError as e:
        print(f"❌ Authentication Error: {str(e)}")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

async def test_token_persistence():
    """Test token persistence functionality."""
    print("\n📁 Testing Token Persistence")
    
    # Test saving dummy tokens
    test_tokens = {
        "access_token": "test_access",
        "refresh_token": "test_refresh", 
        "id_token": "test_id",
        "expires_in": 21600  # 6 hours
    }
    
    success = await token_manager.save_tokens(test_tokens)
    if success:
        print("✅ Test tokens saved successfully")
        
        # Load them back
        loaded = await token_manager.load_tokens()
        if loaded:
            print("✅ Test tokens loaded successfully")
            print(f"Refresh token: {token_manager.get_refresh_token()[:20]}...")
            print(f"Is for user {config.username}: {token_manager.is_token_for_user(config.username)}")
        else:
            print("❌ Failed to load test tokens")
            
        # Clean up
        await token_manager.clear_tokens()
        print("✅ Test tokens cleared")
    else:
        print("❌ Failed to save test tokens")

if __name__ == "__main__":
    print("🚀 Starting MFA Test Suite\n")
    
    if not config.username or not config.password:
        print("❌ VIVINT_USERNAME and VIVINT_PASSWORD must be set")
        sys.exit(1)
    
    async def main():
        await test_token_persistence()
        await test_mfa_flow()
    
    asyncio.run(main())