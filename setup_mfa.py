#!/usr/bin/env python3
"""Interactive MFA setup script for Vivint accounts with 2FA enabled."""

import asyncio
import sys
import os
import logging
import getpass
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from config import config
from vivint_client import VivintMCPClient
from token_manager import token_manager
from vivintpy.account import Account
from vivintpy.exceptions import VivintSkyApiMfaRequiredError, VivintSkyApiAuthenticationError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

async def interactive_mfa_setup():
    """Interactive MFA setup with real-time code input."""
    
    print("🔐 Vivint MFA Setup Assistant")
    print("=" * 50)
    print()
    
    # Check credentials
    if not config.username or not config.password:
        print("❌ VIVINT_USERNAME and VIVINT_PASSWORD must be set in .env file")
        return False
    
    print(f"📧 Account: {config.username}")
    print(f"💾 Token file: {config.refresh_token_file}")
    print()
    
    # Check for existing tokens
    existing_tokens = await token_manager.load_tokens()
    if existing_tokens and token_manager.is_token_for_user(config.username):
        print("✅ Found existing valid tokens!")
        print("💡 You can start the server directly: python src/server.py")
        
        choice = input("🔄 Do you want to refresh tokens anyway? (y/N): ").lower()
        if choice != 'y':
            return True
    
    print("🔌 Attempting to connect to Vivint...")
    
    # Create Account object directly for better control
    account = Account(username=config.username, password=config.password)
    
    try:
        # Try initial connection - this will trigger MFA if needed
        print("🔑 Authenticating with username/password...")
        await account.connect()
        
        # If we get here without MFA, great!
        print("✅ Authentication successful (no MFA required)!")
        
    except VivintSkyApiMfaRequiredError:
        print()
        print("🔐 Two-Factor Authentication Required")
        print("📱 Please check your Vivint app or email for a 6-digit code")
        print()
        
        # Get fresh MFA code interactively
        while True:
            try:
                mfa_code = input("🔢 Enter your 6-digit MFA code: ").strip()
                
                if len(mfa_code) != 6 or not mfa_code.isdigit():
                    print("❌ Please enter exactly 6 digits")
                    continue
                
                print(f"🔍 Verifying code: {mfa_code}")
                
                # Verify MFA code
                await account.verify_mfa(mfa_code)
                
                print("✅ MFA verification successful!")
                break
                
            except Exception as e:
                error_msg = str(e).lower()
                if "incorrect" in error_msg or "invalid" in error_msg:
                    print("❌ Invalid MFA code. Please try again.")
                    print("💡 Make sure you're using the most recent code from your app/email")
                    continue
                else:
                    print(f"❌ MFA verification failed: {e}")
                    return False
    
    except VivintSkyApiAuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        print("💡 Check your username and password in .env file")
        return False
    
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False
    
    # Save tokens if we have them
    if hasattr(account.api, 'tokens') and account.api.tokens:
        print("💾 Saving refresh tokens...")
        success = await token_manager.save_tokens(account.api.tokens)
        
        if success:
            print("✅ Tokens saved successfully!")
            print(f"📁 Location: {config.refresh_token_file}")
            print()
            print("🎉 Setup Complete!")
            print("🚀 You can now start the server: python src/server.py")
            print("💡 Future startups won't require MFA (tokens will be reused)")
        else:
            print("⚠️ Failed to save tokens - you'll need MFA each time")
    else:
        print("⚠️ No tokens received from Vivint API")
    
    # Test basic functionality
    print()
    print("🧪 Testing connection...")
    try:
        # Load systems to verify connection works
        await account.refresh()
        
        if account.systems:
            system = account.systems[0]
            print(f"✅ Connected to system: {getattr(system, 'name', 'Unknown')} (ID: {system.id})")
            print(f"🛡️ Armed state: {getattr(system, 'arm_state', 'unknown')}")
        else:
            print("⚠️ No systems found in account")
    
    except Exception as e:
        print(f"⚠️ Test failed: {e}")
    
    # Cleanup
    await account.disconnect()
    
    return True

async def main():
    """Main entry point."""
    print("🏠 Vivint MCP Server - MFA Setup")
    print()
    
    try:
        success = await interactive_mfa_setup()
        if success:
            print()
            print("🎯 Next steps:")
            print("1. Start server: python src/server.py")
            print("2. Generate JWT token: python src/generate_token.py --type token")
            print("3. Test with MCP Inspector: npx @modelcontextprotocol/inspector")
        else:
            print()
            print("❌ Setup failed. Please check your credentials and try again.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print()
        print("⚠️ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())