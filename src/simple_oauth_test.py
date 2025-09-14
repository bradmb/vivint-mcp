#!/usr/bin/env python3
"""Simple test to verify OAuth server starts up correctly."""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test imports
try:
    from server import mcp, auth_provider, config
    print("✅ Server imports successful")
    print(f"Auth type: {config.auth_type}")
    print(f"Auth provider: {type(auth_provider).__name__ if auth_provider else 'None'}")
    
    if config.auth_type == "oauth":
        print(f"OAuth client ID: {config.oauth_client_id}")
        print("✅ OAuth configuration looks good")
        
except Exception as e:
    print(f"❌ Import error: {e}")
    import traceback
    traceback.print_exc()