#!/usr/bin/env python3
"""Generate OAuth client ID and secret for local authentication.

This script generates OAuth client credentials that can be used with Claude Desktop
and other MCP clients. The credentials are stored in the .env file and used by
the MCP server's InMemoryOAuthProvider.
"""

import argparse
import os
import secrets
import string
from pathlib import Path
from dotenv import load_dotenv, set_key

def generate_client_id() -> str:
    """Generate a unique client ID."""
    # Format: vivint-mcp-<random_string>
    random_part = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(16))
    return f"vivint-mcp-{random_part}"

def generate_client_secret() -> str:
    """Generate a secure client secret."""
    # 64 character random string using URL-safe characters
    alphabet = string.ascii_letters + string.digits + '-_'
    return ''.join(secrets.choice(alphabet) for _ in range(64))

def update_env_file(client_id: str, client_secret: str, env_path: Path) -> None:
    """Update the .env file with OAuth credentials."""
    # Load existing .env
    load_dotenv(env_path)
    
    # Update OAuth credentials
    set_key(env_path, "OAUTH_CLIENT_ID", client_id)
    set_key(env_path, "OAUTH_CLIENT_SECRET", client_secret)
    
    # Set auth type to oauth if not already set
    current_auth_type = os.getenv("AUTH_TYPE")
    if not current_auth_type:
        set_key(env_path, "AUTH_TYPE", "oauth")
        print("ℹ️  Set AUTH_TYPE=oauth (you can change this in .env if needed)")

def print_credentials(client_id: str, client_secret: str) -> None:
    """Print the generated credentials in a user-friendly format."""
    print("🔑 OAuth Client Credentials Generated")
    print("=" * 50)
    print(f"Client ID:     {client_id}")
    print(f"Client Secret: {client_secret}")
    print()
    
    print("📱 Claude Desktop Configuration")
    print("-" * 30)
    print("Add this to your Claude Desktop MCP settings:")
    print()
    print('  "mcpServers": {')
    print('    "vivint": {')
    print(f'      "command": "python",')
    print(f'      "args": ["/path/to/your/mcp-server-template/src/server.py"],')
    print('      "auth": {')
    print(f'        "client_id": "{client_id}",')
    print(f'        "client_secret": "{client_secret}"')
    print('      }')
    print('    }')
    print('  }')
    print()
    
    print("🌐 Server URL for OAuth Flow")
    print("-" * 30)
    print("Your MCP server will run at: http://localhost:8000")
    print()
    
    print("💡 Next Steps")
    print("-" * 15)
    print("1. Start your MCP server: python src/server.py")
    print("2. The server will automatically register these credentials")
    print("3. Claude Desktop will use these credentials for OAuth authentication")

def main():
    parser = argparse.ArgumentParser(
        description="Generate OAuth client ID and secret for MCP server authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/generate_oauth_credentials.py
  python src/generate_oauth_credentials.py --regenerate
  python src/generate_oauth_credentials.py --env-file custom.env

The generated credentials will be saved to your .env file and can be used
with Claude Desktop and other MCP clients that support OAuth authentication.
        """
    )
    
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Path to .env file (default: .env)"
    )
    
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Regenerate credentials even if they already exist"
    )
    
    args = parser.parse_args()
    
    # Ensure the script is run from the correct directory
    if not Path("src").exists():
        print("❌ Error: Please run this script from the project root directory")
        print("   Current directory:", os.getcwd())
        return 1
    
    # Check if credentials already exist
    load_dotenv(args.env_file)
    existing_client_id = os.getenv("OAUTH_CLIENT_ID")
    existing_client_secret = os.getenv("OAUTH_CLIENT_SECRET")
    
    if existing_client_id and existing_client_secret and not args.regenerate:
        print("🔑 OAuth Credentials Already Exist")
        print("=" * 40)
        print(f"Client ID:     {existing_client_id}")
        print(f"Client Secret: {existing_client_secret}")
        print()
        print("💡 Use --regenerate to generate new credentials")
        return 0
    
    # Generate new credentials
    print("🔄 Generating OAuth client credentials...")
    client_id = generate_client_id()
    client_secret = generate_client_secret()
    
    # Update .env file
    try:
        update_env_file(client_id, client_secret, args.env_file)
        print(f"✅ Credentials saved to {args.env_file}")
        print()
        
        # Display credentials and usage instructions
        print_credentials(client_id, client_secret)
        
        return 0
        
    except Exception as e:
        print(f"❌ Error updating {args.env_file}: {str(e)}")
        return 1

if __name__ == "__main__":
    exit(main())