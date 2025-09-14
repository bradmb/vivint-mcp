#!/usr/bin/env python3
"""
OAuth Redirect URI Management Utility

This script helps manage OAuth redirect URIs for dynamic tunnel URLs.
When you start a new Cloudflare tunnel, use this script to update your
OAuth configuration with the new tunnel URL.
"""

import os
import argparse
from pathlib import Path
from dotenv import load_dotenv, set_key

def get_current_uris(env_path: Path) -> list:
    """Get currently configured redirect URIs."""
    load_dotenv(env_path)
    uris_str = os.getenv("OAUTH_REDIRECT_URIS", "")
    return [uri.strip() for uri in uris_str.split(",") if uri.strip()]

def update_redirect_uris(env_path: Path, tunnel_url: str = None, add_uri: str = None, remove_uri: str = None):
    """Update redirect URIs in the .env file."""
    load_dotenv(env_path)
    current_uris = get_current_uris(env_path)
    
    # Handle tunnel URL addition
    if tunnel_url:
        # Remove old tunnel URLs (trycloudflare.com)
        current_uris = [uri for uri in current_uris if "trycloudflare.com" not in uri]
        
        # Add new tunnel callback URL
        new_callback = f"{tunnel_url.rstrip('/')}/callback"
        if new_callback not in current_uris:
            current_uris.append(new_callback)
            print(f"✅ Added tunnel callback: {new_callback}")
    
    # Handle manual URI addition
    if add_uri:
        if add_uri not in current_uris:
            current_uris.append(add_uri)
            print(f"✅ Added URI: {add_uri}")
        else:
            print(f"ℹ️  URI already exists: {add_uri}")
    
    # Handle URI removal
    if remove_uri:
        if remove_uri in current_uris:
            current_uris.remove(remove_uri)
            print(f"✅ Removed URI: {remove_uri}")
        else:
            print(f"ℹ️  URI not found: {remove_uri}")
    
    # Update .env file
    updated_uris = ",".join(current_uris)
    set_key(env_path, "OAUTH_REDIRECT_URIS", updated_uris)
    
    return current_uris

def show_current_config(env_path: Path):
    """Display current OAuth configuration."""
    load_dotenv(env_path)
    
    client_id = os.getenv("OAUTH_CLIENT_ID", "Not set")
    uris = get_current_uris(env_path)
    
    print("🔑 Current OAuth Configuration")
    print("=" * 50)
    print(f"Client ID: {client_id}")
    print(f"Redirect URIs ({len(uris)} total):")
    for i, uri in enumerate(uris, 1):
        print(f"  {i}. {uri}")
    print()

def auto_detect_tunnel():
    """Auto-detect current tunnel URL from .mcp_public_url file."""
    tunnel_file = Path(".mcp_public_url")
    if tunnel_file.exists():
        with open(tunnel_file, "r") as f:
            mcp_url = f.read().strip()
            # Extract base URL from MCP URL (remove /mcp suffix)
            if mcp_url.endswith("/mcp"):
                return mcp_url[:-4]
    return None

def main():
    parser = argparse.ArgumentParser(
        description="Manage OAuth redirect URIs for MCP server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show current configuration
  python update_oauth_uris.py --show

  # Auto-detect and add current tunnel
  python update_oauth_uris.py --auto-tunnel

  # Add specific tunnel URL
  python update_oauth_uris.py --tunnel https://my-tunnel.trycloudflare.com

  # Add custom URI
  python update_oauth_uris.py --add https://myapp.com/callback

  # Remove URI
  python update_oauth_uris.py --remove https://old-tunnel.trycloudflare.com/callback
        """
    )
    
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Path to .env file (default: .env)"
    )
    
    parser.add_argument(
        "--show",
        action="store_true",
        help="Show current OAuth configuration"
    )
    
    parser.add_argument(
        "--auto-tunnel",
        action="store_true",
        help="Auto-detect current tunnel URL and update URIs"
    )
    
    parser.add_argument(
        "--tunnel",
        type=str,
        help="Tunnel base URL to add (e.g., https://my-tunnel.trycloudflare.com)"
    )
    
    parser.add_argument(
        "--add",
        type=str,
        help="Add specific redirect URI"
    )
    
    parser.add_argument(
        "--remove",
        type=str,
        help="Remove specific redirect URI"
    )
    
    args = parser.parse_args()
    
    if not args.env_file.exists():
        print(f"❌ Error: {args.env_file} not found")
        return 1
    
    # Show current configuration
    if args.show or not any([args.auto_tunnel, args.tunnel, args.add, args.remove]):
        show_current_config(args.env_file)
        return 0
    
    # Handle auto tunnel detection
    if args.auto_tunnel:
        tunnel_url = auto_detect_tunnel()
        if tunnel_url:
            print(f"🔍 Detected tunnel: {tunnel_url}")
            args.tunnel = tunnel_url
        else:
            print("❌ No tunnel detected. Make sure your tunnel is running and try --tunnel instead.")
            return 1
    
    # Update URIs
    try:
        current_uris = update_redirect_uris(
            args.env_file,
            tunnel_url=args.tunnel,
            add_uri=args.add,
            remove_uri=args.remove
        )
        
        print(f"\n✅ Updated {args.env_file}")
        print("\n📋 Current redirect URIs:")
        for i, uri in enumerate(current_uris, 1):
            print(f"  {i}. {uri}")
        
        print(f"\n💡 Restart your MCP server to apply changes:")
        print("   pkill -f 'python.*server.py' && python src/server.py &")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error updating URIs: {str(e)}")
        return 1

if __name__ == "__main__":
    exit(main())