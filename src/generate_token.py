#!/usr/bin/env python3
"""Token generation utility for Vivint MCP Server authentication."""

import secrets
import time
import jwt
import json
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

try:
    from .config import config
except ImportError:
    # Handle case when run directly
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from config import config

def generate_secret_key(length: int = 64) -> str:
    """Generate a cryptographically secure random secret key.
    
    Args:
        length: Length of the secret key in bytes (default 64 for 512-bit key)
    
    Returns:
        Hex-encoded secret key
    """
    return secrets.token_hex(length)

def generate_rsa_keypair() -> tuple[str, str]:
    """Generate an RSA key pair for JWT signing.
    
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')
    
    # Serialize public key to PEM format
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    
    return private_pem, public_pem

def generate_jwt_token(
    secret_or_private_key: str,
    algorithm: str = "HS256",
    issuer: str = "vivint-mcp-server",
    audience: str = "vivint-mcp-client",
    subject: str = "vivint-user",
    expires_in_hours: int = 24,
    additional_claims: Optional[dict] = None
) -> str:
    """Generate a JWT token.
    
    Args:
        secret_or_private_key: Secret key (for HMAC) or private key PEM (for RSA)
        algorithm: JWT algorithm (HS256, HS384, HS512, RS256, RS384, RS512)
        issuer: Token issuer
        audience: Token audience
        subject: Token subject (user identifier)
        expires_in_hours: Token expiration time in hours
        additional_claims: Additional claims to include in the token
    
    Returns:
        JWT token string
    """
    current_time = int(time.time())
    
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": current_time,
        "exp": current_time + (expires_in_hours * 3600),
        "scope": "vivint:read",  # Standard OAuth scope
    }
    
    if additional_claims:
        payload.update(additional_claims)
    
    return jwt.encode(payload, secret_or_private_key, algorithm=algorithm)

def decode_jwt_token(
    token: str, 
    secret_or_public_key: str, 
    algorithm: str = "HS256",
    audience: str = None,
    issuer: str = None
) -> dict:
    """Decode and verify a JWT token.
    
    Args:
        token: JWT token to decode
        secret_or_public_key: Secret key (for HMAC) or public key PEM (for RSA)
        algorithm: JWT algorithm used
        audience: Expected audience claim
        issuer: Expected issuer claim
    
    Returns:
        Decoded token payload
    """
    return jwt.decode(
        token,
        secret_or_public_key,
        algorithms=[algorithm],
        audience=audience,
        issuer=issuer,
        options={"verify_exp": True}
    )

def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate authentication tokens for Vivint MCP Server")
    parser.add_argument(
        "--type",
        choices=["secret", "keypair", "token"],
        default="secret",
        help="Type of credential to generate (default: secret)"
    )
    parser.add_argument(
        "--algorithm",
        choices=["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"],
        default="HS256",
        help="JWT algorithm (default: HS256)"
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Token expiration time in hours (default: 24)"
    )
    parser.add_argument(
        "--subject",
        default="vivint-user",
        help="Token subject/user ID (default: vivint-user)"
    )
    parser.add_argument(
        "--verify",
        help="Verify and decode an existing JWT token"
    )
    
    args = parser.parse_args()
    
    if args.verify:
        # Verify an existing token
        try:
            if config.auth_type == "jwt" and config.jwt_algorithm.startswith("HS"):
                if not config.auth_secret:
                    print("❌ AUTH_SECRET not configured for token verification")
                    return
                decoded = decode_jwt_token(
                    args.verify, 
                    config.auth_secret, 
                    config.jwt_algorithm,
                    audience=config.jwt_audience,
                    issuer=config.jwt_issuer
                )
            elif config.auth_type == "jwt" and config.jwt_algorithm.startswith("RS"):
                if not config.jwt_public_key:
                    print("❌ JWT_PUBLIC_KEY not configured for token verification")
                    return
                decoded = decode_jwt_token(
                    args.verify, 
                    config.jwt_public_key, 
                    config.jwt_algorithm,
                    audience=config.jwt_audience,
                    issuer=config.jwt_issuer
                )
            else:
                print("❌ Invalid authentication configuration")
                return
            
            print("✅ Token is valid!")
            print(f"📝 Payload: {json.dumps(decoded, indent=2)}")
            
            # Check expiration
            exp = decoded.get('exp', 0)
            if exp > time.time():
                remaining = int((exp - time.time()) / 3600)
                print(f"⏰ Expires in {remaining} hours")
            else:
                print("⚠️ Token has expired")
                
        except jwt.ExpiredSignatureError:
            print("❌ Token has expired")
        except jwt.InvalidTokenError as e:
            print(f"❌ Token is invalid: {e}")
        return
    
    if args.type == "secret":
        # Generate a secret key for HMAC algorithms
        secret = generate_secret_key()
        print("🔑 Generated Secret Key:")
        print(f"AUTH_SECRET={secret}")
        print()
        print("💡 Add this to your .env file:")
        print(f"AUTH_SECRET={secret}")
        print("JWT_ALGORITHM=HS256")
        
    elif args.type == "keypair":
        # Generate RSA key pair for RSA algorithms
        private_key, public_key = generate_rsa_keypair()
        
        print("🔐 Generated RSA Key Pair:")
        print()
        print("🔑 Private Key (keep secret!):")
        print(private_key)
        print()
        print("🔓 Public Key:")
        print(public_key)
        print()
        print("💡 Add these to your .env file:")
        print('JWT_PRIVATE_KEY="' + private_key.replace('\n', '\\n') + '"')
        print('JWT_PUBLIC_KEY="' + public_key.replace('\n', '\\n') + '"')
        print("JWT_ALGORITHM=RS256")
        
    elif args.type == "token":
        # Generate a JWT token
        algorithm = args.algorithm
        
        if algorithm.startswith("HS"):
            # HMAC algorithm - need secret
            if not config.auth_secret:
                print("❌ AUTH_SECRET environment variable required for HMAC algorithms")
                print("💡 Generate one with: python src/generate_token.py --type secret")
                return
            secret_key = config.auth_secret
        else:
            # RSA algorithm - need private key
            if not config.jwt_private_key:
                print("❌ JWT_PRIVATE_KEY environment variable required for RSA algorithms")
                print("💡 Generate one with: python src/generate_token.py --type keypair")
                return
            secret_key = config.jwt_private_key
        
        token = generate_jwt_token(
            secret_or_private_key=secret_key,
            algorithm=algorithm,
            issuer=config.jwt_issuer,
            audience=config.jwt_audience,
            subject=args.subject,
            expires_in_hours=args.hours
        )
        
        print(f"🎫 Generated JWT Token (expires in {args.hours} hours):")
        print(token)
        print()
        print("💡 Use this token in your MCP client:")
        print(f'Authorization: Bearer {token}')
        
        # Show decoded payload for verification
        try:
            if algorithm.startswith("HS"):
                decoded = decode_jwt_token(
                    token, 
                    secret_key, 
                    algorithm,
                    audience=config.jwt_audience,
                    issuer=config.jwt_issuer
                )
            else:
                # For verification, we need the public key
                if config.jwt_public_key:
                    decoded = decode_jwt_token(
                        token, 
                        config.jwt_public_key, 
                        algorithm,
                        audience=config.jwt_audience,
                        issuer=config.jwt_issuer
                    )
                else:
                    print("⚠️ Cannot verify token - JWT_PUBLIC_KEY not configured")
                    return
            
            print()
            print("📝 Token Contents:")
            print(json.dumps(decoded, indent=2))
        except Exception as e:
            print(f"⚠️ Could not verify generated token: {e}")

if __name__ == "__main__":
    main()