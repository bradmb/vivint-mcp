#!/usr/bin/env python3
"""Configuration management for Vivint MCP server."""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class VivintConfig:
    """Configuration settings for Vivint integration."""
    
    def __init__(self):
        # Vivint credentials (required)
        self.username = os.getenv("VIVINT_USERNAME")
        self.password = os.getenv("VIVINT_PASSWORD")
        self.system_id = os.getenv("VIVINT_SYSTEM_ID")
        
        # MFA/2FA settings
        self.mfa_code = os.getenv("VIVINT_MFA_CODE")  # One-time MFA code
        self.refresh_token_file = os.getenv("VIVINT_REFRESH_TOKEN_FILE", ".vivint_tokens.json")
        self.mfa_auto_wait = os.getenv("VIVINT_MFA_AUTO_WAIT", "false").lower() == "true"
        
        # Server configuration
        self.port = int(os.getenv("PORT", 8000))
        self.host = os.getenv("HOST", "0.0.0.0")
        self.environment = os.getenv("ENVIRONMENT", "development")
        
        # Debug settings
        self.debug_mode = os.getenv("DEBUG_MODE", "false").lower() == "true"
        self.log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        
        # Session management
        self.session_refresh_interval = int(os.getenv("SESSION_REFRESH_INTERVAL", 900))  # 15 minutes
        self.token_refresh_interval = int(os.getenv("TOKEN_REFRESH_INTERVAL", 18000))   # 5 hours
        
        # Authentication settings
        self.auth_enabled = os.getenv("AUTH_ENABLED", "true").lower() == "true"
        self.auth_type = os.getenv("AUTH_TYPE", "jwt").lower()
        self.auth_secret = os.getenv("AUTH_SECRET")  # For simple bearer token
        
        # Rate limiting settings
        self.rate_limit_enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
        self.rate_limit_lockout_minutes = int(os.getenv("RATE_LIMIT_LOCKOUT_MINUTES", 5))
        self.rate_limit_max_attempts = int(os.getenv("RATE_LIMIT_MAX_ATTEMPTS", 1))
        
        # JWT settings
        self.jwt_public_key = os.getenv("JWT_PUBLIC_KEY")  # For JWT verification
        self.jwt_private_key = os.getenv("JWT_PRIVATE_KEY")  # For JWT signing (optional)
        self.jwt_issuer = os.getenv("JWT_ISSUER", "vivint-mcp-server")
        self.jwt_audience = os.getenv("JWT_AUDIENCE", "vivint-mcp-client")
        self.jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256")
        self.token_expiry_hours = int(os.getenv("TOKEN_EXPIRY_HOURS", 24))
        
        # OAuth settings
        self.oauth_client_id = os.getenv("OAUTH_CLIENT_ID")
        self.oauth_client_secret = os.getenv("OAUTH_CLIENT_SECRET")
        self.oauth_clients_file = os.getenv("OAUTH_CLIENTS_FILE", ".oauth_clients.json")
        self.oauth_redirect_uris = os.getenv("OAUTH_REDIRECT_URIS", 
            "https://claude.ai/api/mcp/auth_callback,http://localhost:3000/callback,http://localhost:8080/callback"
        ).split(",")
        
        # Cloudflare tunnel settings
        self.cloudflare_tunnel_url = os.getenv("CLOUDFLARE_TUNNEL_URL")  # e.g., https://your-tunnel.trycloudflare.com
        
        # Validate required settings
        self.validate()
    
    def validate(self):
        """Validate required configuration settings."""
        # Skip Vivint validation if we're just doing authentication tasks
        import sys
        if len(sys.argv) > 0 and 'generate_token.py' in sys.argv[0]:
            # Allow token generation without Vivint credentials
            pass
        else:
            if not self.username:
                raise ValueError("VIVINT_USERNAME environment variable is required")
            if not self.password:
                raise ValueError("VIVINT_PASSWORD environment variable is required")
        
        if self.log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            self.log_level = "INFO"
        
        # Validate authentication settings (skip during token/credential generation)
        import sys
        is_credential_generation = len(sys.argv) > 0 and ('generate_token.py' in sys.argv[0] or 'generate_oauth_credentials.py' in sys.argv[0])
        
        if self.auth_enabled and not is_credential_generation:
            if self.auth_type == "jwt":
                if self.jwt_algorithm.startswith("HS") and not self.auth_secret:
                    raise ValueError("AUTH_SECRET is required for HMAC JWT algorithms (HS256/384/512)")
                elif self.jwt_algorithm.startswith("RS") and not self.jwt_public_key:
                    raise ValueError("JWT_PUBLIC_KEY is required for RSA JWT algorithms (RS256/384/512)")
            elif self.auth_type == "bearer" and not self.auth_secret:
                raise ValueError("AUTH_SECRET is required for bearer token authentication")
            elif self.auth_type == "oauth":
                if not self.oauth_client_id or not self.oauth_client_secret:
                    raise ValueError("OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET are required for OAuth authentication")
        
        if self.auth_type not in ["jwt", "bearer", "oauth"]:
            raise ValueError("AUTH_TYPE must be one of 'jwt', 'bearer', or 'oauth'")
        
        if self.jwt_algorithm not in ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"]:
            self.jwt_algorithm = "HS256"
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment.lower() == "development"

# Global configuration instance
config = VivintConfig()