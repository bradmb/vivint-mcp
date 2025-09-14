# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Vivint Security System MCP (Model Context Protocol) server built with FastMCP. It provides read-only access to Vivint home security systems through 8 specialized tools, using the unofficial `vivintpy` library for API access.

## Key Commands

### Development Setup
```bash
# Create and activate conda environment (Python 3.13+ required)
conda create -n mcp-server python=3.13
conda activate mcp-server
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with credentials and settings
```

### Running the Server
```bash
# Standard run
python src/server.py

# Debug mode
DEBUG_MODE=true LOG_LEVEL=DEBUG python src/server.py

# Test Vivint connection
python test_vivint_connection.py

# Test with MCP Inspector
npx @modelcontextprotocol/inspector
# Connect to http://localhost:8000/mcp with Authorization header
```

### Authentication Management
```bash
# Generate authentication secret (HMAC JWT)
python src/generate_token.py --type secret

# Generate JWT access token
python src/generate_token.py --type token --hours 24

# Generate OAuth client credentials
python src/generate_oauth_credentials.py

# Verify JWT token
python src/generate_token.py --verify "token-here"

# Setup MFA/2FA (interactive)
python setup_mfa.py
```

### OAuth Testing
```bash
# Test OAuth flow
python src/simple_oauth_test.py

# Manual OAuth flow test
curl -X POST "http://localhost:8000/oauth/authorize" \
  -d "response_type=code&client_id=test-client&redirect_uri=https://claude.ai/api/mcp/auth_callback&scope=claudeai&state=test123&username=test@example.com&password=test123&action=login"
```

## Architecture

### Core Components

1. **`src/server.py`** - Main FastMCP server (1572+ lines)
   - Implements 8 Vivint tools (get_system_status, get_all_devices, etc.)
   - OAuth routes at `/oauth/authorize`, `/authorize`, `/oauth/token`, `/token`
   - Uses `_get_oauth_provider()` helper for OAuth provider consistency
   - Supports both standard and `/oauth/` prefixed routes for compatibility
   - Registers clients from `config.oauth_redirect_uris` (comma-separated list)

2. **`src/vivint_client.py`** - Vivint API wrapper
   - Session persistence with 20-minute timeout, 6-hour token refresh
   - MFA/2FA authentication with token persistence to `.vivint_tokens.json`
   - Automatic reconnection and keepalive mechanism
   - Maps Vivint structure: System → AlarmPanels → Devices

3. **`src/config.py`** - Configuration management
   - Validates all environment variables
   - `OAUTH_REDIRECT_URIS`: Comma-separated list of allowed redirect URIs
   - `CLOUDFLARE_TUNNEL_URL`: For Cloudflare tunnel deployments
   - Supports JWT (HMAC/RSA), OAuth, and bearer token auth

4. **`src/template_free_oauth_provider.py`** - OAuth implementation
   - Generates HTML directly (no Jinja2 - avoids Python 3.13 issues)
   - Auto-registers Claude Desktop clients
   - Vivint authentication as security layer
   - Placeholder PKCE values when not provided

### OAuth Flow

Custom OAuth implementation with Vivint authentication:
1. Client requests `/oauth/authorize` or `/authorize`
2. Server shows login form (auto-registers unknown clients)
3. User authenticates with Vivint credentials
   - Test credentials: `test@example.com` / `test123`
   - Or actual Vivint credentials from environment
4. Server issues authorization code
5. Client exchanges code at `/oauth/token` or `/token`

### Authentication Types

- **JWT (HMAC/RSA)**: Primary method using Bearer tokens
- **OAuth 2.0**: Full flow with Vivint authentication
- **Bearer Token**: Simple token auth (legacy)

## Important Implementation Details

### Vivint Data Structure
- Devices nested under AlarmPanels, not directly under System
- Lock state in `is_locked` attribute (not "state" field)
- Battery levels need int conversion and null handling
- Session expires after 20 minutes, tokens after 6 hours

### OAuth Specifics
- Both `/authorize` and `/oauth/authorize` routes registered
- Auto-registers clients with Claude callback: `https://claude.ai/api/mcp/auth_callback`
- PKCE parameters use defaults when not provided
- Form POST preserves OAuth parameters via hidden fields
- `_get_oauth_provider()` ensures consistent client registration

### MFA/2FA Handling
- Tokens stored in `.vivint_tokens.json` (or `VIVINT_REFRESH_TOKEN_FILE`)
- Automatic refresh before expiry
- Interactive setup via `setup_mfa.py` recommended
- Per-user token files for multi-user support

### Error Handling Patterns
- All tools return error dictionaries with timestamps
- Vivint client auto-reconnects on session expiry
- OAuth provider handles missing clients gracefully
- Template-free implementation avoids Jinja2 issues

## Environment Variables

Critical settings that must be configured:
- `VIVINT_USERNAME` - Vivint account username
- `VIVINT_PASSWORD` - Vivint account password
- `AUTH_SECRET` or JWT keys - For authentication
- `OAUTH_CLIENT_ID/SECRET` - For OAuth flow (generate via script)
- `OAUTH_REDIRECT_URIS` - Comma-separated list of allowed redirect URIs
- `CLOUDFLARE_TUNNEL_URL` - If running behind Cloudflare tunnel

Security settings:
- `OAUTH_DISABLE_NEW_CLIENTS=true` - Completely disable OAuth client registration AND authorization (production lockdown)
- `RATE_LIMIT_ENABLED=true` - Enable login rate limiting (default: enabled)
- `DEBUG_MODE=false` - Disable debug endpoints in production (default: false)

## Common Issues and Solutions

1. **"jinja2 must be installed"** → Use `template_free_oauth_provider.py`
2. **"Redirect URI not registered"** → Provider auto-registers clients now
3. **Lock showing wrong state** → Use `is_locked` attribute, not "state"
4. **MFA code expired** → Use `setup_mfa.py` for interactive setup
5. **OAuth route conflicts** → Both `/authorize` and `/oauth/authorize` registered
6. **PKCE validation errors** → Provider uses placeholder values when not provided
7. **Port already in use** → Kill existing process: `lsof -ti :8000 | xargs kill -9`

## Recent Updates

The server has been updated with:
- Full OAuth 2.0 support with `/authorize` and `/oauth/authorize` routes
- Auto-registration of Claude Desktop clients
- Support for comma-separated `OAUTH_REDIRECT_URIS` in config
- `_get_oauth_provider()` helper for consistent OAuth provider handling
- Cloudflare tunnel support via `CLOUDFLARE_TUNNEL_URL`
- Template-free OAuth provider to avoid Jinja2 dependencies
- Enhanced logging for OAuth flow debugging

## MCP Tools Reference

1. **`get_system_status`** - Overall armed status and alerts
2. **`get_all_devices`** - Complete device inventory with health
3. **`get_security_sensors`** - Motion, door/window, smoke sensors
4. **`get_cameras`** - Camera status and recording capabilities
5. **`get_locks`** - Smart lock states and battery levels
6. **`get_thermostats`** - Climate control data
7. **`get_recent_events`** - Last 24 hours of activity
8. **`get_device_health`** - Connectivity and battery status