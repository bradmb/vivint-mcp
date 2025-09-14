# Vivint Security System MCP Server

A [FastMCP](https://github.com/jlowin/fastmcp) server that provides read-only access to your Vivint home security system through the Model Context Protocol (MCP).

⚠️ **Important**: This integration uses an unofficial reverse-engineered API (`vivintpy`) as Vivint does not provide an official public API. Use at your own discretion.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/InteractionCo/mcp-server-template)

## Features

This MCP server provides 8 tools for accessing your Vivint security system:

- **`get_system_status`** - Overall security system state and armed status
- **`get_all_devices`** - Complete device inventory with health status
- **`get_security_sensors`** - Motion, door/window, smoke, and other security sensors
- **`get_cameras`** - Camera status and recording capabilities
- **`get_locks`** - Smart lock states and battery levels
- **`get_thermostats`** - Climate control data and settings
- **`get_recent_events`** - Recent system activity and events
- **`get_device_health`** - Device connectivity and battery status

## Prerequisites

- **Vivint Account**: Active Vivint home security system
- **Dedicated User**: Recommended to create a separate Vivint user for API access
- **2FA Support**: Full support for accounts with 2FA/MFA enabled (see 2FA Setup section)
- **Python 3.13+**: Required for FastMCP compatibility

## Local Development

### Setup

1. Fork and clone the repository:

```bash
git clone <your-repo-url>
cd mcp-server-template
```

2. Create and activate conda environment:

```bash
# Create the environment (only needed first time)
conda create -n mcp-server python=3.13

# Activate the environment
conda activate mcp-server

# Install dependencies
pip install -r requirements.txt
```

3. Configure your Vivint credentials and authentication:

```bash
cp .env.example .env
# Edit .env file with your credentials:
# VIVINT_USERNAME=your_vivint_username
# VIVINT_PASSWORD=your_vivint_password
```

4. **🔐 Setup Authentication** (Secure your server):

Generate a secure authentication key:
```bash
python src/generate_token.py --type secret
```

This will output something like:
```
AUTH_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2
```

Add this to your `.env` file to secure your server.

### Test

1. **Generate an access token**:
```bash
python src/generate_token.py --type token --hours 24
```

This outputs a JWT token you'll need for authentication.

2. **Start the server**:
```bash
python src/server.py
```

The server will show:
- 🔐 **Authentication enabled** - requires valid JWT tokens
- ⚠️ **Authentication disabled** - publicly accessible (if AUTH_ENABLED=false)

3. **Test with MCP Inspector**:
```bash
npx @modelcontextprotocol/inspector
```

4. **Connect with authentication**:
   - Open http://localhost:3000
   - Connect to `http://localhost:8000/mcp` using "Streamable HTTP" transport
   - **Important**: Include your JWT token in the Authorization header:
     ```
     Authorization: Bearer your-jwt-token-here
     ```

5. **Test the tools**:
   - `get_system_status()` - Check if your system is armed
   - `get_all_devices()` - See all your connected devices
   - `get_device_health()` - Check battery levels and connectivity

### Debug Mode

For troubleshooting, enable debug mode:

```bash
DEBUG_MODE=true LOG_LEVEL=DEBUG python src/server.py
```

## 🔐 2FA/MFA Setup

If your Vivint account has Two-Factor Authentication (2FA) enabled, the server now fully supports it with automatic token persistence.

### First-Time Setup with 2FA

**Option 1: Interactive Setup (Recommended)**
```bash
python setup_mfa.py
```
This script will:
- Guide you through the MFA process step-by-step
- Prompt for your 2FA code when needed (no expiry issues)
- Save tokens automatically for future use
- Test the connection to verify everything works

**Option 2: Environment Variable Method**
1. **Get your 2FA code**:
   - Check your Vivint app for a 6-digit code
   - Or check your email if you use email-based 2FA

2. **Set the MFA code temporarily**:
   ```bash
   export VIVINT_MFA_CODE=123456  # Your 6-digit code
   ```

3. **Start the server**:
   ```bash
   python src/server.py
   ```

**After successful setup**:
- Refresh tokens are saved to `.vivint_tokens.json`
- Future server restarts will use the saved tokens (no MFA required)
- Tokens are valid for ~6 hours and auto-refresh

### Configuration Options

Add these to your `.env` file for 2FA customization:

```bash
# Required: Your 2FA code (only for initial setup)
VIVINT_MFA_CODE=123456

# Optional: Custom token storage location
VIVINT_REFRESH_TOKEN_FILE=.vivint_tokens.json

# Optional: Wait for MFA input (for interactive setups)
VIVINT_MFA_AUTO_WAIT=false
```

### Token Management

The server automatically:
- ✅ **Saves refresh tokens** after successful MFA verification
- ✅ **Reuses tokens** on subsequent startups (no MFA needed)
- ✅ **Auto-refreshes** tokens before they expire
- ✅ **Handles expiration** gracefully by requesting new MFA
- ✅ **Per-user tokens** - different users get separate token files

### Troubleshooting 2FA

**"MFA code required" error**:
```bash
export VIVINT_MFA_CODE=123456
python src/server.py
```

**Tokens expired**:
- Server will automatically request a new MFA code
- Check logs for specific instructions

**Test your setup**:
```bash
python test_mfa.py  # Test MFA flow and token persistence
```

## 🔐 Authentication & Security

### Authentication Methods

The server supports JWT (JSON Web Token) authentication with two algorithms:

1. **HMAC (HS256) - Recommended for single-user setups**:
   - Uses a shared secret key
   - Simpler setup, perfect for personal use
   - Generate with: `python src/generate_token.py --type secret`

2. **RSA (RS256) - For multi-user or enterprise setups**:
   - Uses public/private key pairs  
   - More secure, supports multiple clients
   - Generate with: `python src/generate_token.py --type keypair`

### Token Management

**Generate tokens**:
```bash
# 24-hour token (default)
python src/generate_token.py --type token

# Custom expiry
python src/generate_token.py --type token --hours 168  # 1 week

# Custom user
python src/generate_token.py --type token --subject "john-doe"
```

**Verify tokens**:
```bash
python src/generate_token.py --verify "your-jwt-token-here"
```

### Client Authentication

**For MCP Inspector**:
Add the Authorization header when connecting:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**For programmatic clients**:
```python
import httpx

headers = {
    "Authorization": f"Bearer {your_jwt_token}",
    "Content-Type": "application/json"
}

response = httpx.post("http://localhost:8000/mcp", headers=headers, json=request)
```

### Disabling Authentication

For development or trusted network environments:
```bash
# In .env file
AUTH_ENABLED=false
```

⚠️ **Warning**: Only disable authentication if your server is not accessible from the internet.

## Deployment

### Render Deployment

1. **One-Click Deploy**: Click the "Deploy to Render" button above, or:

2. **Manual Deployment**:
   - Fork this repository
   - Connect your GitHub account to Render
   - Create a new Web Service on Render
   - Connect your forked repository
   - Render will automatically detect the `render.yaml` configuration

3. **Environment Variables**: In your Render service settings, add:
   - `VIVINT_USERNAME`: Your Vivint username
   - `VIVINT_PASSWORD`: Your Vivint password
   - `AUTH_SECRET`: Generated secret key (from `generate_token.py`)
   - `AUTH_ENABLED`: Set to `true` for production security
   - `ENVIRONMENT`: Set to `production`
   - `LOG_LEVEL`: Set to `WARNING` or `ERROR` for production

Your **authenticated** server will be available at `https://your-service-name.onrender.com/mcp` (NOTE THE `/mcp`!)

### Security Considerations

- **🔐 Always enable authentication in production** (`AUTH_ENABLED=true`)
- **Never commit your `.env` file** - it contains sensitive credentials and auth secrets
- Use a dedicated Vivint user account for API access
- Rotate authentication secrets regularly in production
- Consider additional network security (VPN, IP restrictions)
- Monitor authentication logs for suspicious activity
- Consider the legal implications of using an unofficial API
- Monitor for any changes to the `vivintpy` library

## Architecture

### Core Components

- **`src/server.py`**: Main FastMCP server with 8 Vivint tools
- **`src/vivint_client.py`**: Vivint API client wrapper with session management
- **`src/config.py`**: Configuration and environment variable management
- **`.env.example`**: Template for environment configuration

### Session Management

The client automatically handles:
- Initial authentication with Vivint API
- 15-minute keepalive cycles to maintain session
- Automatic re-authentication when tokens expire (6-hour limit)
- Connection pooling and retry logic
- Graceful error handling and recovery

## Limitations & Disclaimers

⚠️ **Unofficial API**: This integration relies on reverse-engineered API access through the `vivintpy` library. Vivint does not provide an official public API.

⚠️ **Service Stability**: Vivint may change their internal APIs at any time, potentially breaking this integration.

⚠️ **Terms of Service**: Using unofficial API methods may violate Vivint's Terms of Service. Use responsibly and at your own risk.

⚠️ **Read-Only Access**: This server only provides read access to your Vivint system data. It cannot control devices or change settings.

## Troubleshooting

### Common Issues

1. **Authentication Failed**:
   - Verify username/password in `.env` file
   - Ensure account doesn't have 2FA enabled
   - Try creating a dedicated user account

2. **Connection Timeouts**:
   - Check internet connectivity
   - Enable debug mode to see detailed logs
   - Verify Vivint services are operational

3. **No Devices Found**:
   - Confirm your account has access to the system
   - Check if you have multiple systems (may need `VIVINT_SYSTEM_ID`)
   - Review system permissions

### Getting Help

- Check the logs with `DEBUG_MODE=true`
- Review the `vivintpy` library documentation
- Consider contacting Vivint for official API access

## Contributing

Contributions are welcome! Please:
- Test changes thoroughly with your Vivint system
- Update documentation for any new features
- Follow existing code patterns and error handling
- Be mindful of rate limiting and API usage

## License

MIT License - see LICENSE file for details.

**Disclaimer**: This project is not affiliated with or endorsed by Vivint. Use at your own risk.
