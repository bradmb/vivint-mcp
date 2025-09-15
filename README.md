# Vivint Security System MCP Server

A FastMCP server that exposes read-only access to your Vivint home security system over the Model Context Protocol (MCP) via Streamable HTTP at the /mcp endpoint.

Important: This integration uses an unofficial, reverse‑engineered API (vivintpy). Vivint has no official public API. Use at your own risk and review your Terms of Service.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/InteractionCo/mcp-server-template)

## Features

Eight read-only tools are exposed to MCP clients:

- get_system_status — Overall system armed state and metadata
- get_all_devices — Complete device inventory
- get_security_sensors — Motion/door/window/smoke/CO/flood sensors
- get_cameras — Camera status and capabilities
- get_locks — Smart lock states and battery level
- get_thermostats — Climate data and setpoints
- get_recent_events — Recent activity snapshots
- get_device_health — Battery/online/attention summaries

Endpoint base path: /mcp (clients must include this path).

## Prerequisites

- Python 3.13+
- A Vivint account (recommend a dedicated, least‑privilege user)
- Node.js (for MCP Inspector via npx)
- Optional: Cloudflared (to expose your local server)
- macOS, Linux, or Windows. Commands below use macOS/zsh patterns.

## Quick start (local)

1) Clone and enter the project

```bash
cd /Users/brad/GitHub
# Or your workspace directory
# git clone <your-remote> mcp-server-template
cd mcp-server-template
```

2) Create an environment and install dependencies

Option A: venv
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Option B: conda
```bash
conda create -n mcp-server python=3.13 -y
conda activate mcp-server
pip install -r requirements.txt
```

3) Configure environment

```bash
cp .env.example .env
# Edit .env and set at minimum:
# VIVINT_USERNAME=your_email@example.com
# VIVINT_PASSWORD=your_password
```

4) Enable authentication (recommended)

Generate a strong HMAC secret and add it to .env:
```bash
python src/generate_token.py --type secret
# Copy the printed AUTH_SECRET=... into your .env
# Ensure AUTH_ENABLED=true, AUTH_TYPE=jwt, JWT_ALGORITHM=HS256
```

Generate a short‑lived JWT for local testing:
```bash
python src/generate_token.py --type token --hours 24 --subject local-dev
```

5) Start the server

```bash
python src/server.py
# Endpoint: http://localhost:8000/mcp
```

6) Test with MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```
Then connect with:
- Transport: Streamable HTTP
- URL: http://localhost:8000/mcp
- If AUTH_ENABLED=true: add the header Authorization: Bearer <your_jwt>

## Example .env

Copy/paste and edit values as needed. Do not commit this file.

```bash
# Environment
ENVIRONMENT=development
PORT=8000
# HOST optional; defaults internally (container vs. strict local)
# HOST=*******

# Logging / debug
DEBUG_MODE=false
LOG_LEVEL=INFO

# Vivint credentials (required)
VIVINT_USERNAME=your_email@example.com
VIVINT_PASSWORD=your_password
# If you have multiple systems, set a specific one
# VIVINT_SYSTEM_ID=

# Session management (seconds)
SESSION_REFRESH_INTERVAL=900
TOKEN_REFRESH_INTERVAL=18000

# Authentication (recommended in all environments)
AUTH_ENABLED=true
AUTH_TYPE=jwt
JWT_ALGORITHM=HS256
AUTH_SECRET=replace-with-strong-secret
JWT_ISSUER=vivint-mcp-server
JWT_AUDIENCE=vivint-mcp-client
TOKEN_EXPIRY_HOURS=24

# 2FA/MFA
# VIVINT_MFA_CODE=123456
VIVINT_REFRESH_TOKEN_FILE=.vivint_tokens.json
VIVINT_MFA_AUTO_WAIT=false

# OAuth (optional)
# OAUTH_CLIENT_ID=
# OAUTH_CLIENT_SECRET=
OAUTH_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback,http://localhost:3000/callback,http://localhost:8080/callback
OAUTH_DISABLE_NEW_CLIENTS=false
# CLOUDFLARE_TUNNEL_URL=https://your-tunnel.trycloudflare.com

# Rate limiting for login endpoints
RATE_LIMIT_ENABLED=true
RATE_LIMIT_LOCKOUT_MINUTES=5
RATE_LIMIT_MAX_ATTEMPTS=1
```

Notes:
- The server binds to HOST and PORT (defaults provided). For containers, bind‑all is recommended; for strict local, use a loopback address. The default HOST in code is redacted (*******).
- All URLs must include the /mcp base path.

## Authentication options

JWT (HMAC, HS256) — recommended for single‑user/local
- Generate secret: python src/generate_token.py --type secret
- Configure .env: AUTH_ENABLED=true, AUTH_TYPE=jwt, JWT_ALGORITHM=HS256, AUTH_SECRET=...
- Create token: python src/generate_token.py --type token --hours 24 --subject local-dev
- Verify token: python src/generate_token.py --verify "<token>"
- Use with Inspector: Authorization: Bearer <token>

JWT (RSA, RS256) — multi‑client
- Generate keys: python src/generate_token.py --type keypair
- Configure .env: JWT_PRIVATE_KEY, JWT_PUBLIC_KEY, JWT_ALGORITHM=RS256
- Generate tokens with the private key (same script) and verify with the public key.

OAuth 2.0 — optional
- Generate a client: python src/generate_oauth_credentials.py
- Ensure OAUTH_REDIRECT_URIS includes https://claude.ai/api/mcp/auth_callback (for Claude) and any local callbacks.
- Start the server and complete the flow using the server’s OAuth endpoints. In production, consider setting OAUTH_DISABLE_NEW_CLIENTS=true.

Disable auth (development only)
```bash
# In .env
AUTH_ENABLED=false
```
Warning: Do not disable authentication if your server is reachable from the internet.

## 2FA/MFA setup and token persistence

Interactive (recommended)
```bash
python setup_mfa.py
```
What it does:
- Prompts for a fresh 6‑digit code when required
- Saves refresh tokens to VIVINT_REFRESH_TOKEN_FILE (default: .vivint_tokens.json)
- Validates the connection

Non‑interactive (one‑off)
```bash
export VIVINT_MFA_CODE=123456
python src/server.py
```

Validation
```bash
python test_mfa.py
```
Token file security: treat .vivint_tokens.json as a secret and restrict permissions (chmod 600).

## Running and debugging

Start:
```bash
python src/server.py
```
Explicit host/port:
```bash
HOST=********* PORT=8000 python src/server.py
```
Verbose logs:
```bash
DEBUG_MODE=true LOG_LEVEL=DEBUG python src/server.py
```
Debug endpoint (when available): /debug/oauth requires DEBUG_MODE=true.

## Testing with MCP Inspector

- Launch: npx @modelcontextprotocol/inspector
- Transport: Streamable HTTP
- URL: http://localhost:8000/mcp
- If auth enabled: add Authorization: Bearer <token>
- Try tools: get_system_status, get_all_devices, get_device_health

## Cloudflare tunnel (optional)

If you want to test over the internet without opening ports:

Helper scripts in repo:
```bash
./start_tunnel.sh       # Starts a Quick Tunnel, prints public URL and saves it to .mcp_public_url
./tunnel_status.sh      # Shows status and tests the endpoint
./stop_tunnel.sh        # Stops the tunnel and cleans up
```
OAuth redirect URIs can be updated automatically:
```bash
python update_oauth_uris.py --auto-tunnel
```
Manual alternative:
```bash
cloudflared tunnel --url http://localhost:8000
# Your MCP endpoint is: https://<random>.trycloudflare.com/mcp
```

## Deploying to Render

Use the button above or set up a Web Service that runs:
- Build: pip install -r requirements.txt
- Start: python src/server.py

Environment variables (minimum):
- ENVIRONMENT=production
- AUTH_ENABLED=true
- AUTH_TYPE=jwt (or oauth)
- For JWT HS: AUTH_SECRET=<strong-secret>, JWT_ALGORITHM=HS256
- For JWT RS: JWT_PRIVATE_KEY, JWT_PUBLIC_KEY, JWT_ALGORITHM=RS256
- VIVINT_USERNAME, VIVINT_PASSWORD
- Optional: VIVINT_SYSTEM_ID, LOG_LEVEL=WARNING/ERROR

Your endpoint will be: https://<service>.onrender.com/mcp

## Tool reference

- get_system_status() → { armed, arm_state, is_disarmed, is_armed_stay, is_armed_away, system_id, panel_id, panel_name, timestamp, ... }
- get_all_devices() → [ { id, name, type, panel_id, system_id, state, is_online, battery_level, last_update_time, ... } ]
- get_security_sensors() → [ { id, name, sensor_type, triggered, bypassed, zone_id, ... } ]
- get_cameras() → [ { id, name, resolution, night_vision, motion_detection, rtsp_available, ... } ]
- get_locks() → [ { id, name, locked, tamper_status, battery_level, last_operated_at, ... } ]
- get_thermostats() → [ { id, name, current_temperature, target_temperature, heat_setpoint, cool_setpoint, mode, ... } ]
- get_recent_events(hours=24) → [ { id, type, description, timestamp, device_id, device_name } ]
- get_device_health() → { total_devices, online_devices, offline_devices, low_battery_devices, devices_needing_attention, ... }

Return fields are best‑effort and depend on your account/devices; errors are returned as { error, timestamp }.

## Architecture

Core files
- src/server.py — FastMCP app, auth setup (JWT/OAuth), tool registration, HTTP transport on /mcp
- src/vivint_client.py — vivintpy wrapper, session lifecycle, MFA handling
- src/token_manager.py — secure token persistence and validation
- src/config.py — environment variable parsing and validation
- setup_mfa.py, test_mfa.py — interactive MFA onboarding and validation
- start_tunnel.sh, tunnel_status.sh, stop_tunnel.sh — Cloudflared helpers
- render.yaml — Render deployment config

Session notes
- Sessions are refreshed periodically; tokens auto‑refresh ~5–6 hours
- Device and state shapes come from vivintpy and can change upstream

## Troubleshooting

Authentication
- “AUTH_SECRET is required” → Add AUTH_SECRET for HS* or JWT_PUBLIC_KEY for RS*
- “MFA required” → export VIVINT_MFA_CODE or run setup_mfa.py
- OAuth redirect mismatch → Ensure the exact URL is in OAUTH_REDIRECT_URIS, restart server

Connectivity
- Inspector can’t connect → Server running? Port correct? URL includes /mcp?
- Render 502 → Ensure HOST/PORT are correct for container; ENVIRONMENT=production

Devices
- No devices → Confirm account/system access; set VIVINT_SYSTEM_ID when multiple systems exist

Rate limits
- Login locked → Adjust RATE_LIMIT_* or wait for lockout to expire

Debugging
- DEBUG_MODE=true LOG_LEVEL=DEBUG for verbose logs
- /debug/oauth (if enabled) inspects OAuth configuration

## Security

- Keep AUTH_ENABLED=true in production
- Rotate AUTH_SECRET/keys regularly
- Use a dedicated Vivint user
- Do not commit .env or token files; treat .vivint_tokens.json as a secret (chmod 600)
- Keep DEBUG_MODE=false in production
- Be mindful that vivintpy is unofficial and may break without notice

## Limitations & disclaimers

- Unofficial API usage via vivintpy (no guarantees; subject to breakage)
- Read‑only access only; no device control
- May violate provider terms — proceed responsibly

## License

MIT — see LICENSE.

This project is not affiliated with or endorsed by Vivint.
