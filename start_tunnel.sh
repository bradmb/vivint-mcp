#!/bin/bash

# MCP Server Cloudflare Tunnel Starter
# This script starts a Cloudflare Quick Tunnel for the MCP server

set -e

# Configuration
MCP_PORT=8000
LOG_FILE=".cf_tunnel.log"
PID_FILE=".cf_tunnel.pid"
URL_FILE=".cf_tunnel.url"
MCP_URL_FILE=".mcp_public_url"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 MCP Server Tunnel Starter${NC}"
echo "================================"

# Check if cloudflared is installed
if ! command -v cloudflared &> /dev/null; then
    echo -e "${RED}❌ Error: cloudflared not found${NC}"
    echo "Install it with: brew install cloudflared"
    exit 1
fi

# Check if tunnel is already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo -e "${YELLOW}⚠️  Tunnel already running (PID: $OLD_PID)${NC}"
        if [ -f "$MCP_URL_FILE" ]; then
            echo -e "${GREEN}📡 Current MCP endpoint: $(cat $MCP_URL_FILE)${NC}"
        fi
        exit 0
    else
        echo -e "${YELLOW}🧹 Cleaning up stale PID file (process $OLD_PID no longer exists)${NC}"
        rm -f "$PID_FILE" "$LOG_FILE" "$URL_FILE" "$MCP_URL_FILE"
    fi
fi

# Check if MCP server is running
echo -e "${BLUE}🔍 Checking MCP server status...${NC}"
if ! lsof -nP -iTCP:$MCP_PORT -sTCP:LISTEN >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  MCP server not detected on port $MCP_PORT${NC}"
    echo "Please start your MCP server first with:"
    echo "  python src/server.py"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}✅ MCP server is running on port $MCP_PORT${NC}"
fi

# Clean up old files
rm -f "$LOG_FILE" "$URL_FILE" "$MCP_URL_FILE"

echo -e "${BLUE}🌐 Starting Cloudflare tunnel...${NC}"

# Start the tunnel
cloudflared tunnel --url http://localhost:$MCP_PORT > "$LOG_FILE" 2>&1 &
TUNNEL_PID=$!
echo $TUNNEL_PID > "$PID_FILE"

echo -e "${BLUE}⏳ Waiting for tunnel URL...${NC}"

# Wait for the tunnel URL to appear
CF_URL=""
for i in {1..60}; do
    CF_URL=$(grep -Eo 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$LOG_FILE" 2>/dev/null | head -n1)
    if [ -n "$CF_URL" ]; then
        break
    fi
    printf "."
    sleep 1
done

echo "" # New line after dots

if [ -z "$CF_URL" ]; then
    echo -e "${RED}❌ Error: Could not obtain tunnel URL${NC}"
    echo "Check the log file: $LOG_FILE"
    kill $TUNNEL_PID 2>/dev/null || true
    rm -f "$PID_FILE"
    exit 1
fi

# Save URLs
echo "$CF_URL" > "$URL_FILE"
MCP_PUBLIC_URL="${CF_URL}/mcp"
echo "$MCP_PUBLIC_URL" > "$MCP_URL_FILE"

# Auto-update OAuth redirect URIs if OAuth is configured
if [ -f "update_oauth_uris.py" ] && [ -f ".env" ]; then
    echo -e "${BLUE}🔧 Updating OAuth redirect URIs...${NC}"
    if grep -q "AUTH_TYPE=oauth" .env 2>/dev/null; then
        python update_oauth_uris.py --tunnel "$CF_URL" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ OAuth URIs updated for tunnel${NC}"
            echo -e "${YELLOW}💡 Restart MCP server to apply OAuth changes${NC}"
        fi
    fi
fi

# Display results
echo ""
echo -e "${GREEN}🎉 Tunnel started successfully!${NC}"
echo "================================"
echo -e "${BLUE}📡 Tunnel URL:${NC}     $CF_URL"
echo -e "${GREEN}🔗 MCP Endpoint:${NC}  $MCP_PUBLIC_URL"
echo -e "${YELLOW}📋 Process ID:${NC}    $TUNNEL_PID"
echo ""
echo -e "${BLUE}💡 Usage:${NC}"
echo "  • Connect MCP clients to: $MCP_PUBLIC_URL"
echo "  • Use transport: Streamable HTTP"
echo "  • Stop tunnel: kill $TUNNEL_PID"
echo ""
echo -e "${BLUE}📁 Files created:${NC}"
echo "  • $LOG_FILE (tunnel logs)"
echo "  • $PID_FILE (process ID)"
echo "  • $URL_FILE (tunnel URL)"
echo "  • $MCP_URL_FILE (MCP endpoint URL)"
echo ""

# Test the endpoint with retry strategy
echo -e "${BLUE}🧪 Testing endpoint (waiting for propagation)...${NC}"
echo -e "${BLUE}⏳ This may take 10-30 seconds...${NC}"

# Wait a bit for the tunnel to fully propagate
sleep 5

ENDPOINT_READY=false
for attempt in {1..6}; do
    printf "${BLUE}   Attempt $attempt/6: ${NC}"
    STATUS=$(curl -sS -o /dev/null -w "%{http_code}" -H "Accept: text/event-stream" --connect-timeout 5 --max-time 10 "$MCP_PUBLIC_URL" 2>/dev/null || echo "000")
    
    if [ "$STATUS" = "401" ]; then
        echo -e "${GREEN}✅ Success (401 - auth required, as expected)${NC}"
        ENDPOINT_READY=true
        break
    elif [ "$STATUS" -ge 200 ] && [ "$STATUS" -lt 500 ]; then
        echo -e "${GREEN}✅ Success (HTTP $STATUS)${NC}"
        ENDPOINT_READY=true
        break
    elif [ "$STATUS" = "000" ]; then
        echo -e "${YELLOW}⏳ Connection failed, retrying...${NC}"
    else
        echo -e "${YELLOW}⏳ Got HTTP $STATUS, retrying...${NC}"
    fi
    
    if [ $attempt -lt 6 ]; then
        sleep 5
    fi
done

if [ "$ENDPOINT_READY" = "true" ]; then
    echo -e "${GREEN}🎯 Endpoint is ready and responding!${NC}"
else
    echo -e "${YELLOW}⚠️  Endpoint test timed out${NC}"
    echo -e "${YELLOW}   The tunnel may still be establishing connection${NC}"
    echo -e "${YELLOW}   Try testing manually in a few minutes${NC}"
fi

echo ""
echo -e "${GREEN}🚀 Ready to accept MCP connections!${NC}"