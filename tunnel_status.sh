#!/bin/bash

# MCP Server Cloudflare Tunnel Status Checker
# This script checks the current status of the tunnel

# Configuration
PID_FILE=".cf_tunnel.pid"
URL_FILE=".cf_tunnel.url"
MCP_URL_FILE=".mcp_public_url"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}📊 MCP Server Tunnel Status${NC}"
echo "================================"

# Check if tunnel is running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    
    if kill -0 "$PID" 2>/dev/null; then
        echo -e "${GREEN}✅ Tunnel is RUNNING${NC}"
        echo -e "${BLUE}📋 Process ID:${NC} $PID"
        
        if [ -f "$URL_FILE" ]; then
            TUNNEL_URL=$(cat "$URL_FILE")
            echo -e "${BLUE}📡 Tunnel URL:${NC} $TUNNEL_URL"
        fi
        
        if [ -f "$MCP_URL_FILE" ]; then
            MCP_URL=$(cat "$MCP_URL_FILE")
            echo -e "${GREEN}🔗 MCP Endpoint:${NC} $MCP_URL"
            
            # Test the endpoint with brief retry
            echo ""
            echo -e "${BLUE}🧪 Testing endpoint...${NC}"
            
            ENDPOINT_READY=false
            for attempt in {1..3}; do
                STATUS=$(curl -sS -o /dev/null -w "%{http_code}" -H "Accept: text/event-stream" --connect-timeout 3 --max-time 8 "$MCP_URL" 2>/dev/null || echo "000")
                
                if [ "$STATUS" = "401" ]; then
                    echo -e "${GREEN}✅ Endpoint responding (401 - auth required)${NC}"
                    ENDPOINT_READY=true
                    break
                elif [ "$STATUS" -ge 200 ] && [ "$STATUS" -lt 500 ]; then
                    echo -e "${GREEN}✅ Endpoint responding (HTTP $STATUS)${NC}"
                    ENDPOINT_READY=true
                    break
                elif [ "$STATUS" = "000" ] && [ $attempt -lt 3 ]; then
                    printf "${YELLOW}   Connection failed, retrying... ${NC}"
                    sleep 2
                fi
            done
            
            if [ "$ENDPOINT_READY" = "false" ]; then
                echo -e "${RED}❌ Endpoint not responding (HTTP $STATUS)${NC}"
                echo -e "${YELLOW}   Tunnel may still be establishing connection${NC}"
            fi
        fi
        
        echo ""
        echo -e "${YELLOW}💡 Management:${NC}"
        echo "  • Stop tunnel: ./stop_tunnel.sh"
        echo "  • View logs: tail -f .cf_tunnel.log"
        
    else
        echo -e "${RED}❌ Tunnel process not found (PID: $PID)${NC}"
        echo -e "${YELLOW}🧹 This appears to be a stale PID file${NC}"
        echo -e "${YELLOW}💡 Clean up with: ./stop_tunnel.sh${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Tunnel is NOT RUNNING${NC}"
    echo -e "${BLUE}💡 Start tunnel with: ./start_tunnel.sh${NC}"
fi

echo ""

# Check MCP server status
echo -e "${BLUE}🔍 MCP Server Status:${NC}"
if lsof -nP -iTCP:8000 -sTCP:LISTEN >/dev/null 2>&1; then
    echo -e "${GREEN}✅ MCP server is running on port 8000${NC}"
else
    echo -e "${RED}❌ MCP server not detected on port 8000${NC}"
fi