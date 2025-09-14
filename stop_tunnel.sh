#!/bin/bash

# MCP Server Cloudflare Tunnel Stopper
# This script stops the Cloudflare tunnel and cleans up files

# Configuration
PID_FILE=".cf_tunnel.pid"
LOG_FILE=".cf_tunnel.log"
URL_FILE=".cf_tunnel.url"
MCP_URL_FILE=".mcp_public_url"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛑 MCP Server Tunnel Stopper${NC}"
echo "================================"

# Check if PID file exists
if [ ! -f "$PID_FILE" ]; then
    echo -e "${YELLOW}⚠️  No tunnel PID file found${NC}"
    echo "Tunnel may not be running or was started manually"
else
    PID=$(cat "$PID_FILE")
    
    # Check if process is still running
    if kill -0 "$PID" 2>/dev/null; then
        echo -e "${BLUE}🔄 Stopping tunnel (PID: $PID)...${NC}"
        kill "$PID" 2>/dev/null || true
        
        # Wait a moment for graceful shutdown
        sleep 2
        
        # Force kill if still running
        if kill -0 "$PID" 2>/dev/null; then
            echo -e "${YELLOW}⚠️  Force killing tunnel...${NC}"
            kill -9 "$PID" 2>/dev/null || true
        fi
        
        echo -e "${GREEN}✅ Tunnel stopped${NC}"
    else
        echo -e "${YELLOW}🧹 Tunnel process not found (PID $PID was stale)${NC}"
        echo -e "${BLUE}Proceeding with cleanup...${NC}"
    fi
fi

# Clean up files
echo -e "${BLUE}🧹 Cleaning up files...${NC}"
FILES_REMOVED=0

for file in "$PID_FILE" "$LOG_FILE" "$URL_FILE" "$MCP_URL_FILE"; do
    if [ -f "$file" ]; then
        rm -f "$file"
        echo -e "${GREEN}  ✓ Removed $file${NC}"
        FILES_REMOVED=$((FILES_REMOVED + 1))
    fi
done

if [ $FILES_REMOVED -eq 0 ]; then
    echo -e "${YELLOW}  No files to clean up${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Cleanup complete!${NC}"
echo -e "${BLUE}💡 To start a new tunnel, run: ./start_tunnel.sh${NC}"