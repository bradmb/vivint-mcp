# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## MCP Server Template

A minimal FastMCP server template for Render deployment with streamable HTTP transport.

### Repository Structure

- `src/server.py`: Single entrypoint. Defines FastMCP app, registers tools, and runs the HTTP transport on `/mcp`
- `requirements.txt`: Python dependencies (fastmcp, uvicorn)
- `render.yaml`: Render deployment configuration
- `README.md`: Quickstart for local usage and Render deployment

### Development Commands

**Setup:**
```bash
# Clone your fork
git clone <your-repo-url>
cd mcp-server-template

# Python environment
conda create -n mcp-server python=3.13
conda activate mcp-server

# Install dependencies
pip install -r requirements.txt
```

**Run locally:**
```bash
# Default port (falls back to 8000)
python src/server.py

# Explicit port
PORT=8000 python src/server.py
```

**Test locally with MCP Inspector:**
```bash
# Start the server first (see above), then in another terminal:
npx @modelcontextprotocol/inspector
# In the Inspector:
# - Transport: "Streamable HTTP"
# - URL: http://localhost:8000/mcp   (NOTE the /mcp suffix)
```

Expected tools visible in Inspector: `greet`, `get_server_info`.

### High-level Architecture (FastMCP Integration)

- `fastmcp.FastMCP` is used to register tools and serve the MCP server over HTTP
- `src/server.py` structure:
  - `mcp = FastMCP("Sample MCP Server")`
  - `@mcp.tool(...)` decorated functions define MCP tools
  - `mcp.run(transport="http", host=..., port=...)` starts a streamable HTTP endpoint
- Endpoint base path: `/mcp` (FastMCP's HTTP transport exposes the MCP API at this route)
- Server is stateless; tools must return JSON-serializable values

### Key Development Patterns for Adding Tools

- Define synchronous functions with clear type hints and JSON-serializable returns
- Register with `@mcp.tool` and provide a concise description (used by clients like Inspector)
- Validate inputs and raise `ValueError` with actionable messages for client-friendly errors
- Keep side effects minimal; return structured dicts for non-trivial outputs

**Example:**
```python
from fastmcp import FastMCP

mcp = FastMCP("Sample MCP Server")

@mcp.tool(description="Perform basic arithmetic operations.")
def calculate(x: float, y: float, operation: str = "add") -> float:
    if operation == "add":
        return x + y
    elif operation == "multiply":
        return x * y
    elif operation == "subtract":
        return x - y
    elif operation == "divide":
        if y == 0:
            raise ValueError("Division by zero.")
        return x / y
    else:
        raise ValueError(f"Unsupported operation: {operation}")
```

No extra wiring needed; FastMCP auto-exposes the tool.

### Local Development and Testing Workflow

1. Start local server: `python src/server.py`
2. Start Inspector: `npx @modelcontextprotocol/inspector`
3. Connect with:
   - Transport: Streamable HTTP
   - URL: `http://localhost:8000/mcp`
4. Smoke tests:
   - Call `get_server_info` and verify environment and Python version values
   - Call `greet` with a custom name and confirm string response

**If Inspector can't connect, confirm:**
- The server process is running
- You used the `/mcp` path
- The chosen port matches PORT or default 8000

### Deployment to Render

**Two options:**
1. One-click via the button in README (Render detects `render.yaml`)
2. Manual web service:
   - Connect your forked repo
   - Build: `pip install -r requirements.txt`
   - Start command: `python src/server.py`
   - Environment:
     - PORT is provided by Render automatically
     - Set `ENVIRONMENT=production` (used by `get_server_info`)

**Post-deploy:**
- Your service URL + `/mcp` is the public MCP endpoint
- Use Inspector with Streamable HTTP to connect to that public `/mcp` URL

### HTTP Transport and Endpoint Details

- Transport: Streamable HTTP via FastMCP (JSON over HTTP with server-sent streams)
- Base path: `/mcp` (required; clients must include this path)
- Host/Port:
  - Port comes from PORT env var (Render supplies this); defaults to 8000 locally
  - Host must bind to all interfaces in containers (`0.0.0.0`) for Render
- Clients must explicitly use Streamable HTTP; WebSocket transport is not used here

### Important Technical Notes and Quirks

**Host binding in `src/server.py`:**
- The file currently has a redacted host value. For local and Render, use `0.0.0.0` (container) or `127.0.0.1` (strict local)
- Recommended patch:
  ```python
  host = os.environ.get("HOST", "0.0.0.0")
  ```

**Response text in `greet` mentions "Heroku":** This repository targets Render. Adjust copy if desired.

**ENVIRONMENT variable:**
- `get_server_info` reads ENVIRONMENT (defaults to "development")
- Set `ENVIRONMENT=production` in Render for accurate reporting

### Quick Command Reference

```bash
# Setup
conda create -n mcp-server python=3.13
conda activate mcp-server
pip install -r requirements.txt

# Run
python src/server.py
# or
PORT=8000 python src/server.py

# Inspect
npx @modelcontextprotocol/inspector
# Connect to: http://localhost:8000/mcp  (Streamable HTTP)
```