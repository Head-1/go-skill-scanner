#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

MCP_URL=${MCP_URL:-"http://localhost:8081"}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     GSS ↔ AEGIS Integration Test                         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# 1. Healthcheck
echo -e "${YELLOW}🔍 Testing healthcheck...${NC}"
if curl -s -f "${MCP_URL}/health" > /dev/null; then
    echo -e "${GREEN}✅ Healthcheck OK${NC}"
else
    echo -e "${RED}❌ Healthcheck failed - is MCP server running?${NC}"
    echo "   Run: go run cmd/scanner/main.go mcp"
    exit 1
fi
echo ""

# 2. List tools
echo -e "${YELLOW}🔧 Listing available tools...${NC}"
curl -s -X POST "${MCP_URL}/mcp" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1
    }' | jq '.' || echo -e "${RED}Failed to parse response${NC}"
echo ""

# 3. Test clean payload
echo -e "${YELLOW}✅ Testing CLEAN payload...${NC}"
curl -s -X POST "${MCP_URL}/mcp" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "gss_scan",
            "arguments": {
                "payload": "print(\"Hello, world!\")",
                "payload_type": "code",
                "options": {
                    "enable_ast": false
                }
            }
        },
        "id": 2
    }' | jq '.' || echo -e "${RED}Failed to parse response${NC}"
echo ""

# 4. Test malicious payload
echo -e "${YELLOW}🔴 Testing MALICIOUS payload...${NC}"
curl -s -X POST "${MCP_URL}/mcp" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "gss_scan",
            "arguments": {
                "payload": "import os; os.system(\"rm -rf / --no-preserve-root\")",
                "payload_type": "code",
                "options": {
                    "enable_ast": true,
                    "timeout_ms": 5000
                }
            }
        },
        "id": 3
    }' | jq '.' || echo -e "${RED}Failed to parse response${NC}"
echo ""

# 5. Test file scan (if file exists)
if [ -f "./test_payload.py" ]; then
    echo -e "${YELLOW}📁 Testing file scan...${NC}"
    curl -s -X POST "${MCP_URL}/mcp" \
        -H "Content-Type: application/json" \
        -d '{
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "gss_scan",
                "arguments": {
                    "payload": "./test_payload.py",
                    "payload_type": "file",
                    "options": {
                        "enable_ast": true
                    }
                }
            },
            "id": 4
        }' | jq '.' || echo -e "${RED}Failed to parse response${NC}"
else
    echo -e "${YELLOW}📁 Skipping file scan (test_payload.py not found)${NC}"
fi
echo ""

# 6. Test error case (missing required field)
echo -e "${YELLOW}⚠️ Testing error handling...${NC}"
curl -s -X POST "${MCP_URL}/mcp" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "gss_scan",
            "arguments": {
                "wrong_field": "test"
            }
        },
        "id": 5
    }' | jq '.' || echo -e "${RED}Failed to parse response${NC}"
echo ""

echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     All tests completed                                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
