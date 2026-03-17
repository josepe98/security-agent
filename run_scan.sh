#!/bin/bash
# ──────────────────────────────────────────────
# Web Security Agent - Quick Runner
# Usage: ./run_scan.sh <url1> [url2] [url3] ...
# ──────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$#" -eq 0 ]; then
  echo ""
  echo "  🛡  Web Security Agent"
  echo "  ─────────────────────────────────────"
  echo "  Usage:   ./run_scan.sh <url1> [url2] ..."
  echo ""
  echo "  Examples:"
  echo "    ./run_scan.sh https://mysite.com"
  echo "    ./run_scan.sh https://site1.com https://site2.com https://site3.com"
  echo ""
  exit 0
fi

# Check Python
if ! command -v python3 &> /dev/null; then
  echo "❌ Python 3 not found. Please install Python 3."
  exit 1
fi

# Install dependencies quietly if missing
python3 -c "import requests" 2>/dev/null || pip3 install requests --break-system-packages -q

# Run the agent
python3 "$SCRIPT_DIR/security_agent.py" "$@"
