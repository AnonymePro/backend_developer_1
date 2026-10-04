#!/usr/bin/env bash
# End-to-end demo runner for the assignment video.
#
# 1. Starts the vulnerable app on :8001 and attacks it (expect: RCE).
# 2. Starts the hardened app on :8002 and runs the same attacks
#    (expect: every attack rejected, legit upload still works).
#
# Run from anywhere; paths are resolved relative to this script.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VULN_PORT=8001
SECURE_PORT=8002

cleanup() {
    echo
    echo "--- stopping demo servers ---"
    [[ -n "${VULN_PID:-}" ]] && kill "$VULN_PID" 2>/dev/null || true
    [[ -n "${SECURE_PID:-}" ]] && kill "$SECURE_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "############################################################"
echo "# PART A — exploiting the VULNERABLE app (port $VULN_PORT)"
echo "############################################################"
php -S 127.0.0.1:$VULN_PORT -t "$ROOT_DIR/vulnerable_app" >/tmp/vuln_server.log 2>&1 &
VULN_PID=$!
sleep 1

bash "$ROOT_DIR/exploit/exploit.sh" "http://127.0.0.1:$VULN_PORT"

echo
echo "(Vulnerable server log: /tmp/vuln_server.log)"
kill "$VULN_PID" 2>/dev/null || true
unset VULN_PID
sleep 1

echo
echo "############################################################"
echo "# PART B — same attacks against the HARDENED app (port $SECURE_PORT)"
echo "############################################################"
php -S 127.0.0.1:$SECURE_PORT -t "$ROOT_DIR/secure_app" >/tmp/secure_server.log 2>&1 &
SECURE_PID=$!
sleep 1

bash "$ROOT_DIR/exploit/exploit_against_secure.sh" "http://127.0.0.1:$SECURE_PORT"

echo
echo "(Hardened server log: /tmp/secure_server.log)"
echo
echo "Contents of secure_app/uploads/ (should contain ONLY one *.jpg — the legit upload):"
ls -la "$ROOT_DIR/secure_app/uploads/"
echo
echo "Contents of vulnerable_app/uploads/ (should contain the planted webshells):"
ls -la "$ROOT_DIR/vulnerable_app/uploads/"
