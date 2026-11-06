#!/bin/bash

# Heimdall SIEM Startup Script
# Runs API server and HTML/JS Dashboard

set -e

API_PID=""
DASHBOARD_PID=""
SYSLOG_PID=""

# Ensure data directory exists
mkdir -p /app/data

# Function to handle shutdown
cleanup() {
    echo "Shutting down services..."
    kill $API_PID $DASHBOARD_PID $SYSLOG_PID 2>/dev/null || true
    wait $API_PID $DASHBOARD_PID $SYSLOG_PID 2>/dev/null || true
    exit 0
}

# Trap signals for graceful shutdown
trap cleanup SIGTERM SIGINT

# Start API server in background
echo "Starting Heimdall API server on port ${SIEM_SERVER_PORT:-8010}..."
cd /app
python -m uvicorn core.server_api:app \
    --host ${SIEM_SERVER_HOST:-0.0.0.0} \
    --port ${SIEM_SERVER_PORT:-8010} \
    --workers 1 \
    --log-level info &
API_PID=$!

# Wait a moment for API to start and write the syslog agent key
sleep 2

SYSLOG_PID=""
if [ "${SYSLOG_ENABLED:-true}" != "false" ]; then
    echo "Starting syslog collector on udp/${SYSLOG_UDP_PORT:-5514}..."
    python -m core.syslog_collector &
    SYSLOG_PID=$!
fi

# Start Dashboard server in background
echo "Starting Heimdall Dashboard on port ${DASHBOARD_PORT:-8501}..."
cd /app/ui
DASHBOARD_PORT=${DASHBOARD_PORT:-8501} python dashboard_server.py &
DASHBOARD_PID=$!

echo "Heimdall SIEM is running:"
echo "  API Server: http://0.0.0.0:${SIEM_SERVER_PORT:-8010}"
echo "  Dashboard: http://0.0.0.0:${DASHBOARD_PORT:-8501}"
echo "  Syslog: udp/${SYSLOG_UDP_PORT:-5514}"

# Wait for both processes
wait $API_PID $DASHBOARD_PID $SYSLOG_PID
