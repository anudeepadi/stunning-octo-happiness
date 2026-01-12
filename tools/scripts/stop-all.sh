#!/bin/bash
#===============================================================================
# CyberLab - Stop All Services
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "Stopping CyberLab services..."

cd "$PROJECT_ROOT/docker"

# Stop Docker containers
docker-compose down

echo ""
echo "All services stopped."
