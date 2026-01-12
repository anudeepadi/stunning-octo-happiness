#!/bin/bash
#===============================================================================
# CyberLab - Start All Services
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "Starting CyberLab services..."

cd "$PROJECT_ROOT/docker"

# Start Docker containers
docker-compose up -d

# Start Apache (if installed)
if command -v apache2 &> /dev/null; then
    sudo systemctl start apache2
fi

echo ""
echo "Services starting... run 'docker ps' to check status"
echo "Dashboard: http://localhost/cyberlab/"
