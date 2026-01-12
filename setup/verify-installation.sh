#!/bin/bash
#===============================================================================
# CyberLab - Installation Verification Script
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              CYBERLAB INSTALLATION VERIFICATION              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

#===============================================================================
# Test 1: Docker Status
#===============================================================================

echo -e "${BLUE}[Test 1]${NC} Docker Container Status"
echo "─────────────────────────────────────────────"

if docker ps &> /dev/null; then
    echo -e "${GREEN}[OK]${NC} Docker daemon is running"
    echo ""
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | head -15
else
    echo -e "${RED}[FAIL]${NC} Docker daemon is not running"
    echo "  Try: sudo systemctl start docker"
fi
echo ""

#===============================================================================
# Test 2: Web Service Accessibility
#===============================================================================

echo -e "${BLUE}[Test 2]${NC} Web Service Accessibility"
echo "─────────────────────────────────────────────"

declare -A services=(
    ["Dashboard"]="http://localhost/cyberlab/"
    ["DVWA"]="http://localhost:8081"
    ["Juice Shop"]="http://localhost:8082"
    ["WebGoat"]="http://localhost:8083"
    ["bWAPP"]="http://localhost:8084"
    ["Mutillidae"]="http://localhost:8085"
)

for name in "${!services[@]}"; do
    url="${services[$name]}"
    status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null || echo "000")
    if [[ "$status" =~ ^(200|302|301)$ ]]; then
        echo -e "  ${GREEN}[OK]${NC} $name - HTTP $status"
    elif [[ "$status" == "000" ]]; then
        echo -e "  ${YELLOW}[WAIT]${NC} $name - Connection refused (starting?)"
    else
        echo -e "  ${RED}[FAIL]${NC} $name - HTTP $status"
    fi
done
echo ""

#===============================================================================
# Test 3: Database Connectivity
#===============================================================================

echo -e "${BLUE}[Test 3]${NC} Database Connectivity"
echo "─────────────────────────────────────────────"

# MySQL
if docker exec lab-mysql-vuln mysql -uroot -proot -e "SELECT 1" &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} MySQL - Connected (port 3307)"
else
    echo -e "  ${YELLOW}[WAIT]${NC} MySQL - Not ready yet"
fi

# PostgreSQL
if docker exec lab-postgres-vuln psql -U postgres -c "SELECT 1" &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} PostgreSQL - Connected (port 5433)"
else
    echo -e "  ${YELLOW}[WAIT]${NC} PostgreSQL - Not ready yet"
fi

# Redis
if docker exec lab-redis-vuln redis-cli PING 2>/dev/null | grep -q PONG; then
    echo -e "  ${GREEN}[OK]${NC} Redis - Connected (port 6380)"
else
    echo -e "  ${YELLOW}[WAIT]${NC} Redis - Not ready yet"
fi

# MongoDB
if docker exec lab-mongodb-vuln mongosh --eval "db.runCommand({ping:1})" &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} MongoDB - Connected (port 27018)"
else
    echo -e "  ${YELLOW}[WAIT]${NC} MongoDB - Not ready yet"
fi
echo ""

#===============================================================================
# Test 4: Network Configuration
#===============================================================================

echo -e "${BLUE}[Test 4]${NC} Network Configuration"
echo "─────────────────────────────────────────────"

if docker network ls | grep -q lab-network; then
    echo -e "  ${GREEN}[OK]${NC} lab-network exists (172.20.0.0/16)"
else
    echo -e "  ${RED}[FAIL]${NC} lab-network not found"
fi

if docker network ls | grep -q isolated-web; then
    echo -e "  ${GREEN}[OK]${NC} isolated-web exists (internal)"
else
    echo -e "  ${YELLOW}[INFO]${NC} isolated-web not created yet"
fi

if docker network ls | grep -q isolated-db; then
    echo -e "  ${GREEN}[OK]${NC} isolated-db exists (internal)"
else
    echo -e "  ${YELLOW}[INFO]${NC} isolated-db not created yet"
fi
echo ""

#===============================================================================
# Test 5: Security Tools
#===============================================================================

echo -e "${BLUE}[Test 5]${NC} Security Tools"
echo "─────────────────────────────────────────────"

tools=("nmap" "nikto" "sqlmap" "hydra" "john" "hashcat" "msfconsole" "wireshark" "burpsuite" "gobuster")

for tool in "${tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} $tool"
    else
        echo -e "  ${YELLOW}[WARN]${NC} $tool not found"
    fi
done
echo ""

#===============================================================================
# Test 6: Custom Services
#===============================================================================

echo -e "${BLUE}[Test 6]${NC} Custom Vulnerable Services"
echo "─────────────────────────────────────────────"

# SSH
if nc -z localhost 2222 2>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} Vulnerable SSH - port 2222"
else
    echo -e "  ${YELLOW}[WAIT]${NC} Vulnerable SSH - not ready"
fi

# FTP
if nc -z localhost 2121 2>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} Vulnerable FTP - port 2121"
else
    echo -e "  ${YELLOW}[WAIT]${NC} Vulnerable FTP - not ready"
fi

# Buffer Overflow
if nc -z localhost 9999 2>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} Buffer Overflow Server - port 9999"
else
    echo -e "  ${YELLOW}[WAIT]${NC} Buffer Overflow Server - not ready"
fi
echo ""

#===============================================================================
# Summary
#===============================================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                     VERIFICATION COMPLETE                    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "If services show [WAIT], they may still be starting."
echo "Run this script again in 30 seconds."
echo ""
echo "Dashboard: http://localhost/cyberlab/"
echo ""
