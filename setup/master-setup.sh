#!/bin/bash
#===============================================================================
# CyberLab - Master Setup Script for Kali Linux
#===============================================================================
# Comprehensive cybersecurity learning platform setup
# Run with: sudo ./master-setup.sh
#===============================================================================

set -e

#===============================================================================
# Configuration
#===============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/cyberlab-setup.log"
WEB_ROOT="/var/www/html/cyberlab"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

#===============================================================================
# Helper Functions
#===============================================================================

log() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

info() {
    echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOG_FILE"
}

header() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${CYAN}========================================${NC}" | tee -a "$LOG_FILE"
    echo -e "${CYAN} $1${NC}" | tee -a "$LOG_FILE"
    echo -e "${CYAN}========================================${NC}" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

print_banner() {
    clear
    echo -e "${CYAN}"
    echo '  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗      █████╗ ██████╗ '
    echo ' ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║     ██╔══██╗██╔══██╗'
    echo ' ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     ███████║██████╔╝'
    echo ' ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║     ██╔══██║██╔══██╗'
    echo ' ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████╗██║  ██║██████╔╝'
    echo '  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ '
    echo -e "${NC}"
    echo " Comprehensive Cybersecurity Learning Platform"
    echo " =============================================="
    echo ""
}

#===============================================================================
# Phase 1: System Prerequisites
#===============================================================================

install_prerequisites() {
    header "Phase 1: Installing System Prerequisites"

    log "Updating package lists..."
    apt-get update -qq

    log "Installing core packages..."
    apt-get install -y -qq \
        curl \
        wget \
        git \
        jq \
        tree \
        vim \
        tmux \
        build-essential \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        software-properties-common \
        2>/dev/null || warn "Some core packages may have failed"

    log "Installing Python dependencies..."
    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        2>/dev/null || warn "Some Python packages may have failed"

    log "Installing Node.js..."
    if ! command -v node &> /dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
    else
        info "Node.js already installed: $(node --version)"
    fi

    log "Prerequisites installed successfully"
}

#===============================================================================
# Phase 2: Docker Installation
#===============================================================================

install_docker() {
    header "Phase 2: Installing Docker"

    if command -v docker &> /dev/null; then
        warn "Docker already installed: $(docker --version)"
    else
        log "Installing Docker..."

        # Add Docker's official GPG key
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg

        # Set up repository
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
          $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
          tee /etc/apt/sources.list.d/docker.list > /dev/null

        apt-get update -qq
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

        # Add current user to docker group
        if [[ -n "$SUDO_USER" ]]; then
            usermod -aG docker "$SUDO_USER"
            log "Added $SUDO_USER to docker group"
        fi

        systemctl enable docker
        systemctl start docker

        log "Docker installed: $(docker --version)"
    fi

    # Install docker-compose standalone (for compatibility)
    if ! command -v docker-compose &> /dev/null; then
        log "Installing docker-compose..."
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
            -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        log "docker-compose installed: $(docker-compose --version)"
    fi
}

#===============================================================================
# Phase 3: Security Tools Installation
#===============================================================================

install_security_tools() {
    header "Phase 3: Installing Security Tools"

    log "Installing network analysis tools..."
    apt-get install -y -qq \
        nmap \
        wireshark \
        tshark \
        tcpdump \
        netcat-openbsd \
        hping3 \
        dsniff \
        ettercap-text-only \
        mitmproxy \
        2>/dev/null || warn "Some network tools may have failed"

    log "Installing web security tools..."
    apt-get install -y -qq \
        sqlmap \
        nikto \
        dirb \
        gobuster \
        burpsuite \
        2>/dev/null || warn "Some web tools may have failed"

    log "Installing exploitation tools..."
    apt-get install -y -qq \
        metasploit-framework \
        hydra \
        john \
        hashcat \
        2>/dev/null || warn "Some exploitation tools may have failed"

    log "Installing forensics tools..."
    apt-get install -y -qq \
        binwalk \
        foremost \
        steghide \
        exiftool \
        2>/dev/null || warn "Some forensics tools may have failed"

    log "Installing binary analysis tools..."
    apt-get install -y -qq \
        gdb \
        radare2 \
        2>/dev/null || warn "Some binary tools may have failed"

    log "Installing Python security packages..."
    pip3 install --quiet \
        scapy \
        pwntools \
        requests \
        beautifulsoup4 \
        flask \
        2>/dev/null || warn "Some Python packages may have failed"

    log "Security tools installed"
}

#===============================================================================
# Phase 4: Pull Docker Images
#===============================================================================

pull_docker_images() {
    header "Phase 4: Pulling Docker Images"

    images=(
        "vulnerables/web-dvwa:latest"
        "bkimminich/juice-shop:latest"
        "webgoat/webgoat:latest"
        "citizenstig/nowasp:latest"
        "raesene/bwapp:latest"
        "tleemcjr/metasploitable2:latest"
        "redis:6-alpine"
        "mongo:4.4"
        "mysql:5.7"
        "postgres:12"
    )

    for image in "${images[@]}"; do
        info "Pulling $image..."
        docker pull "$image" 2>/dev/null || warn "Failed to pull $image (may not be available)"
    done

    log "Docker images pulled"
}

#===============================================================================
# Phase 5: Build Custom Containers
#===============================================================================

build_custom_containers() {
    header "Phase 5: Building Custom Containers"

    cd "$PROJECT_ROOT/docker"

    log "Building custom vulnerable services..."
    docker-compose build --quiet 2>/dev/null || warn "Some containers failed to build"

    log "Custom containers built"
}

#===============================================================================
# Phase 6: Build and Deploy UI
#===============================================================================

build_ui() {
    header "Phase 6: Building UI"

    cd "$PROJECT_ROOT/ui"

    log "Installing Node.js dependencies..."
    npm install --silent 2>/dev/null || npm install

    log "Building production bundle..."
    npm run build 2>/dev/null || {
        warn "Build failed, trying with legacy OpenSSL..."
        NODE_OPTIONS=--openssl-legacy-provider npm run build
    }

    log "Deploying to web server..."
    mkdir -p "$WEB_ROOT"
    cp -r dist/* "$WEB_ROOT/"

    # Set permissions
    chown -R www-data:www-data "$WEB_ROOT"
    chmod -R 755 "$WEB_ROOT"

    log "UI deployed to $WEB_ROOT"
}

#===============================================================================
# Phase 7: Setup Web Server
#===============================================================================

setup_webserver() {
    header "Phase 7: Setting Up Web Server"

    log "Installing Apache..."
    apt-get install -y -qq apache2 libapache2-mod-php php

    log "Enabling Apache modules..."
    a2enmod rewrite 2>/dev/null || true

    log "Starting Apache..."
    systemctl enable apache2
    systemctl restart apache2

    log "Web server configured"
}

#===============================================================================
# Phase 8: Run Existing Network Labs Setup
#===============================================================================

setup_network_labs() {
    header "Phase 8: Setting Up Network Labs"

    if [[ -f "$PROJECT_ROOT/network-lab-setup.sh" ]]; then
        log "Running existing network labs setup..."
        chmod +x "$PROJECT_ROOT/network-lab-setup.sh"
        bash "$PROJECT_ROOT/network-lab-setup.sh" || warn "Network labs setup had some issues"
    else
        warn "network-lab-setup.sh not found, skipping..."
    fi

    log "Network labs configured"
}

#===============================================================================
# Phase 9: Start Services
#===============================================================================

start_services() {
    header "Phase 9: Starting Services"

    cd "$PROJECT_ROOT/docker"

    log "Starting Docker containers..."
    docker-compose up -d 2>/dev/null || {
        warn "docker-compose up failed, trying docker compose..."
        docker compose up -d
    }

    log "Waiting for services to initialize..."
    sleep 10

    log "Services started"
}

#===============================================================================
# Phase 10: Verification
#===============================================================================

verify_installation() {
    header "Phase 10: Verifying Installation"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  INSTALLATION VERIFICATION                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # Check Docker
    if docker ps &> /dev/null; then
        echo -e "${GREEN}[OK]${NC} Docker is running"
        echo ""
        echo "Running containers:"
        docker ps --format "  {{.Names}}: {{.Status}}" | head -10
    else
        echo -e "${RED}[FAIL]${NC} Docker is not running"
    fi

    echo ""

    # Check web services
    declare -A services=(
        ["Dashboard"]="http://localhost/cyberlab/"
        ["DVWA"]="http://localhost:8081"
        ["Juice Shop"]="http://localhost:8082"
        ["WebGoat"]="http://localhost:8083"
    )

    for name in "${!services[@]}"; do
        url="${services[$name]}"
        status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null || echo "000")
        if [[ "$status" =~ ^(200|302|301)$ ]]; then
            echo -e "${GREEN}[OK]${NC} $name accessible at $url"
        elif [[ "$status" == "000" ]]; then
            echo -e "${YELLOW}[WAIT]${NC} $name starting at $url"
        else
            echo -e "${RED}[FAIL]${NC} $name not accessible (HTTP $status)"
        fi
    done

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    SETUP COMPLETE!                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Access the dashboard at: ${CYAN}http://localhost/cyberlab/${NC}"
    echo ""
    echo "Quick commands:"
    echo "  Start all:   ${YELLOW}cd $PROJECT_ROOT/docker && docker-compose up -d${NC}"
    echo "  Stop all:    ${YELLOW}cd $PROJECT_ROOT/docker && docker-compose down${NC}"
    echo "  View logs:   ${YELLOW}docker-compose logs -f${NC}"
    echo ""
    echo "Target services:"
    echo "  DVWA:         http://localhost:8081 (admin:password)"
    echo "  Juice Shop:   http://localhost:8082"
    echo "  WebGoat:      http://localhost:8083"
    echo "  MySQL:        localhost:3307 (admin:admin123)"
    echo "  Redis:        localhost:6380 (no auth)"
    echo "  BOF Server:   nc localhost 9999"
    echo ""
    echo -e "${GREEN}Happy Hacking!${NC}"
    echo ""
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    print_banner
    check_root

    # Create log file
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== CyberLab Setup Started: $(date) ===" > "$LOG_FILE"

    install_prerequisites
    install_docker
    install_security_tools
    pull_docker_images
    build_custom_containers
    setup_webserver
    build_ui
    setup_network_labs
    start_services
    verify_installation

    echo "=== CyberLab Setup Completed: $(date) ===" >> "$LOG_FILE"
}

# Run main function
main "$@"
