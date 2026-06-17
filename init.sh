#!/usr/bin/env bash
# =============================================================================
# Juice Garden — Environment Setup Script
# =============================================================================
# This script sets up and starts the Juice Garden vulnerable web lab platform.
# Run from the project root directory.
#
# Prerequisites:
#   - Docker Engine 24+ with Docker Compose v2
#   - Python 3.11+ (for the garden CLI)
#   - Ports 80 and 8081 available on the host
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
AMBER='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'
BOLD='\033[1m'

log()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()   { echo -e "${AMBER}[!]${RESET} $*"; }
error()  { echo -e "${RED}[x]${RESET} $*"; }
header() { echo -e "\n${BOLD}${GREEN}=== $* ===${RESET}\n"; }

# =============================================================================
# Step 1: Verify Prerequisites
# =============================================================================
header "Checking Prerequisites"

# Docker
if ! command -v docker &>/dev/null; then
    error "Docker is not installed. Please install Docker Engine 24+."
    exit 1
fi
DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "0.0.0")
log "Docker version: $DOCKER_VERSION"

# Docker Compose v2
if ! docker compose version &>/dev/null; then
    error "Docker Compose v2 is not available. Please install Docker Compose v2."
    exit 1
fi
COMPOSE_VERSION=$(docker compose version --short 2>/dev/null || echo "unknown")
log "Docker Compose version: $COMPOSE_VERSION"

# Python 3.11+
if ! command -v python3 &>/dev/null; then
    error "Python 3 is not installed. Please install Python 3.11+."
    exit 1
fi
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
log "Python version: $PYTHON_VERSION"

# =============================================================================
# Step 2: Install Python garden CLI
# =============================================================================
header "Installing garden CLI"

if [ -f "pyproject.toml" ] || [ -f "setup.py" ] || [ -f "setup.cfg" ]; then
    log "Installing garden CLI in editable mode..."
    pip3 install -e . --quiet 2>&1 | tail -5 || warn "pip install failed — garden CLI may not be available"
elif [ -f "requirements.txt" ]; then
    log "Installing Python dependencies from requirements.txt..."
    pip3 install -r requirements.txt --quiet 2>&1 | tail -5 || warn "pip install failed"
else
    warn "No Python package configuration found. Skipping pip install."
fi

# =============================================================================
# Step 3: Set up /etc/hosts entries
# =============================================================================
header "Checking /etc/hosts entries"

HOSTS_OK=true
if ! grep -q "garden\.lab" /etc/hosts 2>/dev/null; then
    warn "/etc/hosts is missing garden.lab entry."
    HOSTS_OK=false
fi
if ! grep -q "attacker\.lab" /etc/hosts 2>/dev/null; then
    warn "/etc/hosts is missing attacker.lab entry."
    HOSTS_OK=false
fi

if [ "$HOSTS_OK" = false ]; then
    warn "Please add the following lines to /etc/hosts (requires sudo):"
    echo ""
    echo "    127.0.0.1 garden.lab attacker.lab"
    echo ""
    warn "Run: sudo sh -c 'echo \"127.0.0.1 garden.lab attacker.lab\" >> /etc/hosts'"
    warn "CS-02 (same-site SOP boundary) and CS-03 (SameSite CSRF) challenges require these entries."
else
    log "/etc/hosts entries: garden.lab and attacker.lab are present."
fi

# =============================================================================
# Step 4: Copy .env template if .env doesn't exist
# =============================================================================
header "Environment Configuration"

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        log "Copied .env.example to .env"
    elif [ -f ".env.template" ]; then
        cp .env.template .env
        log "Copied .env.template to .env"
    else
        warn "No .env file found and no template to copy. Creating default .env..."
        cat > .env << 'ENVFILE'
# Juice Garden Environment Configuration
# Nginx host-published ports
NGINX_PORT=80
EXPLOIT_SERVER_PORT=8081

# Session configuration
SESSION_SAMESITE=lax
SESSION_SECRET=change-me-in-production-juice-garden-secret

# PostgreSQL
POSTGRES_DB=garden_fresh
POSTGRES_USER=garden
POSTGRES_PASSWORD=gardenpassword123

# Seed credentials (bot accounts)
STAFF_BOT_EMAIL=staff.bot@garden.internal
STAFF_BOT_PASSWORD=StaffBot2024!
MANAGER_BOT_EMAIL=manager.bot@garden.internal
MANAGER_BOT_PASSWORD=ManagerBot2024!
ADMIN_BOT_EMAIL=admin.bot@garden.internal
ADMIN_BOT_PASSWORD=AdminBot2024!

# Flask platform
FLASK_SECRET_KEY=flask-platform-secret-juice-garden
ENVFILE
        log "Created default .env file"
    fi
else
    log ".env file already exists."
fi

# =============================================================================
# Step 5: Start the Docker Compose stack
# =============================================================================
header "Starting Juice Garden Stack"

log "Pulling/building Docker images and starting all services..."
log "This may take 2-4 minutes on first run (image builds + PostgreSQL init)."
echo ""

if command -v garden &>/dev/null; then
    log "Using garden CLI: garden start"
    garden start
else
    log "garden CLI not found; using docker compose directly..."
    docker compose up -d --wait 2>&1 | tail -20
    echo ""
    log "Waiting for health checks to pass..."
    sleep 10
fi

# =============================================================================
# Step 6: Print Status and Access Information
# =============================================================================
header "Juice Garden is Ready!"

echo -e "  ${BOLD}Garden Fresh (Vulnerable App):${RESET}"
echo -e "    URL:          ${GREEN}http://garden.lab:80/${RESET}"
echo -e "    Guest access: Browse product menu, view recent deliveries"
echo ""
echo -e "  ${BOLD}Challenge Board:${RESET}"
echo -e "    URL:          ${GREEN}http://garden.lab:80/platform/${RESET}"
echo -e "    Register:     Create a platform account at /platform/"
echo ""
echo -e "  ${BOLD}Exploit Server:${RESET}"
echo -e "    URL:          ${GREEN}http://garden.lab:80/platform/exploit-server/${RESET}"
echo ""
echo -e "  ${BOLD}CS-02 Cross-Origin Attack Pages:${RESET}"
echo -e "    Origin:       ${GREEN}http://garden.lab:8081/payloads/<id>${RESET}"
echo -e "    (cross-origin same-site; SOP applies; session cookie sent)"
echo ""
echo -e "  ${BOLD}CS-03 Cross-Site Attack Pages:${RESET}"
echo -e "    Origin:       ${GREEN}http://attacker.lab/payloads/<id>${RESET}"
echo -e "    (cross-site; SameSite=Lax permits GET navigation; Strict blocks)"
echo ""
echo -e "  ${BOLD}Operator Commands:${RESET}"
echo -e "    garden status           — check all 8 service states"
echo -e "    garden flags list       — print all 23 flags (operator only)"
echo -e "    garden flags verify F   — verify a flag value"
echo -e "    garden reset            — soft reset (regenerate flags)"
echo -e "    garden reset --hard     — hard reset (destroy volumes)"
echo -e "    garden hosts check      — verify /etc/hosts entries"
echo -e "    garden stop             — stop all containers"
echo ""
echo -e "  ${BOLD}Tracks & Challenge Count:${RESET}"
echo -e "    AUTH (4) | INJ (4) | BAC (4) | CS (3) | SS (3) | BL (3)"
echo -e "    MISSION-ALPHA (1) | Hidden Bonus (1) | Total: 23 flags"
echo ""

if [ "$HOSTS_OK" = false ]; then
    warn "Remember to add /etc/hosts entries before attempting CS-02 or CS-03!"
fi

echo -e "${GREEN}${BOLD}Happy hacking!${RESET}"
