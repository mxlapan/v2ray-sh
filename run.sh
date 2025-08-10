#!/bin/bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root user."
    fi
}

check_nginx_conflicts() {
    local domain="$1"

    if netstat -tuln | grep -q ":80\|:443"; then
        log_warning "Detected that ports 80 or 443 are already in use."
        log_info "Processes currently listening on ports 80/443:"
        netstat -tuln | grep ":80\|:443" || true
    fi

    if grep -r "server_name.*$domain" /etc/nginx/sites-enabled/ 2>/dev/null | grep -v "v2ray-$domain"; then
        log_warning "Detected that other Nginx configuration files already contain domain $domain:"
        grep -r "server_name.*$domain" /etc/nginx/sites-enabled/ 2>/dev/null | grep -v "v2ray-$domain" || true
        log_warning "This may cause configuration conflicts."
        echo ""
        read -p "Do you want to continue with installation? (y/N): " continue_choice
        if [[ "$continue_choice" != "y" && "$continue_choice" != "Y" ]]; then
            log_error "Installation cancelled. Please resolve domain conflicts first."
        fi
        log_info "User chose to continue installation, will create independent V2Ray configuration."
    fi
}


do_install() {
    log_info "Starting v2ray-sh secure deployment process..."

    read -p "Please enter your domain (e.g., example.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then log_error "Domain cannot be empty."; fi

    read -p "Please enter your email (for certificate application, e.g., test@gmail.com): " EMAIL
    if [ -z "$EMAIL" ]; then log_error "Email cannot be empty."; fi

    V2RAY_UUID=$(cat /proc/sys/kernel/random/uuid)
    V2RAY_PATH="/$(cat /proc/sys/kernel/random/uuid | cut -d'-' -f1)"

    log_info "Domain: $DOMAIN"
    log_info "Email: $EMAIL"
    log_info "V2Ray UUID: $V2RAY_UUID"
    log_info "V2Ray WebSocket Path: $V2RAY_PATH"

    log_info "Checking system environment and possible conflicts..."
    check_nginx_conflicts "$DOMAIN"

    log_info "Preparing system environment..."
    timedatectl set-timezone Asia/Shanghai
    apt-get update && apt-get upgrade -y
    apt-get install -y nginx curl socat ufw jq qrencode net-tools

    log_info "Installing V2Ray..."
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

    log_info "Applying for certificate for $DOMAIN..."
    systemctl stop nginx || true
    curl https://get.acme.sh | sh -s email="$EMAIL"
    ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256 --force
    mkdir -p /etc/v2ray
    ~/.acme.sh/acme.sh --installcert -d "$DOMAIN" --ecc --fullchain-file /etc/v2ray/v2ray.crt --key-file /etc/v2ray/v2ray.key
    chmod 644 /etc/v2ray/v2ray.crt
    chmod 600 /etc/v2ray/v2ray.key
    chown root:root /etc/v2ray/v2ray.*

    log_info "Configuring V2Ray..."
    if ! id -u v2ray >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin v2ray
        log_info "Created v2ray system user"
    fi

    mkdir -p /usr/local/etc/v2ray
    mkdir -p /var/log/v2ray
    chown v2ray:v2ray /var/log/v2ray
    chmod 755 /var/log/v2ray

    # Create log files and set correct permissions
    touch /var/log/v2ray/access.log /var/log/v2ray/error.log
    chown v2ray:v2ray /var/log/v2ray/access.log /var/log/v2ray/error.log
    chmod 644 /var/log/v2ray/access.log /var/log/v2ray/error.log

    sed -e "s/__V2RAY_UUID__/$V2RAY_UUID/g" \
        -e "s|__V2RAY_PATH__|$V2RAY_PATH|g" \
        ./templates/v2ray.json > /usr/local/etc/v2ray/config.json

    # Ensure V2Ray config file has correct permissions
    chown v2ray:v2ray /usr/local/etc/v2ray/config.json
    chmod 644 /usr/local/etc/v2ray/config.json

    log_info "Configuring Nginx..."
    cat > /etc/nginx/conf.d/geoip.conf <<EOF
geo \$allowed_country {
    default no;
    include /etc/nginx/geoip/cn_ips.conf;
}
EOF

    V2RAY_SITE_CONFIG="/etc/nginx/sites-available/v2ray-$DOMAIN"

    sed -e "s/__DOMAIN__/$DOMAIN/g" \
        -e "s|__V2RAY_PATH__|$V2RAY_PATH|g" \
        ./templates/nginx.conf > "$V2RAY_SITE_CONFIG"

    ln -sf "$V2RAY_SITE_CONFIG" "/etc/nginx/sites-enabled/v2ray-$DOMAIN"

    if [ -e "/etc/nginx/sites-enabled/default" ]; then
        log_warning "Detected that default site configuration is enabled."
        log_warning "If your domain $DOMAIN conflicts with the default site, manually disable the default site:"
        log_warning "  sudo rm /etc/nginx/sites-enabled/default"
        log_warning "Or modify the server_name configuration of the default site to avoid conflicts."
    fi

    WEB_ROOT="/var/www/$DOMAIN"
    mkdir -p "$WEB_ROOT"
    echo "<h1>Welcome to $DOMAIN</h1><p>This is a placeholder page.</p>" > "$WEB_ROOT/index.html"

    log_info "Configuring GeoIP access restrictions..."
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    chmod +x ./update_geoip.sh
    cp ./update_geoip.sh /usr/local/bin/update_geoip.sh
    chmod +x /usr/local/bin/update_geoip.sh
    bash ./update_geoip.sh
    (crontab -l 2>/dev/null; echo "0 3 * * 1 /bin/bash /usr/local/bin/update_geoip.sh >/dev/null 2>&1") | crontab -
    log_success "GeoIP automatic update task has been set up."

    log_info "Performing system security hardening..."

    SSH_PORT=$(grep -i '^port' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=22
        log_info "No custom SSH port detected in sshd_config, will set firewall rules for default port 22."
    else
        log_info "Detected custom SSH port: $SSH_PORT, will set firewall rules for this port."
    fi

    ufw default deny
    ufw allow "$SSH_PORT"/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw --force enable

    apt-get install -y fail2ban
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF
    systemctl enable fail2ban && systemctl restart fail2ban

    apt-get install -y unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades

    log_info "Starting services..."

    if [ -f /etc/systemd/system/v2ray.service ]; then
        log_info "Fixing V2Ray service configuration..."

        cp /etc/systemd/system/v2ray.service /etc/systemd/system/v2ray.service.backup

        cat > /etc/systemd/system/v2ray.service <<EOF
[Unit]
Description=V2Ray Service
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target

[Service]
Type=simple
User=v2ray
Group=v2ray
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStartPre=/bin/mkdir -p /var/log/v2ray
ExecStartPre=/bin/chown v2ray:v2ray /var/log/v2ray
ExecStartPre=/bin/chmod 755 /var/log/v2ray
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=100000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

        # Ensure certificate files are readable by v2ray user
        chown root:v2ray /etc/v2ray/v2ray.crt /etc/v2ray/v2ray.key
        chmod 640 /etc/v2ray/v2ray.key
        chmod 644 /etc/v2ray/v2ray.crt

        systemctl daemon-reload
        log_info "Updated V2Ray service configuration to run with v2ray user"
    fi

    if ! nginx -t; then
        log_error "Nginx configuration validation failed, please check configuration files!"
    fi
    if ! /usr/local/bin/v2ray test -config /usr/local/etc/v2ray/config.json; then
        log_error "V2Ray configuration validation failed, please check configuration files!"
    fi

    systemctl enable nginx v2ray
    systemctl restart nginx v2ray

    sleep 3
    if ! systemctl is-active --quiet nginx; then
        log_error "Nginx failed to start, please check logs: journalctl -u nginx"
    fi
    if ! systemctl is-active --quiet v2ray; then
        log_error "V2Ray failed to start, please check logs: journalctl -u v2ray"
    fi

    log_success "v2ray-sh secure deployment completed!"
    print_summary "$DOMAIN" "$V2RAY_UUID" "$V2RAY_PATH"
}

print_summary() {
    local domain="$1"
    local uuid="$2"
    local path="$3"

    CLIENT_JSON=$(jq \
      --arg id "$uuid" \
      --arg add "$domain" \
      --arg path "$path" \
      --arg ps "$domain" \
      '.id = $id | .add = $add | .path = $path | .ps = $ps | .host = $add | .port = 443' \
      ./templates/client.json)

    VMESS_URL="vmess://$(echo -n "$CLIENT_JSON" | base64 -w 0)"

    echo -e "\n==================================================================="
    echo -e "${GREEN}                        Installation Successful!                        ${NC}"
    echo -e "==================================================================="
    echo -e "${YELLOW}Your V2Ray Configuration Details:${NC}"
    echo -e "  ${GREEN}Address:${NC} $domain"
    echo -e "  ${GREEN}Port:${NC} 443"
    echo -e "  ${GREEN}UUID:${NC} $uuid"
    echo -e "  ${GREEN}AlterId:${NC} 0"
    echo -e "  ${GREEN}Security:${NC} auto"
    echo -e "  ${GREEN}Network:${NC} ws"
    echo -e "  ${GREEN}Host:${NC} $domain"
    echo -e "  ${GREEN}Path:${NC} $path"
    echo -e "  ${GREEN}TLS:${NC} tls"
    echo -e "==================================================================="
    echo -e "${YELLOW}VMess URL (Copy to client):${NC}"
    echo -e "${GREEN}$VMESS_URL${NC}"
    echo -e "==================================================================="
    echo -e "${YELLOW}Configuration QR Code (Scan with V2RayN, V2RayNG, etc.):${NC}"
    qrencode -t ANSIUTF8 "$VMESS_URL"
    echo -e "===================================================================\n"
}

do_uninstall() {
    log_warning "About to uninstall all v2ray-sh related components!"
    read -p "Are you sure you want to continue? (y/N): " choice
    if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
        log_info "Operation cancelled."
        exit 0
    fi

    log_info "Stopping services..."
    systemctl stop v2ray || true
    systemctl disable v2ray || true

    log_info "Removing V2Ray service configuration..."
    rm -f /etc/systemd/system/v2ray.service.backup

    log_info "Removing Nginx site configuration..."
    rm -f /etc/nginx/sites-available/v2ray-*
    rm -f /etc/nginx/sites-enabled/v2ray-*
    rm -f /etc/nginx/conf.d/geoip.conf

    log_info "Removing GeoIP configuration files and scheduled tasks..."
    rm -rf /etc/nginx/geoip /usr/local/bin/update_geoip.sh
    (crontab -l 2>/dev/null | grep -v "update_geoip.sh") | crontab - || true

    log_info "Uninstalling packages..."
    apt-get purge -y v2ray unattended-upgrades qrencode jq
    apt-get autoremove -y

    log_info "Removing configuration files and certificates..."
    rm -rf /usr/local/etc/v2ray /var/log/v2ray
    find /var/www -maxdepth 1 -name "*" -type d -exec sh -c 'if [ -f "$1/index.html" ] && grep -q "This is a placeholder page" "$1/index.html" 2>/dev/null; then rm -rf "$1"; fi' _ {} \;
    ~/.acme.sh/acme.sh --uninstall || true

    if id -u v2ray >/dev/null 2>&1; then
        userdel v2ray 2>/dev/null || true
        log_info "Removed v2ray system user"
    fi

    log_success "Uninstall complete."
}

do_list_sites() {
    log_info "Current V2Ray site configurations in the system:"
    echo "================================="

    if ls /etc/nginx/sites-available/v2ray-* 2>/dev/null | head -1 >/dev/null; then
        for site_config in /etc/nginx/sites-available/v2ray-*; do
            site_name=$(basename "$site_config" | sed 's/^v2ray-//')
            if [ -L "/etc/nginx/sites-enabled/$(basename "$site_config")" ]; then
                status="Enabled"
            else
                status="Disabled"
            fi
            echo "  - $site_name [$status]"
        done
    else
        echo "  No V2Ray site configurations found."
    fi
    echo "================================="

    log_info "All Nginx sites in the system:"
    echo "================================="
    if ls /etc/nginx/sites-enabled/* 2>/dev/null | head -1 >/dev/null; then
        for enabled_site in /etc/nginx/sites-enabled/*; do
            site_name=$(basename "$enabled_site")
            echo "  - $site_name [Enabled]"
        done
    else
        echo "  No enabled sites found."
    fi
    echo "================================="
}

main() {
    check_root
    clear

    echo -e "${GREEN}Welcome to v2ray-sh Secure Deployment Script${NC}"
    echo "================================="
    echo "1. Install and configure v2ray-sh"
    echo "2. Uninstall v2ray-sh"
    echo "3. View site configuration status"
    echo "4. Exit script"
    echo "================================="
    read -p "Please enter your choice [1-4]: " menu_choice

    case $menu_choice in
        1) do_install ;;
        2) do_uninstall ;;
        3) do_list_sites ;;
        4) exit 0 ;;
        *) log_error "Invalid choice." ;;
    esac
}

main "$@"