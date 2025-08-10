#!/bin/bash

set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

GEOIP_DIR="/etc/nginx/geoip"
GEOIP_FILE="$GEOIP_DIR/cn_ips.conf"
TMP_FILE_RAW="/tmp/geoip_raw.txt"
TMP_FILE_NGINX="/tmp/geoip_nginx.conf"

# Download and process function
try_download() {
    local url="$1"
    log_info "==> Trying source: $url"

    if curl -sfL --connect-timeout 10 "$url" -o "$TMP_FILE_RAW"; then
        if [ -s "$TMP_FILE_RAW" ]; then
            # 1. '!/^\s*#/'  - Ignore comment lines starting with # (allowing leading spaces)
            # 2. 'NF > 0'    - Ignore empty lines (NF is field count, >0 means non-empty)
            # Only lines meeting both conditions will be processed and appended with " yes;"
            awk '!/^\s*#/ && NF > 0 {print $0 " yes;"}' "$TMP_FILE_RAW" > "$TMP_FILE_NGINX"
            rm -f "$TMP_FILE_RAW"
            return 0
        else
            log_warning "Downloaded file is empty."
        fi
    else
        log_warning "Download failed (404 Not Found or network timeout)."
    fi
    rm -f "$TMP_FILE_RAW"
    return 1
}

log_info "Starting update of Chinese IP address list..."
mkdir -p "$GEOIP_DIR"

SOURCES=(
    "https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china.txt"
    "https://ghproxy.com/https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt"
    "https://cdn.jsdelivr.net/gh/misakaio/chnroutes2/cn.txt"
    "https://ghproxy.com/https://raw.githubusercontent.com/misakaio/chnroutes2/master/cn.txt"
    "https://cdn.jsdelivr.net/gh/17mon/china_ip_list/china_ip_list.txt"
    "https://ghproxy.com/https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"
)

DOWNLOAD_SUCCESS=false
for url in "${SOURCES[@]}"; do
    if try_download "$url"; then
        log_success "Successfully fetched and processed IP list from this source!"
        DOWNLOAD_SUCCESS=true
        break
    fi
done

if [ "$DOWNLOAD_SUCCESS" = false ]; then
    log_error "All download sources have been tried and failed! Unable to fetch IP list."
fi

mv "$TMP_FILE_NGINX" "$GEOIP_FILE"
log_success "IP list has been successfully updated to $GEOIP_FILE"

log_info "Testing Nginx configuration..."
if systemctl is-active --quiet nginx; then
    log_info "Nginx is running, performing configuration test and graceful reload..."
    if nginx -t; then
        systemctl reload nginx
        log_success "Nginx configuration reloaded successfully!"
    else
        log_error "Nginx configuration test failed! Reload aborted."
    fi
else
    log_warning "Nginx service is not currently running, skipping reload. Configuration will take effect on next startup."
fi