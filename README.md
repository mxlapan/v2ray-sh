# V2RAY-SH: Secure V2Ray Deployment Script

A shell script for rapid, high-security deployment of V2Ray, featuring a VMess + TLS + WebSocket + Web stack, with GeoIP restrictions.

[![Debian/Ubuntu](https://img.shields.io/badge/OS-Debian%2FUbuntu-blue.svg)](https://www.debian.org/)
[![Security Hardened](https://img.shields.io/badge/Security-Hardened-brightgreen.svg)](https://github.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Introduction

This script is for anyone who wants to quickly set up a secure, stable, and hard-to-detect V2Ray proxy without getting bogged down in complex configurations. It's more than just a component installer; it's a well-balanced solution that handles the small but crucial details for you.

## Core Features

- **Fully Automated Deployment**: From system updates and dependency installation to service configuration, the entire process is automated.
- **Built-in Security Hardening**:
    - **UFW Firewall**: Configures the firewall, automatically allowing the current SSH port to prevent lockouts.
    - **Fail2Ban**: Protects against brute-force attacks by monitoring SSH login attempts.
    - **Unattended Upgrades**: Enables automatic security patches to keep the system secure.
    - **Hardened TLS**: Enforces TLSv1.3 with modern cipher suites and HSTS.
- **Traffic Obfuscation**: All V2Ray traffic is proxied through Nginx and disguised as standard HTTPS traffic using WebSocket and TLS on port 443.
- **Multi-Site Friendly**: Creates isolated Nginx configurations for each domain, ensuring no conflicts with other websites hosted on the same server.
- **GeoIP Filtering**: Restricts access to specific countries and automatically updates the IP database weekly.
- **Secure by Default**: Runs the V2Ray service under a dedicated, unprivileged `v2ray` user, not `root` or `nobody`.
- **Easy Management**: An interactive menu for installation, uninstallation, and status checks, complete with auto-generated client configuration links and QR codes.

## Prerequisites

1.  A server running **Debian (10+)** or **Ubuntu (20.04+)**, located outside mainland China.
2.  A **domain name** with its **A record** pointed to your server's IP address.
3.  Root access to the server.

## Getting Started

1.  **Clone the repository**
    ```bash
    git clone https://github.com/mxlapan/v2ray-sh.git
    cd v2ray-sh
    ```
    *(If `git` is not installed, run `apt install git -y` first.)*

2.  **Set execute permissions**
    ```bash
    chmod +x run.sh update_geoip.sh
    ```

3.  **Run the script**
    ```bash
    ./run.sh
    ```
    Then, just follow the on-screen prompts.

## Usage Guide

### Main Menu

- `1. Install & Configure`: Use this for the initial setup or to add a new domain.
- `2. Uninstall`: Removes all components created by the script.
- `3. View Site Status`: Lists all V2Ray sites and their current status (enabled/disabled).
- `4. Exit`

### Uninstallation

The uninstall process cleanly removes all related components, including the V2Ray service, Nginx site configurations, the `v2ray` user, GeoIP rules, logs, certificates, and cron jobs. It is designed to not interfere with other services or websites on your server.

## Technical Details

### Common Commands

- **Check V2Ray Status**: `systemctl status v2ray`
- **Check Nginx Status**: `systemctl status nginx`
- **Follow V2Ray Logs**: `journalctl -u v2ray -f`
- **View V2Ray Error Log**: `tail -f /var/log/v2ray/error.log`
- **Test Nginx Configuration**: `nginx -t`
- **Test V2Ray Configuration**: `/usr/local/bin/v2ray test -config /usr/local/etc/v2ray/config.json`
- **Check Firewall Status**: `ufw status`

### File Locations

- **V2Ray Config**: `/usr/local/etc/v2ray/config.json`
- **V2Ray Logs**: `/var/log/v2ray/`
- **Nginx Site Config**: `/etc/nginx/sites-available/v2ray-{your_domain}`
- **SSL Certificate**: `/etc/v2ray/v2ray.crt` & `/etc/v2ray/v2ray.key`
- **GeoIP Config**: `/etc/nginx/conf.d/geoip.conf`
- **Website Root**: `/var/www/{your_domain}/`
- **V2Ray Service**: `/etc/systemd/system/v2ray.service`

## FAQ

- **Q: The installation is stuck at "Applying for certificate". What should I do?**
  **A:** This is almost always a DNS issue. Make sure your domain's A record is correctly pointing to the server's IP and has had enough time to propagate. You can check this with `ping your.domain.com`.

- **Q: V2Ray fails to start with a permission error.**
  **A:** The script handles file permissions automatically. If you encounter this, first try re-running the installation. If the problem persists, check the ownership of `/var/log/v2ray/` and `/etc/v2ray/` to ensure the `v2ray` user has the necessary access.

- **Q: How can I allow a specific IP to bypass the GeoIP filter?**
  **A:** Edit `/etc/nginx/geoip/cn_ips.conf` and add `your_ip yes;` (e.g., `1.2.3.4 yes;`) at the top of the file. Then, reload Nginx with `systemctl reload nginx`.

- **Q: I forgot my connection details.**
  **A:** The UUID and path are in `/usr/local/etc/v2ray/config.json`. The address is your domain, and the port is 443.

- **Q: Will this script mess up my existing websites?**
  **A:** No. It's designed to be non-destructive and uses isolated configurations. It also checks for potential port and domain conflicts before installation.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).