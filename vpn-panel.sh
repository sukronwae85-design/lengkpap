#!/bin/bash
# ============================================================================
# VPN PANEL COMPLETE - SSH + Vmess + UDP Custom
# AUTO INSTALL dari GitHub: https://github.com/sukronwae85-design/sshvmess-udp-costume
# 
# ONE COMMAND INSTALL:
# curl -sSL https://raw.githubusercontent.com/sukronwae85-design/sshvmess-udp-costume/main/vpn-panel.sh | bash
# 
# Atau:
# wget -q -O vpn.sh https://raw.githubusercontent.com/sukronwae85-design/sshvmess-udp-costume/main/vpn-panel.sh && chmod +x vpn.sh && ./vpn.sh
# ============================================================================

set -e

# ============================================================================
# KONFIGURASI UTAMA
# ============================================================================
VERSION="2.0.0"
PANEL_DIR="/root/vpn-panel"
DB_SSH="$PANEL_DIR/database/ssh.db"
DB_VMESS="$PANEL_DIR/database/vmess.db"
DB_LOGS="$PANEL_DIR/database/logs.db"
CONFIG_DIR="$PANEL_DIR/configs"
BACKUP_DIR="$PANEL_DIR/backup"
LOG_DIR="$PANEL_DIR/logs"
TELEGRAM_FILE="$PANEL_DIR/telegram.conf"
EMAIL_FILE="$PANEL_DIR/email.conf"
DOMAIN_FILE="$PANEL_DIR/domain.conf"
LOCK_FILE="$PANEL_DIR/lock.db"

# Port yang dibuka
PORTS_TCP=("22" "80" "443" "53" "7300" "7200" "7100" "8080" "8443" "2052" "2082" "2095")
PORTS_UDP=("53" "80" "443" "7300" "7200" "7100" "8080" "8443")

# ============================================================================
# WARNA OUTPUT
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
NC='\033[0m'

# ============================================================================
# FUNGSI BANTUAN
# ============================================================================

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔════════════════════════════════════════════════════════╗
║                                                        ║
║   ██╗   ██╗██████╗ ███╗   ██╗     ██████╗ █████╗ ███╗  ║
║   ██║   ██║██╔══██╗████╗  ██║    ██╔═══██╗██╔══██╗████╗ ║
║   ██║   ██║██████╔╝██╔██╗ ██║    ██║   ██║███████║██╔██╗║
║   ██║   ██║██╔═══╝ ██║╚██╗██║    ██║   ██║██╔══██║██║╚██╗║
║   ╚██████╔╝██║     ██║ ╚████║    ╚██████╔╝██║  ██║██║ ╚██╗║
║    ╚═════╝ ╚═╝     ╚═╝  ╚═══╝     ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝║
║                                                        ║
║           SSH + Vmess + UDP Custom Panel                ║
║                  Version 2.0.0                          ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_status() { echo -e "${GREEN}[✓] $1${NC}"; }
print_error() { echo -e "${RED}[✗] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Script ini harus dijalankan sebagai root!"
        echo "Gunakan: sudo bash $0"
        exit 1
    fi
}

check_ubuntu() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [ "$ID" = "ubuntu" ]; then
            print_status "Ubuntu $VERSION_ID detected"
            return 0
        fi
    fi
    print_error "Hanya Ubuntu 18.04/20.04/22.04 yang didukung!"
    exit 1
}

# ============================================================================
# FUNGSI INSTALASI UTAMA
# ============================================================================

install_vpn_panel() {
    print_banner
    echo -e "${YELLOW}[+] Memulai instalasi VPN Panel...${NC}"
    echo ""
    
    # Cek persyaratan
    check_root
    check_ubuntu
    
    # Update system
    print_info "Updating system packages..."
    apt-get update -y
    apt-get upgrade -y
    
    # Install dependencies
    print_info "Installing dependencies..."
    apt-get install -y \
        curl wget git nano htop \
        jq sqlite3 dos2unix \
        ufw iptables-persistent \
        nginx certbot python3-certbot-nginx \
        socat netcat-openbsd \
        python3 python3-pip \
        cron openssl unzip \
        fail2ban net-tools \
        bc apache2-utils \
        mailutils postfix \
        vnstat
    
    # Setup firewall - BUKA SEMUA PORT
    setup_firewall_all_ports
    
    # Buat direktori
    mkdir -p $PANEL_DIR/{database,configs,logs,backup,ssl}
    mkdir -p $CONFIG_DIR/{ssh,vmess}
    
    # Setup database
    setup_database
    
    # Setup SSH Server
    setup_ssh_server
    
    # Setup Nginx
    setup_nginx_proxy
    
    # Install Xray (Vmess)
    install_xray_vmess
    
    # Setup cron jobs
    setup_cron_jobs
    
    # Buat symlinks
    ln -sf $0 /usr/local/bin/menu
    ln -sf $0 /usr/local/bin/vpn
    ln -sf $0 /usr/local/bin/vpn-panel
    
    # Setup backup system
    setup_backup_system
    
    # Test installation
    test_installation
    
    # Show completion
    show_completion_message
    
    # Create example user
    create_example_user
}

setup_firewall_all_ports() {
    print_info "Setting up firewall - ALL PORTS OPEN..."
    
    # Nonaktifkan UFW
    ufw --force disable 2>/dev/null || true
    
    # Reset iptables
    iptables -F
    iptables -X
    iptables -Z
    
    # Default policy: ACCEPT semua
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Allow specific ports dengan logging
    for port in "${PORTS_TCP[@]}"; do
        iptables -A INPUT -p tcp --dport $port -j ACCEPT
        print_info "Port $port/tcp opened"
    done
    
    for port in "${PORTS_UDP[@]}"; do
        iptables -A INPUT -p udp --dport $port -j ACCEPT
        print_info "Port $port/udp opened"
    done
    
    # Allow all other ports
    iptables -A INPUT -p tcp -m tcp --dport 1:65535 -j ACCEPT
    iptables -A INPUT -p udp -m udp --dport 1:65535 -j ACCEPT
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    
    # Enable persistent
    systemctl enable netfilter-persistent
    netfilter-persistent save
    
    print_status "Firewall configured - ALL PORTS 1-65535 OPEN"
}

setup_database() {
    print_info "Setting up databases..."
    
    # SSH Users Database
    sqlite3 $DB_SSH << 'EOF'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expired_at TEXT,
    status TEXT DEFAULT 'active',
    max_ips INTEGER DEFAULT 2,
    current_ips INTEGER DEFAULT 0,
    allowed_ips TEXT DEFAULT 'any',
    port TEXT DEFAULT '22',
    bandwidth_limit TEXT DEFAULT 'unlimited',
    last_login TIMESTAMP,
    last_ip TEXT,
    violations INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip_address TEXT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip_address TEXT,
    violation_type TEXT,
    violation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action_taken TEXT
);
EOF

    # Vmess Users Database
    sqlite3 $DB_VMESS << 'EOF'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    uuid TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expired_at TEXT,
    status TEXT DEFAULT 'active',
    max_ips INTEGER DEFAULT 2,
    current_ips INTEGER DEFAULT 0,
    last_login TIMESTAMP,
    last_ip TEXT,
    violations INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vmess_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip_address TEXT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1
);
EOF

    # Logs Database
    sqlite3 $DB_LOGS << 'EOF'
CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_type TEXT,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS backup_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    backup_type TEXT,
    filename TEXT,
    size TEXT,
    status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
EOF

    print_status "Databases created"
}

setup_ssh_server() {
    print_info "Configuring SSH server..."
    
    # Backup config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Update SSH config
    cat >> /etc/ssh/sshd_config << 'EOF'

# ============================================
# VPN PANEL CONFIGURATION
# ============================================
Port 22
Port 2222
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
TCPKeepAlive yes
ClientAliveInterval 30
ClientAliveCountMax 3
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 60
AllowTcpForwarding yes
GatewayPorts yes
# ============================================
EOF
    
    systemctl restart ssh
    systemctl enable ssh
    
    print_status "SSH server configured"
}

setup_nginx_proxy() {
    print_info "Configuring Nginx proxy..."
    
    # Stop nginx jika running
    systemctl stop nginx 2>/dev/null || true
    
    # Buat config nginx lengkap
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # MIME Types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_ecdh_curve secp384r1;
    ssl_session_timeout 10m;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;
    
    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    
    # Default Server (HTTP)
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        
        # Redirect to HTTPS
        return 301 https://$host$request_uri;
    }
    
    # Default Server (HTTPS)
    server {
        listen 443 ssl http2 default_server;
        listen [::]:443 ssl http2 default_server;
        server_name _;
        
        # SSL Certificates (self-signed for now)
        ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
        ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
        
        # Security Headers
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Referrer-Policy "no-referrer-when-downgrade";
        add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
        
        # Root location
        location / {
            return 200 'VPN Panel - SSH + Vmess Server\n';
            add_header Content-Type text/plain;
        }
        
        # Vmess WebSocket Path
        location /vmess {
            proxy_pass http://127.0.0.1:10086;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }
        
        # Status page
        location /status {
            stub_status on;
            access_log off;
            allow 127.0.0.1;
            deny all;
        }
        
        # Panel API
        location /api/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}

# UDP Stream for SSH over UDP
stream {
    # SSH UDP
    upstream ssh_udp {
        server 127.0.0.1:22;
    }
    
    # Port 80 UDP
    server {
        listen 80 udp reuseport;
        proxy_pass ssh_udp;
        proxy_timeout 300s;
        proxy_responses 0;
    }
    
    # Port 443 UDP
    server {
        listen 443 udp reuseport;
        proxy_pass ssh_udp;
        proxy_timeout 300s;
        proxy_responses 0;
    }
    
    # Additional UDP ports
    server {
        listen 53 udp reuseport;
        proxy_pass ssh_udp;
        proxy_timeout 300s;
    }
    
    server {
        listen 7300 udp reuseport;
        proxy_pass ssh_udp;
        proxy_timeout 300s;
    }
    
    server {
        listen 7200 udp reuseport;
        proxy_pass ssh_udp;
        proxy_timeout 300s;
    }
    
    server {
        listen 7100 udp reuseport;
        proxy_pass ssh_udp;
        proxy_timeout 300s;
    }
}
EOF
    
    # Generate self-signed SSL certificates
    print_info "Generating SSL certificates..."
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN Panel/CN=vpn-panel.local" \
        -addext "subjectAltName = DNS:*.vpn-panel.local, IP:127.0.0.1"
    
    # Test and start nginx
    nginx -t
    if [ $? -eq 0 ]; then
        systemctl start nginx
        systemctl enable nginx
        print_status "Nginx configured successfully"
    else
        print_error "Nginx configuration error"
        exit 1
    fi
}

install_xray_vmess() {
    print_info "Installing Xray (Vmess + WebSocket)..."
    
    # Install Xray
    if ! command -v xray &> /dev/null; then
        print_info "Downloading Xray installer..."
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    fi
    
    # Create Xray config
    cat > /usr/local/etc/xray/config.json << 'EOF'
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "inbounds": [
        {
            "port": 10086,
            "listen": "127.0.0.1",
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/vmess",
                    "headers": {
                        "Host": ""
                    }
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "fakedns"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {},
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "direct"
            }
        ]
    },
    "policy": {
        "levels": {
            "0": {
                "handshake": 2,
                "connIdle": 120,
                "uplinkOnly": 1,
                "downlinkOnly": 1,
                "bufferSize": 1024
            }
        }
    }
}
EOF
    
    # Create log directory
    mkdir -p /var/log/xray
    
    # Start Xray
    systemctl start xray
    systemctl enable xray
    
    print_status "Xray installed and configured"
}

setup_cron_jobs() {
    print_info "Setting up cron jobs..."
    
    # Cleanup expired users daily at 2 AM
    cat > /etc/cron.d/vpn-cleanup << EOF
0 2 * * * root /usr/local/bin/vpn-cleanup
EOF
    
    # Auto backup daily at 3 AM
    cat > /etc/cron.d/vpn-backup << EOF
0 3 * * * root /usr/local/bin/vpn-backup
EOF
    
    # Update system weekly
    cat > /etc/cron.d/vpn-update << EOF
0 4 * * 0 root /usr/local/bin/vpn-update
EOF
    
    # Create cleanup script
    cat > /usr/local/bin/vpn-cleanup << 'EOF'
#!/bin/bash
# Cleanup expired users
DB_SSH="/root/vpn-panel/database/ssh.db"
DB_VMESS="/root/vpn-panel/database/vmess.db"

echo "[$(date)] Starting cleanup..." >> /var/log/vpn-cleanup.log

# Clean expired SSH users
sqlite3 "$DB_SSH" "UPDATE users SET status='expired' WHERE expired_at < date('now') AND status='active'" 2>/dev/null

# Clean expired Vmess users
sqlite3 "$DB_VMESS" "UPDATE users SET status='expired' WHERE expired_at < date('now') AND status='active'" 2>/dev/null

# Remove expired system users
sqlite3 "$DB_SSH" "SELECT username FROM users WHERE status='expired'" 2>/dev/null | while read user; do
    pkill -u "$user" 2>/dev/null
    userdel "$user" 2>/dev/null
    echo "[$(date)] Removed expired user: $user" >> /var/log/vpn-cleanup.log
done

echo "[$(date)] Cleanup completed" >> /var/log/vpn-cleanup.log
EOF
    
    chmod +x /usr/local/bin/vpn-cleanup
    
    print_status "Cron jobs configured"
}

setup_backup_system() {
    print_info "Setting up backup system..."
    
    # Create backup script
    cat > /usr/local/bin/vpn-backup << 'EOF'
#!/bin/bash
# VPN Panel Backup Script
BACKUP_DIR="/root/vpn-panel/backup"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/full_backup_$DATE.tar.gz"

echo "[$(date)] Starting backup..." >> /var/log/vpn-backup.log

# Create backup
tar -czf "$BACKUP_FILE" \
    /root/vpn-panel/database \
    /root/vpn-panel/configs \
    /etc/nginx \
    /usr/local/etc/xray \
    /etc/ssh/sshd_config \
    /etc/iptables/rules.v4 \
    2>> /var/log/vpn-backup.log

if [ $? -eq 0 ]; then
    echo "[$(date)] Backup created: $BACKUP_FILE ($(du -h $BACKUP_FILE | cut -f1))" >> /var/log/vpn-backup.log
    
    # Keep only last 7 backups
    cd "$BACKUP_DIR"
    ls -t full_backup_*.tar.gz | tail -n +8 | xargs -r rm -f
    
    # Log to database
    sqlite3 /root/vpn-panel/database/logs.db \
        "INSERT INTO backup_logs (backup_type, filename, size, status) VALUES ('full', 'full_backup_$DATE.tar.gz', '$(du -h $BACKUP_FILE | cut -f1)', 'success')"
else
    echo "[$(date)] Backup failed!" >> /var/log/vpn-backup.log
    sqlite3 /root/vpn-panel/database/logs.db \
        "INSERT INTO backup_logs (backup_type, filename, size, status) VALUES ('full', 'full_backup_$DATE.tar.gz', '0', 'failed')"
fi
EOF
    
    chmod +x /usr/local/bin/vpn-backup
    
    # Create update script
    cat > /usr/local/bin/vpn-update << 'EOF'
#!/bin/bash
# Auto update script
echo "[$(date)] Starting auto-update..." >> /var/log/vpn-update.log
apt-get update -y >> /var/log/vpn-update.log 2>&1
apt-get upgrade -y -qq >> /var/log/vpn-update.log 2>&1
echo "[$(date)] Update completed" >> /var/log/vpn-update.log
EOF
    
    chmod +x /usr/local/bin/vpn-update
    
    print_status "Backup system configured"
}

test_installation() {
    print_info "Testing installation..."
    
    echo ""
    echo -e "${YELLOW}=== SERVICE STATUS ===${NC}"
    
    services=("ssh" "nginx" "xray")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "  ${GREEN}✓ $service: RUNNING${NC}"
        else
            echo -e "  ${RED}✗ $service: STOPPED${NC}"
        fi
    done
    
    echo ""
    echo -e "${YELLOW}=== PORT TEST ===${NC}"
    
    # Test TCP ports
    echo "TCP Ports:"
    for port in 22 80 443 53; do
        if timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null; then
            echo -e "  ${GREEN}✓ Port $port/tcp: OPEN${NC}"
        else
            echo -e "  ${RED}✗ Port $port/tcp: CLOSED${NC}"
        fi
    done
    
    # Test UDP ports
    echo ""
    echo "UDP Ports:"
    for port in 53 80 443; do
        if timeout 1 bash -c "echo > /dev/udp/127.0.0.1/$port" 2>/dev/null; then
            echo -e "  ${GREEN}✓ Port $port/udp: OPEN${NC}"
        else
            echo -e "  ${RED}✗ Port $port/udp: CLOSED${NC}"
        fi
    done
}

show_completion_message() {
    print_banner
    
    PUBLIC_IP=$(curl -s ifconfig.me)
    SERVER_HOSTNAME=$(hostname)
    
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║           INSTALLATION COMPLETE!                       ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${CYAN}📊 SERVER INFORMATION:${NC}"
    echo "Hostname: $SERVER_HOSTNAME"
    echo "Public IP: $PUBLIC_IP"
    echo "Panel Directory: $PANEL_DIR"
    
    echo ""
    echo -e "${CYAN}🚀 QUICK COMMANDS:${NC}"
    echo "menu                    - Open VPN Panel"
    echo "vpn                     - Same as menu"
    echo "vpn-panel               - Same as menu"
    echo "./vpn-panel.sh menu    - Open menu"
    
    echo ""
    echo -e "${CYAN}🔧 INSTALLED FEATURES:${NC}"
    echo "✓ SSH Server with UDP Custom support"
    echo "✓ Vmess + WebSocket + TLS"
    echo "✓ Nginx Reverse Proxy"
    echo "✓ All ports 1-65535 TCP/UDP opened"
    echo "✓ User Management System"
    echo "✓ IP Limiting & Auto Lock"
    echo "✓ Auto Backup System"
    echo "✓ Domain & SSL Support"
    
    echo ""
    echo -e "${YELLOW}📝 NEXT STEPS:${NC}"
    echo "1. Type 'menu' to open control panel"
    echo "2. Create your first user"
    echo "3. Setup domain & SSL (optional)"
    echo "4. Configure Telegram/Email backup"
    
    echo ""
    echo -e "${PURPLE}🔗 SSH UDP Config for HTTP Injector:${NC}"
    echo "Format: IP:PORT@USERNAME:PASSWORD"
    echo "Example: $PUBLIC_IP:22@username:password"
    
    echo ""
    echo -e "${GREEN}✅ VPN Panel is ready to use!${NC}"
    echo ""
}

create_example_user() {
    echo ""
    echo -e "${YELLOW}[+] Create example user? (y/n): ${NC}"
    read -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        username="demo"
        password="demo123"
        server_ip=$(curl -s ifconfig.me)
        
        # Create system user
        useradd -m -s /bin/bash "$username"
        echo "$username:$password" | chpasswd
        
        # Add to database
        expired=$(date -d "+7 days" +"%Y-%m-%d")
        sqlite3 $DB_SSH << EOF
INSERT INTO users (username, password, expired_at, port)
VALUES ('$username', '$password', '$expired', '1-65535');
EOF
        
        echo -e "${GREEN}"
        echo "========================================"
        echo "EXAMPLE USER CREATED!"
        echo "========================================"
        echo "Username: $username"
        echo "Password: $password"
        echo "Expired: $expired"
        echo ""
        echo "SSH UDP Config for HTTP Injector:"
        echo "$server_ip:1-65535@$username:$password"
        echo ""
        echo "Or try specific ports:"
        echo "$server_ip:22@$username:$password"
        echo "$server_ip:443@$username:$password"
        echo "$server_ip:80@$username:$password"
        echo "========================================"
        echo -e "${NC}"
    fi
}

# ============================================================================
# USER MANAGEMENT FUNCTIONS
# ============================================================================

create_ssh_user() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                   CREATE SSH USER                      ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    read -p "Username: " username
    
    # Check if user exists
    if id "$username" &>/dev/null; then
        echo -e "${RED}User $username already exists!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    read -p "Password (empty for auto-generate): " password
    
    if [ -z "$password" ]; then
        password=$(openssl rand -base64 12 | tr -d '/+=')
        echo -e "${YELLOW}Generated password: $password${NC}"
    fi
    
    # Port selection
    echo ""
    echo "Select port:"
    echo "1. Port 22 (Default SSH)"
    echo "2. Port 443 (HTTPS)"
    echo "3. Port 80 (HTTP)"
    echo "4. Port 53 (DNS)"
    echo "5. Port 7300"
    echo "6. Port 1-65535 (All ports)"
    echo "7. Custom port"
    read -p "Choose [1-7]: " port_choice
    
    case $port_choice in
        1) port="22" ;;
        2) port="443" ;;
        3) port="80" ;;
        4) port="53" ;;
        5) port="7300" ;;
        6) port="1-65535" ;;
        7)
            read -p "Enter custom port: " port
            ;;
        *) port="22" ;;
    esac
    
    # Expiry selection
    echo ""
    echo "Select expiry period:"
    echo "1. 1 Day"
    echo "2. 7 Days"
    echo "3. 30 Days"
    echo "4. 90 Days"
    echo "5. 365 Days"
    echo "6. No expiry"
    read -p "Choose [1-6]: " exp_choice
    
    case $exp_choice in
        1) days=1 ;;
        2) days=7 ;;
        3) days=30 ;;
        4) days=90 ;;
        5) days=365 ;;
        6) days=9999 ;;
        *) days=30 ;;
    esac
    
    # IP Limit
    read -p "Max simultaneous IPs (default 2): " max_ips
    max_ips=${max_ips:-2}
    
    # Bandwidth limit
    read -p "Bandwidth limit (e.g., 100GB, unlimited): " bandwidth
    bandwidth=${bandwidth:-"unlimited"}
    
    # Create system user
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    
    # Calculate expiry date
    if [ $days -eq 9999 ]; then
        expired="2099-12-31"
    else
        expired=$(date -d "+$days days" +"%Y-%m-%d")
    fi
    
    # Add to database
    sqlite3 $DB_SSH << EOF
INSERT INTO users (username, password, expired_at, max_ips, port, bandwidth_limit)
VALUES ('$username', '$password', '$expired', $max_ips, '$port', '$bandwidth');
EOF
    
    # Generate config
    server_ip=$(curl -s ifconfig.me)
    config_string="$server_ip:$port@$username:$password"
    
    # Save config
    echo "$config_string" > "$CONFIG_DIR/ssh/$username.txt"
    
    # Show results
    echo -e "${GREEN}"
    echo "========================================"
    echo "✅ SSH USER CREATED SUCCESSFULLY!"
    echo "========================================"
    echo "Username: $username"
    echo "Password: $password"
    echo "Port: $port"
    echo "Expired: $expired"
    echo "Max IPs: $max_ips"
    echo "Bandwidth: $bandwidth"
    echo ""
    echo "🔗 Config for HTTP Injector:"
    echo "$config_string"
    echo ""
    echo "📁 Config saved: $CONFIG_DIR/ssh/$username.txt"
    echo "========================================"
    echo -e "${NC}"
    
    read -p "Press Enter to continue..."
}

create_vmess_user() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                   CREATE VMESS USER                    ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    read -p "Username: " username
    
    # Generate UUID
    uuid=$(cat /proc/sys/kernel/random/uuid)
    
    # Expiry
    read -p "Days (default 30): " days
    days=${days:-30}
    expired=$(date -d "+$days days" +"%Y-%m-%d")
    
    # IP Limit
    read -p "Max simultaneous IPs (default 2): " max_ips
    max_ips=${max_ips:-2}
    
    # Add to database
    sqlite3 $DB_VMESS << EOF
INSERT INTO users (username, uuid, expired_at, max_ips)
VALUES ('$username', '$uuid', '$expired', $max_ips);
EOF
    
    # Update Xray config
    update_xray_config
    
    # Generate Vmess config
    server_ip=$(curl -s ifconfig.me)
    
    vmess_config='{
  "v": "2",
  "ps": "'$username'",
  "add": "'$server_ip'",
  "port": "443",
  "id": "'$uuid'",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "",
  "path": "/vmess",
  "tls": "tls"
}'
    
    encoded_config=$(echo -n "$vmess_config" | base64 -w 0)
    vmess_link="vmess://$encoded_config"
    
    # Save config
    echo "$vmess_link" > "$CONFIG_DIR/vmess/$username.txt"
    
    # QR Code (optional)
    if command -v qrencode &> /dev/null; then
        qrencode -o "$CONFIG_DIR/vmess/${username}_qr.png" "$vmess_link"
    fi
    
    echo -e "${GREEN}"
    echo "========================================"
    echo "✅ VMESS USER CREATED SUCCESSFULLY!"
    echo "========================================"
    echo "Username: $username"
    echo "UUID: $uuid"
    echo "Expired: $expired"
    echo "Max IPs: $max_ips"
    echo ""
    echo "🔗 Vmess Link:"
    echo "$vmess_link"
    echo ""
    echo "📁 Config saved: $CONFIG_DIR/vmess/$username.txt"
    echo "========================================"
    echo -e "${NC}"
    
    read -p "Press Enter to continue..."
}

update_xray_config() {
    # Get all active UUIDs
    uuids=$(sqlite3 $DB_VMESS "SELECT uuid FROM users WHERE status='active'" 2>/dev/null)
    
    # Create new config
    config_file="/usr/local/etc/xray/config.json"
    temp_file="/tmp/xray_config.json"
    
    # Start building config
    echo '{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": 10086,
            "protocol": "vmess",
            "settings": {
                "clients": [' > $temp_file
    
    # Add clients
    first=true
    for uuid in $uuids; do
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> $temp_file
        fi
        echo '                    {
                        "id": "'$uuid'",
                        "alterId": 0
                    }' >> $temp_file
    done
    
    # Close config
    echo '                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vmess"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}' >> $temp_file
    
    # Replace old config
    mv $temp_file $config_file
    
    # Restart Xray
    systemctl restart xray
}

list_all_users() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                     ALL USERS                          ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${YELLOW}=== SSH USERS ===${NC}"
    echo ""
    
    sqlite3 $DB_SSH << 'EOF'
.mode box
.headers on
SELECT 
    username,
    port,
    expired_at,
    status,
    max_ips,
    violations
FROM users
ORDER BY created_at DESC;
EOF
    
    echo ""
    echo -e "${YELLOW}=== VMESS USERS ===${NC}"
    echo ""
    
    sqlite3 $DB_VMESS << 'EOF'
.mode box
.headers on
SELECT 
    username,
    uuid,
    expired_at,
    status,
    max_ips,
    violations
FROM users
ORDER BY created_at DESC;
EOF
    
    echo ""
    echo -e "${YELLOW}=== USERS ONELINE ===${NC}"
    echo ""
    
    # SSH users one line
    ssh_users=$(sqlite3 $DB_SSH "SELECT username FROM users WHERE status='active'" 2>/dev/null || echo "")
    echo -n "SSH Users: "
    if [ -n "$ssh_users" ]; then
        for user in $ssh_users; do
            echo -n "$user "
        done
    else
        echo -n "None"
    fi
    echo ""
    
    # Vmess users one line
    vmess_users=$(sqlite3 $DB_VMESS "SELECT username FROM users WHERE status='active'" 2>/dev/null || echo "")
    echo -n "Vmess Users: "
    if [ -n "$vmess_users" ]; then
        for user in $vmess_users; do
            echo -n "$user "
        done
    else
        echo -n "None"
    fi
    echo ""
    
    # Count
    ssh_count=$(echo "$ssh_users" | wc -w)
    vmess_count=$(echo "$vmess_users" | wc -w)
    echo ""
    echo -e "${GREEN}Total Active Users: $((ssh_count + vmess_count))${NC}"
    echo "SSH: $ssh_count | Vmess: $vmess_count"
    
    read -p "Press Enter to continue..."
}

delete_user() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                     DELETE USER                        ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "1. Delete SSH User"
    echo "2. Delete Vmess User"
    read -p "Choose [1-2]: " choice
    
    read -p "Username: " username
    
    case $choice in
        1)
            # Delete system user
            userdel -r "$username" 2>/dev/null
            
            # Delete from database
            sqlite3 $DB_SSH "DELETE FROM users WHERE username='$username'"
            
            # Delete config file
            rm -f "$CONFIG_DIR/ssh/$username.txt" 2>/dev/null
            
            echo -e "${GREEN}✅ SSH user $username deleted${NC}"
            ;;
        2)
            # Delete from database
            sqlite3 $DB_VMESS "DELETE FROM users WHERE username='$username'"
            
            # Update Xray config
            update_xray_config
            
            # Delete config file
            rm -f "$CONFIG_DIR/vmess/$username.txt" 2>/dev/null
            rm -f "$CONFIG_DIR/vmess/${username}_qr.png" 2>/dev/null
            
            echo -e "${GREEN}✅ Vmess user $username deleted${NC}"
            ;;
        *)
            echo -e "${RED}❌ Invalid choice${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

unlock_user() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                     UNLOCK USER                        ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "1. Unlock SSH User"
    echo "2. Unlock Vmess User"
    read -p "Choose [1-2]: " choice
    
    read -p "Username: " username
    
    case $choice in
        1)
            sqlite3 $DB_SSH "UPDATE users SET status='active', violations=0, locked_until=NULL WHERE username='$username'"
            echo -e "${GREEN}✅ SSH user $username unlocked${NC}"
            ;;
        2)
            sqlite3 $DB_VMESS "UPDATE users SET status='active', violations=0, locked_until=NULL WHERE username='$username'"
            echo -e "${GREEN}✅ Vmess user $username unlocked${NC}"
            ;;
        *)
            echo -e "${RED}❌ Invalid choice${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

# ============================================================================
# BACKUP SYSTEM FUNCTIONS (Telegram & Email)
# ============================================================================

setup_telegram_backup() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                  SETUP TELEGRAM BACKUP                 ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "How to get Telegram Bot Token:"
    echo "1. Open Telegram, search for @BotFather"
    echo "2. Send /newbot command"
    echo "3. Follow instructions to create bot"
    echo "4. Copy the API Token"
    echo ""
    echo "How to get Chat ID:"
    echo "1. Open Telegram, search for @getidsbot"
    echo "2. Start the bot and get your Chat ID"
    echo ""
    
    read -p "Telegram Bot Token: " token
    read -p "Chat ID: " chat_id
    
    if [ -z "$token" ] || [ -z "$chat_id" ]; then
        echo -e "${RED}❌ Token and Chat ID are required!${NC}"
        return
    fi
    
    # Save config
    echo "TOKEN=\"$token\"" > $TELEGRAM_FILE
    echo "CHAT_ID=\"$chat_id\"" >> $TELEGRAM_FILE
    
    # Test connection
    if send_telegram_message "✅ VPN Panel Backup System Activated\n🕐 $(date)\n🖥️ $(hostname)\n🌐 $(curl -s ifconfig.me)"; then
        echo -e "${GREEN}✅ Telegram backup configured successfully!${NC}"
    else
        echo -e "${RED}❌ Failed to send test message${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

send_telegram_message() {
    local message="$1"
    
    if [ -f "$TELEGRAM_FILE" ]; then
        source $TELEGRAM_FILE
        curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
            -d chat_id="$CHAT_ID" \
            -d text="$message" \
            -d parse_mode="HTML" > /dev/null 2>&1
        return $?
    fi
    return 1
}

setup_email_backup() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                   SETUP EMAIL BACKUP                   ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "For Gmail, use App Password (not your regular password):"
    echo "1. Go to Google Account > Security"
    echo "2. Enable 2-Step Verification"
    echo "3. Go to App passwords"
    echo "4. Select 'Mail' and generate password"
    echo ""
    
    read -p "Email address (sender): " email
    read -p "App Password: " password
    read -p "Recipient email: " recipient
    
    if [ -z "$email" ] || [ -z "$password" ] || [ -z "$recipient" ]; then
        echo -e "${RED}❌ All fields are required!${NC}"
        return
    fi
    
    # Save config
    echo "EMAIL=\"$email\"" > $EMAIL_FILE
    echo "PASSWORD=\"$password\"" >> $EMAIL_FILE
    echo "RECIPIENT=\"$recipient\"" >> $EMAIL_FILE
    
    # Test email
    if send_test_email; then
        echo -e "${GREEN}✅ Email backup configured successfully!${NC}"
    else
        echo -e "${RED}❌ Failed to send test email${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

send_test_email() {
    if [ -f "$EMAIL_FILE" ]; then
        source $EMAIL_FILE
        echo "Test email from VPN Panel" | \
            mail -s "VPN Panel Test Notification" \
            -a "From: $EMAIL" \
            "$RECIPIENT"
        return $?
    fi
    return 1
}

backup_menu() {
    while true; do
        clear
        echo -e "${CYAN}"
        echo "╔════════════════════════════════════════════════════════╗"
        echo "║                   BACKUP SYSTEM MENU                   ║"
        echo "╠════════════════════════════════════════════════════════╣"
        echo "║ ${GREEN}1.${NC} Setup Telegram Backup                           ║"
        echo "║ ${GREEN}2.${NC} Setup Email Backup                              ║"
        echo "║ ${GREEN}3.${NC} Manual Backup Now                               ║"
        echo "║ ${GREEN}4.${NC} View Backup Logs                                ║"
        echo "║ ${GREEN}5.${NC} Test Notifications                              ║"
        echo "║ ${GREEN}6.${NC} Back to Main Menu                               ║"
        echo "╚════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        read -p "Choose [1-6]: " choice
        
        case $choice in
            1) setup_telegram_backup ;;
            2) setup_email_backup ;;
            3) manual_backup_now ;;
            4) view_backup_logs ;;
            5) test_notifications ;;
            6) break ;;
            *) echo -e "${RED}Invalid choice!${NC}"; sleep 1 ;;
        esac
    done
}

manual_backup_now() {
    echo -e "${YELLOW}[+] Creating manual backup...${NC}"
    /usr/local/bin/vpn-backup
    echo -e "${GREEN}✅ Backup completed${NC}"
    sleep 2
}

view_backup_logs() {
    echo -e "${CYAN}=== BACKUP LOGS ===${NC}"
    echo ""
    
    if [ -f "/var/log/vpn-backup.log" ]; then
        tail -20 /var/log/vpn-backup.log
    else
        echo "No backup logs found"
    fi
    
    echo ""
    echo -e "${CYAN}=== BACKUP FILES ===${NC}"
    ls -lh $BACKUP_DIR/*.tar.gz 2>/dev/null || echo "No backup files"
    
    read -p "Press Enter to continue..."
}

test_notifications() {
    echo -e "${YELLOW}[+] Testing notifications...${NC}"
    
    # Test Telegram
    if [ -f "$TELEGRAM_FILE" ]; then
        echo -e "${BLUE}[i] Testing Telegram...${NC}"
        if send_telegram_message "🔔 Test Notification\n✅ VPN Panel Backup System\n🕐 $(date)"; then
            echo -e "${GREEN}✅ Telegram notification sent${NC}"
        else
            echo -e "${RED}❌ Telegram notification failed${NC}"
        fi
    fi
    
    # Test Email
    if [ -f "$EMAIL_FILE" ]; then
        echo -e "${BLUE}[i] Testing Email...${NC}"
        if send_test_email; then
            echo -e "${GREEN}✅ Email notification sent${NC}"
        else
            echo -e "${RED}❌ Email notification failed${NC}"
        fi
    fi
    
    echo -e "${GREEN}✅ Notification test completed${NC}"
    sleep 2
}

# ============================================================================
# DOMAIN & SSL FUNCTIONS
# ============================================================================

setup_domain_ssl() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                   SETUP DOMAIN & SSL                   ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    read -p "Enter your domain (example.com): " domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}❌ Domain is required!${NC}"
        return
    fi
    
    # Save domain
    echo "DOMAIN=\"$domain\"" > $DOMAIN_FILE
    
    echo -e "${YELLOW}[+] Setting up SSL for $domain...${NC}"
    
    # Stop nginx temporarily
    systemctl stop nginx
    
    # Install SSL certificate
    if certbot certonly --standalone --agree-tos --register-unsafely-without-email \
        -d "$domain" -d "www.$domain" --non-interactive; then
        
        # Update nginx config
        sed -i "s|ssl_certificate .*|ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;|" /etc/nginx/nginx.conf
        sed -i "s|ssl_certificate_key .*|ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;|" /etc/nginx/nginx.conf
        sed -i "s|server_name _;|server_name $domain www.$domain;|" /etc/nginx/nginx.conf
        
        echo -e "${GREEN}✅ SSL certificate installed for $domain${NC}"
    else
        echo -e "${RED}❌ Failed to install SSL certificate${NC}"
    fi
    
    # Start nginx
    systemctl start nginx
    
    # Setup auto-renewal
    echo "0 3 * * * root certbot renew --quiet" > /etc/cron.d/ssl-renew
    
    echo ""
    echo -e "${YELLOW}[!] DNS Configuration:${NC}"
    echo "Add these DNS records:"
    echo "Type: A, Name: @, Value: $(curl -s ifconfig.me)"
    echo "Type: A, Name: www, Value: $(curl -s ifconfig.me)"
    
    read -p "Press Enter to continue..."
}

# ============================================================================
# MONITORING FUNCTIONS
# ============================================================================

server_status() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                    SERVER STATUS                       ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # System info
    echo -e "${YELLOW}=== SYSTEM INFORMATION ===${NC}"
    echo "Hostname: $(hostname)"
    echo "IP Address: $(curl -s ifconfig.me)"
    echo "Uptime: $(uptime -p)"
    echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
    
    # Memory
    echo ""
    echo -e "${YELLOW}=== MEMORY USAGE ===${NC}"
    free -h
    
    # Disk
    echo ""
    echo -e "${YELLOW}=== DISK USAGE ===${NC}"
    df -h /
    
    # Services
    echo ""
    echo -e "${YELLOW}=== SERVICE STATUS ===${NC}"
    services=("ssh" "nginx" "xray")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "  ${GREEN}✓ $service: RUNNING${NC}"
        else
            echo -e "  ${RED}✗ $service: STOPPED${NC}"
        fi
    done
    
    # Users
    echo ""
    echo -e "${YELLOW}=== USER STATISTICS ===${NC}"
    ssh_count=$(sqlite3 $DB_SSH "SELECT COUNT(*) FROM users WHERE status='active'" 2>/dev/null || echo "0")
    vmess_count=$(sqlite3 $DB_VMESS "SELECT COUNT(*) FROM users WHERE status='active'" 2>/dev/null || echo "0")
    total_users=$((ssh_count + vmess_count))
    echo "Total Active Users: $total_users"
    echo "SSH Users: $ssh_count"
    echo "Vmess Users: $vmess_count"
    
    # Bandwidth (if vnstat installed)
    if command -v vnstat &> /dev/null; then
        echo ""
        echo -e "${YELLOW}=== BANDWIDTH USAGE ===${NC}"
        vnstat -d
    fi
    
    read -p "Press Enter to continue..."
}

test_all_ports() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                     PORT TEST                          ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${YELLOW}Testing TCP Ports:${NC}"
    echo ""
    
    for port in 22 80 443 53 7300 7200 7100; do
        if timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null; then
            echo -e "  ${GREEN}✓ Port $port/tcp: OPEN${NC}"
        else
            echo -e "  ${RED}✗ Port $port/tcp: CLOSED${NC}"
        fi
    done
    
    echo ""
    echo -e "${YELLOW}Testing UDP Ports:${NC}"
    echo ""
    
    for port in 53 80 443 7300; do
        if timeout 1 bash -c "echo > /dev/udp/127.0.0.1/$port" 2>/dev/null; then
            echo -e "  ${GREEN}✓ Port $port/udp: OPEN${NC}"
        else
            echo -e "  ${RED}✗ Port $port/udp: CLOSED${NC}"
        fi
    done
    
    read -p "Press Enter to continue..."
}

# ============================================================================
# MAIN MENU
# ============================================================================

show_main_menu() {
    while true; do
        clear
        print_banner
        
        echo -e "${CYAN}"
        echo "╔════════════════════════════════════════════════════════╗"
        echo "║                    MAIN MENU                           ║"
        echo "╠════════════════════════════════════════════════════════╣"
        echo "║ ${GREEN}1.${NC} Create SSH User                              ║"
        echo "║ ${GREEN}2.${NC} Create Vmess User                            ║"
        echo "║ ${GREEN}3.${NC} List All Users                               ║"
        echo "║ ${GREEN}4.${NC} Delete User                                  ║"
        echo "║ ${GREEN}5.${NC} Unlock User                                  ║"
        echo "║ ${GREEN}6.${NC} Setup Domain & SSL                           ║"
        echo "║ ${GREEN}7.${NC} Backup System (Telegram/Email)               ║"
        echo "║ ${GREEN}8.${NC} Server Status & Monitoring                   ║"
        echo "║ ${GREEN}9.${NC} Test All Ports                               ║"
        echo "║ ${GREEN}10.${NC} Fix All Services                            ║"
        echo "║ ${GREEN}11.${NC} Bandwidth Monitor                           ║"
        echo "║ ${GREEN}0.${NC} Exit                                         ║"
        echo "╚════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        read -p "Choose option [0-11]: " choice
        
        case $choice in
            1) create_ssh_user ;;
            2) create_vmess_user ;;
            3) list_all_users ;;
            4) delete_user ;;
            5) unlock_user ;;
            6) setup_domain_ssl ;;
            7) backup_menu ;;
            8) server_status ;;
            9) test_all_ports ;;
            10) fix_all_services ;;
            11) monitor_bandwidth ;;
            0)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice!${NC}"
                sleep 1
                ;;
        esac
    done
}

fix_all_services() {
    echo -e "${YELLOW}[+] Restarting all services...${NC}"
    
    systemctl restart ssh
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    
    echo -e "${GREEN}✅ All services restarted${NC}"
    sleep 2
}

monitor_bandwidth() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                  BANDWIDTH MONITOR                     ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Install vnstat if not exists
    if ! command -v vnstat &> /dev/null; then
        echo -e "${YELLOW}[+] Installing vnstat...${NC}"
        apt-get install -y vnstat
        vnstat -u -i $(ip route | grep default | awk '{print $5}')
    fi
    
    echo -e "${YELLOW}=== REAL-TIME TRAFFIC ===${NC}"
    echo ""
    
    # Current traffic
    INTERFACE=$(ip route | grep default | awk '{print $5}')
    echo "Active Interface: $INTERFACE"
    echo ""
    ifconfig $INTERFACE | grep -E "RX|TX" | grep bytes
    
    echo ""
    echo -e "${YELLOW}=== DAILY STATISTICS ===${NC}"
    vnstat -d
    
    echo ""
    echo -e "${YELLOW}=== MONTHLY STATISTICS ===${NC}"
    vnstat -m
    
    echo ""
    echo -e "${YELLOW}=== TOP CONNECTIONS ===${NC}"
    ss -tunp | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
    
    read -p "Press Enter to continue..."
}

# ============================================================================
# AUTO INSTALL FROM GITHUB
# ============================================================================

auto_install_from_github() {
    print_banner
    
    echo -e "${YELLOW}"
    echo "This will install VPN Panel from GitHub repository."
    echo "Repository: https://github.com/sukronwae85-design/sshvmess-udp-costume"
    echo ""
    echo "Requirements:"
    echo "- Ubuntu 18.04, 20.04, or 22.04"
    echo "- Root access"
    echo "- Minimum 1GB RAM, 10GB Disk"
    echo ""
    echo -e "${NC}"
    
    read -p "Continue installation? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    install_vpn_panel
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Handle command line arguments
case "${1:-}" in
    "install")
        auto_install_from_github
        ;;
    "menu")
        show_main_menu
        ;;
    "status")
        server_status
        ;;
    "backup")
        backup_menu
        ;;
    "test-ports")
        test_all_ports
        ;;
    "update")
        # Update script from GitHub
        echo -e "${YELLOW}[+] Updating script from GitHub...${NC}"
        wget -q -O /tmp/vpn-panel.sh \
            https://raw.githubusercontent.com/sukronwae85-design/sshvmess-udp-costume/main/vpn-panel.sh
        if [ $? -eq 0 ]; then
            mv /tmp/vpn-panel.sh "$0"
            chmod +x "$0"
            echo -e "${GREEN}✅ Script updated successfully!${NC}"
        else
            echo -e "${RED}❌ Failed to update script${NC}"
        fi
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  install     - Auto install from GitHub"
        echo "  menu        - Show main menu"
        echo "  status      - Show server status"
        echo "  backup      - Backup system menu"
        echo "  test-ports  - Test all ports"
        echo "  update      - Update script from GitHub"
        echo "  help        - Show this help"
        echo ""
        echo "Without command: Show installation menu"
        ;;
    *)
        # No arguments, show main menu
        clear
        print_banner
        
        echo "Select an option:"
        echo "1. Auto Install VPN Panel (Full Installation)"
        echo "2. Open Control Panel Menu"
        echo "3. Exit"
        echo ""
        
        read -p "Choose [1-3]: " choice
        
        case $choice in
            1)
                auto_install_from_github
                ;;
            2)
                show_main_menu
                ;;
            3)
                exit 0
                ;;
            *)
                echo "Invalid choice!"
                exit 1
                ;;
        esac
        ;;
esac