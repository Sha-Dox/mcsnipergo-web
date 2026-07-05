#!/bin/bash
set -e

echo "MCsniperGO Web - One-Line Installer"
echo "===================================="

read -p "Enter web password: " -s PASSWORD
echo
read -p "Enter domain (leave empty for HTTP only): " DOMAIN

sudo yum update -y
sudo yum install -y git wget

if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    wget -q https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
    rm go1.21.6.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi

echo "Cloning repository..."
cd ~
rm -rf mcsnipergo-web
git clone https://github.com/Sha-Dox/mcsnipergo-web.git
cd mcsnipergo-web

echo "Building..."
go build -o mcsnipergo-web ./cmd/web/

echo "Creating systemd service..."
sudo tee /etc/systemd/system/mcsnipergo.service > /dev/null <<EOF
[Unit]
Description=MCsniperGO Web Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/mcsnipergo-web
ExecStart=$HOME/mcsnipergo-web/mcsnipergo-web --password $PASSWORD ${DOMAIN:+--domain $DOMAIN}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable mcsnipergo
sudo systemctl start mcsnipergo

echo
echo "Installation complete!"
echo "======================"
if [ -n "$DOMAIN" ]; then
    echo "Access: https://$DOMAIN"
else
    IP=$(curl -s ifconfig.me)
    echo "Access: http://$IP:8080"
fi
echo
echo "Commands:"
echo "  sudo systemctl status mcsnipergo"
echo "  sudo systemctl restart mcsnipergo"
echo "  sudo journalctl -u mcsnipergo -f"
echo
echo "Don't forget to open ports in AWS Security Group:"
if [ -n "$DOMAIN" ]; then
    echo "  - Port 80 (HTTP for Let's Encrypt)"
    echo "  - Port 443 (HTTPS)"
else
    echo "  - Port 8080 (HTTP)"
fi
