# MCsniperGO Web

Fast Minecraft username sniper with a secure web control panel. Remote access from anywhere with HTTPS, password protection, and comprehensive rate limiting.

## Features

- **Web UI** - Full control panel accessible from any browser
- **HTTPS** - Automatic TLS certificates via Let's Encrypt
- **Password Protected** - bcrypt hashing, rate-limited login
- **Fast** - Optimized with connection pooling, DNS pre-warming, buffered channels
- **NameMC Integration** - Paste NameMC/3name links, auto-extracts usernames
- **File Management** - Edit accounts and proxies directly from the web UI
- **Live Logs** - Real-time SSE log streaming
- **Rate Limiting** - Protection against brute force and DoS attacks

## Quick Start

### Build from Source

```bash
git clone https://github.com/Sha-Dox/mcsnipergo-web.git
cd mcsnipergo-web
go build -o mcsnipergo-web ./cmd/web/
```

### Run

```bash
# With HTTPS (recommended for production)
./mcsnipergo-web --password mySecret123 --domain sniper.example.com

# Without HTTPS (development only)
./mcsnipergo-web --password mySecret123 --bind 0.0.0.0 --port 8080
```

## Amazon Linux Deployment

### 1. Install Go

```bash
sudo yum update -y
sudo yum install -y git

# Install Go 1.21+
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
rm go1.21.6.linux-amd64.tar.gz

echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 2. Clone and Build

```bash
git clone https://github.com/Sha-Dox/mcsnipergo-web.git
cd mcsnipergo-web
go build -o mcsnipergo-web ./cmd/web/
```

### 3. Set Up DNS

Point your domain's A record to your EC2 instance's public IP.

### 4. Open Firewall Ports

```bash
# In AWS Security Group, allow:
# - Port 80 (HTTP, for Let's Encrypt verification)
# - Port 443 (HTTPS)
# - Port 8080 (if not using domain)
```

### 5. Run with systemd

Create `/etc/systemd/system/mcsnipergo.service`:

```ini
[Unit]
Description=MCsniperGO Web Server
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/home/ec2-user/mcsnipergo-web
ExecStart=/home/ec2-user/mcsnipergo-web/mcsnipergo-web --password YOUR_PASSWORD --domain sniper.example.com
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable mcsnipergo
sudo systemctl start mcsnipergo
sudo systemctl status mcsnipergo
```

### 6. Access

Open `https://sniper.example.com` from anywhere and login with your password.

## Usage

### Accounts

Place accounts in the appropriate files (or edit via web UI):

- `gc.txt` - Gift card accounts (no username)
- `ms.txt` - Microsoft accounts (with username)
- `gp.txt` - Game Pass accounts

Format:
```
email:password
```
or
```
bearer_token
```

### Proxies

Edit `proxies.txt` (or via web UI):
```
user:pass@ip:port
```

### Sniping

1. Enter target username or paste NameMC/3name link
2. Set drop range (unix timestamps) or leave empty for immediate/infinite
3. Click "Start Snipe"
4. Monitor live logs

## Security

- **HTTPS** - Automatic Let's Encrypt certificates
- **bcrypt** - Industry-standard password hashing
- **Rate Limiting** - Login attempts, API calls, SSE connections
- **Security Headers** - XSS, CSRF, clickjacking protection
- **Request Limits** - 1MB max request size
- **CORS** - Same-origin only
- **Session Tokens** - 256-bit random, stored in HTTP-only cookies
- **File Permissions** - 0600 for account files

## Command Line Options

```
--password string   Password for web login (required)
--domain string     Domain for automatic HTTPS via Let's Encrypt
--bind string       Bind address (default "0.0.0.0")
--port string       Port to listen on (default "8080")
--cert-dir string   Directory to store TLS certificates (default "./certs")
```

## Building for Different Platforms

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o mcsnipergo-web-linux ./cmd/web/

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o mcsnipergo-web-linux-arm ./cmd/web/

# Windows
GOOS=windows GOARCH=amd64 go build -o mcsnipergo-web.exe ./cmd/web/

# macOS
GOOS=darwin GOARCH=amd64 go build -o mcsnipergo-web-mac ./cmd/web/
```

## License

Based on [MCsniperGO](https://github.com/Kqzz/MCsniperGO) by Kqzz.

## Disclaimer

This tool is for educational purposes only. Use at your own risk. The authors are not responsible for any consequences resulting from the use of this software.
