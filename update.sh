#!/bin/bash
set -e

cd ~/mcsnipergo-web

# Check for updates
git fetch
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse @{u})

if [ "$LOCAL" = "$REMOTE" ]; then
    exit 0
fi

# Pull and rebuild
git pull
go build -o mcsnipergo-web ./cmd/web/

# Restart service
sudo systemctl restart mcsnipergo
