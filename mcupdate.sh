#!/bin/bash
set -e

echo "Updating MCsniperGO..."
cd /home/ec2-user/mcsnipergo-web

git fetch origin
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse @{u})

if [ "$LOCAL" = "$REMOTE" ]; then
    echo "Already up to date."
    exit 0
fi

echo "Pulling updates..."
git pull

echo "Building..."
go build -o mcsnipergo-web ./cmd/web/

echo "Restarting service..."
sudo systemctl restart mcsnipergo

echo "Done!"
