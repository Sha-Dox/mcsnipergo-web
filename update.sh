#!/bin/bash
set -e

cd ~/mcsnipergo-web

# Quick remote check (no download)
REMOTE_SHA=$(git ls-remote origin HEAD | awk '{print $1}')
LOCAL_SHA=$(git rev-parse HEAD)

if [ "$REMOTE_SHA" = "$LOCAL_SHA" ]; then
    exit 0
fi

# Update
git pull
go build -o mcsnipergo-web ./cmd/web/
sudo systemctl restart mcsnipergo
