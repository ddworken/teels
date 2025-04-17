#!/bin/bash

# Kill any existing socat processes
killall socat || true

# Start all socat processes in the background
while true; do
    socat vsock-listen:8001,fork,reuseaddr tcp-connect:acme-staging-v02.api.letsencrypt.org:443 &
    socat vsock-listen:8002,fork,reuseaddr tcp-connect:acme-v02.api.letsencrypt.org:443 &
    socat vsock-listen:8003,fork,reuseaddr tcp-connect:teels-attestations.s3.ap-south-1.amazonaws.com:443 &
    socat tcp-listen:80,fork,reuseaddr,keepalive vsock-connect:16:80,keepalive &
    socat tcp-listen:443,fork,reuseaddr,keepalive vsock-connect:16:443,keepalive &
    
    # Wait for any process to die
    wait -n
    echo "A socat process died, restarting all..."
    killall socat || true
    sleep 1
done 