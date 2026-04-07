#!/bin/bash
set -e

# Start virtual framebuffer at low resolution
Xvfb :1 -screen 0 640x480x24 &
XVFB_PID=$!
sleep 2

# Start x11vnc with minimal CPU settings:
#   -noxdamage: don't use X DAMAGE extension (causes CPU spin)
#   -nowf:      no wireframe
#   -noscr:     no scroll detection
#   -wait 200:  poll interval 200ms (default 20ms)
#   -defer 200: defer update 200ms
#   -nopw:      no password for testing
#   -forever:   don't exit after first disconnect
#   -shared:    allow multiple connections
x11vnc -display :1 -forever -shared -nopw \
    -rfbport 5900 \
    -noxdamage -nowf -noscr -nowcr \
    -wait 200 -defer 200 &

# Wait until port 5900 is listening
for i in $(seq 1 30); do
    if bash -c 'echo > /dev/tcp/127.0.0.1/5900' 2>/dev/null; then
        echo "VNC server ready on port 5900"
        break
    fi
    sleep 1
done

# Keep container alive
wait $XVFB_PID
