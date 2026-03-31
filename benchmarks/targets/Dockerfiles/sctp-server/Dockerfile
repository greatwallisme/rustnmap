# RustNmap SCTP Target - SCTP echo server
# Covers: -sZ (SCTP INIT), -sY (SCTP Cookie Echo) scan types
FROM registry.cn-shanghai.aliyuncs.com/greatwallisme/alpine:3.19

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache \
    socat \
    python3 \
    py3-pip \
    lksctp-tools \
    && pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple \
    && pip3 config set global.trusted-host pypi.tuna.tsinghua.edu.cn \
    && rm -rf /var/cache/apk/*

# Load SCTP kernel module and create SCTP echo server
COPY <<'PYEOF' /usr/local/bin/sctp_server.py
#!/usr/bin/env python3
"""SCTP echo server using lksctp-tools / raw sockets."""
import socket
import struct
import os
import sys
import signal

SCTP_PORTS = [7, 80, 36712]

def start_sctp_echo(port):
    """Start an SCTP echo server on the given port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        print(f"SCTP echo server listening on port {port}", flush=True)

        while True:
            try:
                conn, addr = sock.accept()
                data = conn.recv(4096)
                if data:
                    conn.send(data)
                conn.close()
            except Exception:
                continue
    except Exception as e:
        print(f"Failed to start SCTP server on port {port}: {e}", flush=True)

if __name__ == "__main__":
    # Try to load SCTP module
    try:
        os.system("modprobe sctp 2>/dev/null || true")
    except Exception:
        pass

    # Fork a process for each SCTP port
    pids = []
    for port in SCTP_PORTS:
        pid = os.fork()
        if pid == 0:
            start_sctp_echo(port)
            sys.exit(0)
        else:
            pids.append(pid)

    # Also start TCP echo on the same ports as fallback
    # (in case SCTP is not available in kernel)
    for port in SCTP_PORTS:
        pid = os.fork()
        if pid == 0:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('0.0.0.0', port))
                sock.listen(5)
                while True:
                    conn, addr = sock.accept()
                    conn.close()
            except Exception:
                pass
            sys.exit(0)
        else:
            pids.append(pid)

    # Wait for all children
    for pid in pids:
        try:
            os.waitpid(pid, 0)
        except Exception:
            pass
PYEOF

RUN chmod +x /usr/local/bin/sctp_server.py

EXPOSE 7/sctp 80/sctp 36712/sctp 7/tcp 80/tcp 36712/tcp

CMD ["python3", "/usr/local/bin/sctp_server.py"]
