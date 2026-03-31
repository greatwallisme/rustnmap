# RustNmap Telnet Target - busybox telnetd
# Covers: banner script, telnet version detection
FROM registry.cn-shanghai.aliyuncs.com/greatwallisme/alpine:3.19

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache \
    busybox-extras \
    netcat-openbsd \
    && rm -rf /var/cache/apk/*

# Create test user
RUN adduser -D -s /bin/sh testuser && \
    echo "testuser:test123" | chpasswd && \
    echo "root:root" | chpasswd

# Create login banner
RUN echo "RustNmap Telnet Test Server" > /etc/issue.net && \
    echo "Welcome to RustNmap Telnet Test Target" >> /etc/issue.net

EXPOSE 23/tcp

CMD ["telnetd", "-l", "/bin/sh", "-b", "0.0.0.0", "-F"]
