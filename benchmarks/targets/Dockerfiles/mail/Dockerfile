# RustNmap Mail Target - Dovecot with POP3 + IMAP + SSL
# Covers: pop3-capabilities, imap-capabilities, banner scripts
FROM registry.cn-shanghai.aliyuncs.com/greatwallisme/alpine:3.19

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache \
    dovecot \
    dovecot-pop3d \
    openssl \
    netcat-openbsd \
    && rm -rf /var/cache/apk/*

# Create test user
RUN adduser -D -s /bin/sh testuser && \
    echo "testuser:test123" | chpasswd

# Create passwd-file for dovecot auth (Alpine lacks PAM)
RUN mkdir -p /etc/dovecot/auth && \
    echo "testuser:{PLAIN}test123::::::" > /etc/dovecot/auth/passwdfile && \
    chmod 600 /etc/dovecot/auth/passwdfile

# Generate self-signed SSL certificate
RUN mkdir -p /etc/dovecot/ssl && \
    openssl req -x509 -newkey rsa:2048 -keyout /etc/dovecot/ssl/dovecot.key \
    -out /etc/dovecot/ssl/dovecot.crt -days 3650 -nodes \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=RustNmap Test/OU=Mail/CN=mail.rustnmap.test" && \
    chmod 600 /etc/dovecot/ssl/dovecot.key

# Configure Dovecot
COPY <<'EOF' /etc/dovecot/dovecot.conf
# Protocols
protocols = imap pop3

# Listen on all interfaces
listen = *

# SSL
ssl = required
ssl_cert = </etc/dovecot/ssl/dovecot.crt
ssl_key = </etc/dovecot/ssl/dovecot.key

# Authentication
disable_plaintext_auth = no
auth_mechanisms = plain login

# Passdb - use passwd-file instead of PAM (not available on Alpine)
passdb {
  driver = passwd-file
  args = /etc/dovecot/auth/passwdfile
}

userdb {
  driver = passwd
}

# Mail location
mail_location = mbox:~/Mail:INBOX=/var/mail/%u

# POP3 settings
protocol pop3 {
  pop3_uidl_format = %08Xu%08Xv
  mail_max_userip_connections = 50
}

# IMAP settings
protocol imap {
  mail_max_userip_connections = 50
}

# Logging
log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot-info.log
debug_log_path = /var/log/dovecot-debug.log

# Login greeting
login_greeting = RustNmap Dovecot ready.
EOF

# Create mail spool
RUN mkdir -p /var/mail && \
    touch /var/mail/testuser && \
    chown testuser:testuser /var/mail/testuser

EXPOSE 110/tcp 143/tcp 993/tcp 995/tcp

CMD ["dovecot", "-F"]
