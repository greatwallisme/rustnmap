# RustNmap LDAP Target - OpenLDAP on Alpine
# Covers: ldap-rootdse, ldap-search scripts
FROM registry.cn-shanghai.aliyuncs.com/greatwallisme/alpine:3.19

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache \
    openldap \
    openldap-clients \
    openldap-back-mdb \
    openldap-overlay-memberof \
    openldap-overlay-refint \
    && rm -rf /var/cache/apk/*

# Configure slapd
RUN mkdir -p /var/lib/openldap /var/run/openldap /etc/openldap/slapd.d && \
    chown -R ldap:ldap /var/lib/openldap /var/run/openldap /etc/openldap/slapd.d

# Basic slapd config
COPY <<'EOF' /etc/openldap/slapd.conf
include         /etc/openldap/schema/core.schema
include         /etc/openldap/schema/cosine.schema
include         /etc/openldap/schema/inetorgperson.schema
include         /etc/openldap/schema/nis.schema

pidfile         /var/run/openldap/slapd.pid
argsfile        /var/run/openldap/slapd.args

modulepath      /usr/lib/openldap
moduleload      /usr/lib/openldap/back_mdb.so
moduleload      /usr/lib/openldap/memberof.so
moduleload      /usr/lib/openldap/refint.so

database        mdb
maxsize         1073741824
suffix          "dc=rustnmap,dc=test"
rootdn          "cn=admin,dc=rustnmap,dc=test"
rootpw          test123
directory       /var/lib/openldap

index           objectClass eq
index           uid eq
index           mail eq

overlay         memberof
overlay         refint
refint_attributes memberOf
EOF

# Init LDIF
COPY <<'EOF' /tmp/init.ldif
dn: dc=rustnmap,dc=test
objectClass: top
objectClass: dcObject
objectClass: organization
o: RustNmap Test
dc: rustnmap

dn: cn=admin,dc=rustnmap,dc=test
objectClass: organizationalRole
cn: admin
description: LDAP administrator
userPassword: test123

dn: ou=users,dc=rustnmap,dc=test
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=rustnmap,dc=test
objectClass: organizationalUnit
ou: groups

dn: cn=testuser,ou=users,dc=rustnmap,dc=test
objectClass: inetOrgPerson
cn: testuser
sn: User
uid: testuser
mail: testuser@rustnmap.test
userPassword: test123

dn: cn=adminuser,ou=users,dc=rustnmap,dc=test
objectClass: inetOrgPerson
cn: adminuser
sn: Admin
uid: adminuser
mail: admin@rustnmap.test
userPassword: admin123

dn: cn=testgroup,ou=groups,dc=rustnmap,dc=test
objectClass: groupOfNames
cn: testgroup
member: cn=testuser,ou=users,dc=rustnmap,dc=test
member: cn=adminuser,ou=users,dc=rustnmap,dc=test
EOF

# Startup script
COPY <<'SCRIPT' /usr/local/bin/start-slapd.sh
#!/bin/sh

# Start slapd with config file (foreground for Docker)
slapd -f /etc/openldap/slapd.conf -h "ldap://0.0.0.0:389 ldaps://0.0.0.0:636" -u ldap -g ldap -d 256 &
SLAPD_PID=$!

# Wait for slapd to start
sleep 3

# Add initial data if not already present
if ! ldapsearch -x -H ldap://127.0.0.1:389 -b "dc=rustnmap,dc=test" -LLL "(objectClass=organization)" 2>/dev/null | grep -q "rustnmap"; then
    ldapadd -x -H ldap://127.0.0.1:389 -D "cn=admin,dc=rustnmap,dc=test" -w test123 -f /tmp/init.ldif 2>&1 || true
fi

echo "OpenLDAP ready on port 389"

# Wait for slapd process
wait $SLAPD_PID
SCRIPT

RUN chmod +x /usr/local/bin/start-slapd.sh

EXPOSE 389/tcp 636/tcp

CMD ["/usr/local/bin/start-slapd.sh"]
