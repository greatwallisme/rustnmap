// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  greatwallisme
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Embedded Nmap data files for self-contained deployment.
//!
//! All Nmap database, library, and script files are compiled into the binary.
//! The `init` subcommand extracts them to `~/.rustnmap/` at runtime.

/// A single embedded file with its relative path and binary content.
#[derive(Debug)]
pub struct EmbeddedFile {
    /// Relative path under `~/.rustnmap/` (e.g., `db/nmap-services`).
    pub path: &'static str,
    /// File content bytes.
    pub data: &'static [u8],
}

/// Total number of embedded files (db + nselib + scripts).
pub const EMBEDDED_FILE_COUNT: usize = 804;

/// Returns the complete list of all embedded data files.
///
/// Each entry contains the relative destination path and the file content.
#[must_use]
pub fn all_files() -> &'static [EmbeddedFile] {
    &EMBEDDED_FILES
}

static EMBEDDED_FILES: [EmbeddedFile; EMBEDDED_FILE_COUNT] = [
    EmbeddedFile {
        path: "db/nmap-mac-prefixes",
        data: include_bytes!("../../../db/nmap-mac-prefixes"),
    },
    EmbeddedFile {
        path: "db/nmap-os-db",
        data: include_bytes!("../../../db/nmap-os-db"),
    },
    EmbeddedFile {
        path: "db/nmap-protocols",
        data: include_bytes!("../../../db/nmap-protocols"),
    },
    EmbeddedFile {
        path: "db/nmap-rpc",
        data: include_bytes!("../../../db/nmap-rpc"),
    },
    EmbeddedFile {
        path: "db/nmap-service-probes",
        data: include_bytes!("../../../db/nmap-service-probes"),
    },
    EmbeddedFile {
        path: "db/nmap-services",
        data: include_bytes!("../../../db/nmap-services"),
    },
    EmbeddedFile {
        path: "nselib/afp.lua",
        data: include_bytes!("../../../nselib/afp.lua"),
    },
    EmbeddedFile {
        path: "nselib/ajp.lua",
        data: include_bytes!("../../../nselib/ajp.lua"),
    },
    EmbeddedFile {
        path: "nselib/amqp.lua",
        data: include_bytes!("../../../nselib/amqp.lua"),
    },
    EmbeddedFile {
        path: "nselib/anyconnect.lua",
        data: include_bytes!("../../../nselib/anyconnect.lua"),
    },
    EmbeddedFile {
        path: "nselib/asn1.lua",
        data: include_bytes!("../../../nselib/asn1.lua"),
    },
    EmbeddedFile {
        path: "nselib/base32.lua",
        data: include_bytes!("../../../nselib/base32.lua"),
    },
    EmbeddedFile {
        path: "nselib/base64.lua",
        data: include_bytes!("../../../nselib/base64.lua"),
    },
    EmbeddedFile {
        path: "nselib/bin.lua",
        data: include_bytes!("../../../nselib/bin.lua"),
    },
    EmbeddedFile {
        path: "nselib/bitcoin.lua",
        data: include_bytes!("../../../nselib/bitcoin.lua"),
    },
    EmbeddedFile {
        path: "nselib/bits.lua",
        data: include_bytes!("../../../nselib/bits.lua"),
    },
    EmbeddedFile {
        path: "nselib/bittorrent.lua",
        data: include_bytes!("../../../nselib/bittorrent.lua"),
    },
    EmbeddedFile {
        path: "nselib/bjnp.lua",
        data: include_bytes!("../../../nselib/bjnp.lua"),
    },
    EmbeddedFile {
        path: "nselib/brute.lua",
        data: include_bytes!("../../../nselib/brute.lua"),
    },
    EmbeddedFile {
        path: "nselib/cassandra.lua",
        data: include_bytes!("../../../nselib/cassandra.lua"),
    },
    EmbeddedFile {
        path: "nselib/citrixxml.lua",
        data: include_bytes!("../../../nselib/citrixxml.lua"),
    },
    EmbeddedFile {
        path: "nselib/coap.lua",
        data: include_bytes!("../../../nselib/coap.lua"),
    },
    EmbeddedFile {
        path: "nselib/comm.lua",
        data: include_bytes!("../../../nselib/comm.lua"),
    },
    EmbeddedFile {
        path: "nselib/creds.lua",
        data: include_bytes!("../../../nselib/creds.lua"),
    },
    EmbeddedFile {
        path: "nselib/cvs.lua",
        data: include_bytes!("../../../nselib/cvs.lua"),
    },
    EmbeddedFile {
        path: "nselib/datafiles.lua",
        data: include_bytes!("../../../nselib/datafiles.lua"),
    },
    EmbeddedFile {
        path: "nselib/datetime.lua",
        data: include_bytes!("../../../nselib/datetime.lua"),
    },
    EmbeddedFile {
        path: "nselib/dhcp.lua",
        data: include_bytes!("../../../nselib/dhcp.lua"),
    },
    EmbeddedFile {
        path: "nselib/dhcp6.lua",
        data: include_bytes!("../../../nselib/dhcp6.lua"),
    },
    EmbeddedFile {
        path: "nselib/dicom.lua",
        data: include_bytes!("../../../nselib/dicom.lua"),
    },
    EmbeddedFile {
        path: "nselib/dns.lua",
        data: include_bytes!("../../../nselib/dns.lua"),
    },
    EmbeddedFile {
        path: "nselib/dnsbl.lua",
        data: include_bytes!("../../../nselib/dnsbl.lua"),
    },
    EmbeddedFile {
        path: "nselib/dnssd.lua",
        data: include_bytes!("../../../nselib/dnssd.lua"),
    },
    EmbeddedFile {
        path: "nselib/drda.lua",
        data: include_bytes!("../../../nselib/drda.lua"),
    },
    EmbeddedFile {
        path: "nselib/eap.lua",
        data: include_bytes!("../../../nselib/eap.lua"),
    },
    EmbeddedFile {
        path: "nselib/eigrp.lua",
        data: include_bytes!("../../../nselib/eigrp.lua"),
    },
    EmbeddedFile {
        path: "nselib/formulas.lua",
        data: include_bytes!("../../../nselib/formulas.lua"),
    },
    EmbeddedFile {
        path: "nselib/ftp.lua",
        data: include_bytes!("../../../nselib/ftp.lua"),
    },
    EmbeddedFile {
        path: "nselib/geoip.lua",
        data: include_bytes!("../../../nselib/geoip.lua"),
    },
    EmbeddedFile {
        path: "nselib/giop.lua",
        data: include_bytes!("../../../nselib/giop.lua"),
    },
    EmbeddedFile {
        path: "nselib/gps.lua",
        data: include_bytes!("../../../nselib/gps.lua"),
    },
    EmbeddedFile {
        path: "nselib/http.lua",
        data: include_bytes!("../../../nselib/http.lua"),
    },
    EmbeddedFile {
        path: "nselib/httpspider.lua",
        data: include_bytes!("../../../nselib/httpspider.lua"),
    },
    EmbeddedFile {
        path: "nselib/iax2.lua",
        data: include_bytes!("../../../nselib/iax2.lua"),
    },
    EmbeddedFile {
        path: "nselib/idna.lua",
        data: include_bytes!("../../../nselib/idna.lua"),
    },
    EmbeddedFile {
        path: "nselib/iec61850mms.lua",
        data: include_bytes!("../../../nselib/iec61850mms.lua"),
    },
    EmbeddedFile {
        path: "nselib/ike.lua",
        data: include_bytes!("../../../nselib/ike.lua"),
    },
    EmbeddedFile {
        path: "nselib/imap.lua",
        data: include_bytes!("../../../nselib/imap.lua"),
    },
    EmbeddedFile {
        path: "nselib/informix.lua",
        data: include_bytes!("../../../nselib/informix.lua"),
    },
    EmbeddedFile {
        path: "nselib/ipOps.lua",
        data: include_bytes!("../../../nselib/ipOps.lua"),
    },
    EmbeddedFile {
        path: "nselib/ipmi.lua",
        data: include_bytes!("../../../nselib/ipmi.lua"),
    },
    EmbeddedFile {
        path: "nselib/ipp.lua",
        data: include_bytes!("../../../nselib/ipp.lua"),
    },
    EmbeddedFile {
        path: "nselib/irc.lua",
        data: include_bytes!("../../../nselib/irc.lua"),
    },
    EmbeddedFile {
        path: "nselib/iscsi.lua",
        data: include_bytes!("../../../nselib/iscsi.lua"),
    },
    EmbeddedFile {
        path: "nselib/isns.lua",
        data: include_bytes!("../../../nselib/isns.lua"),
    },
    EmbeddedFile {
        path: "nselib/jdwp.lua",
        data: include_bytes!("../../../nselib/jdwp.lua"),
    },
    EmbeddedFile {
        path: "nselib/json.lua",
        data: include_bytes!("../../../nselib/json.lua"),
    },
    EmbeddedFile {
        path: "nselib/knx.lua",
        data: include_bytes!("../../../nselib/knx.lua"),
    },
    EmbeddedFile {
        path: "nselib/ldap.lua",
        data: include_bytes!("../../../nselib/ldap.lua"),
    },
    EmbeddedFile {
        path: "nselib/lfs.luadoc",
        data: include_bytes!("../../../nselib/lfs.luadoc"),
    },
    EmbeddedFile {
        path: "nselib/libssh2.luadoc",
        data: include_bytes!("../../../nselib/libssh2.luadoc"),
    },
    EmbeddedFile {
        path: "nselib/listop.lua",
        data: include_bytes!("../../../nselib/listop.lua"),
    },
    EmbeddedFile {
        path: "nselib/lpeg-utility.lua",
        data: include_bytes!("../../../nselib/lpeg-utility.lua"),
    },
    EmbeddedFile {
        path: "nselib/lpeg.luadoc",
        data: include_bytes!("../../../nselib/lpeg.luadoc"),
    },
    EmbeddedFile {
        path: "nselib/ls.lua",
        data: include_bytes!("../../../nselib/ls.lua"),
    },
    EmbeddedFile {
        path: "nselib/match.lua",
        data: include_bytes!("../../../nselib/match.lua"),
    },
    EmbeddedFile {
        path: "nselib/membase.lua",
        data: include_bytes!("../../../nselib/membase.lua"),
    },
    EmbeddedFile {
        path: "nselib/mobileme.lua",
        data: include_bytes!("../../../nselib/mobileme.lua"),
    },
    EmbeddedFile {
        path: "nselib/mongodb.lua",
        data: include_bytes!("../../../nselib/mongodb.lua"),
    },
    EmbeddedFile {
        path: "nselib/mqtt.lua",
        data: include_bytes!("../../../nselib/mqtt.lua"),
    },
    EmbeddedFile {
        path: "nselib/msrpc.lua",
        data: include_bytes!("../../../nselib/msrpc.lua"),
    },
    EmbeddedFile {
        path: "nselib/msrpcperformance.lua",
        data: include_bytes!("../../../nselib/msrpcperformance.lua"),
    },
    EmbeddedFile {
        path: "nselib/msrpctypes.lua",
        data: include_bytes!("../../../nselib/msrpctypes.lua"),
    },
    EmbeddedFile {
        path: "nselib/mssql.lua",
        data: include_bytes!("../../../nselib/mssql.lua"),
    },
    EmbeddedFile {
        path: "nselib/multicast.lua",
        data: include_bytes!("../../../nselib/multicast.lua"),
    },
    EmbeddedFile {
        path: "nselib/mysql.lua",
        data: include_bytes!("../../../nselib/mysql.lua"),
    },
    EmbeddedFile {
        path: "nselib/natpmp.lua",
        data: include_bytes!("../../../nselib/natpmp.lua"),
    },
    EmbeddedFile {
        path: "nselib/nbd.lua",
        data: include_bytes!("../../../nselib/nbd.lua"),
    },
    EmbeddedFile {
        path: "nselib/ncp.lua",
        data: include_bytes!("../../../nselib/ncp.lua"),
    },
    EmbeddedFile {
        path: "nselib/ndmp.lua",
        data: include_bytes!("../../../nselib/ndmp.lua"),
    },
    EmbeddedFile {
        path: "nselib/netbios.lua",
        data: include_bytes!("../../../nselib/netbios.lua"),
    },
    EmbeddedFile {
        path: "nselib/nmap.luadoc",
        data: include_bytes!("../../../nselib/nmap.luadoc"),
    },
    EmbeddedFile {
        path: "nselib/nrpc.lua",
        data: include_bytes!("../../../nselib/nrpc.lua"),
    },
    EmbeddedFile {
        path: "nselib/nsedebug.lua",
        data: include_bytes!("../../../nselib/nsedebug.lua"),
    },
    EmbeddedFile {
        path: "nselib/omp2.lua",
        data: include_bytes!("../../../nselib/omp2.lua"),
    },
    EmbeddedFile {
        path: "nselib/oops.lua",
        data: include_bytes!("../../../nselib/oops.lua"),
    },
    EmbeddedFile {
        path: "nselib/openssl.luadoc",
        data: include_bytes!("../../../nselib/openssl.luadoc"),
    },
    EmbeddedFile {
        path: "nselib/ospf.lua",
        data: include_bytes!("../../../nselib/ospf.lua"),
    },
    EmbeddedFile {
        path: "nselib/outlib.lua",
        data: include_bytes!("../../../nselib/outlib.lua"),
    },
    EmbeddedFile {
        path: "nselib/packet.lua",
        data: include_bytes!("../../../nselib/packet.lua"),
    },
    EmbeddedFile {
        path: "nselib/pgsql.lua",
        data: include_bytes!("../../../nselib/pgsql.lua"),
    },
    EmbeddedFile {
        path: "nselib/pop3.lua",
        data: include_bytes!("../../../nselib/pop3.lua"),
    },
    EmbeddedFile {
        path: "nselib/pppoe.lua",
        data: include_bytes!("../../../nselib/pppoe.lua"),
    },
    EmbeddedFile {
        path: "nselib/proxy.lua",
        data: include_bytes!("../../../nselib/proxy.lua"),
    },
    EmbeddedFile {
        path: "nselib/punycode.lua",
        data: include_bytes!("../../../nselib/punycode.lua"),
    },
    EmbeddedFile {
        path: "nselib/rand.lua",
        data: include_bytes!("../../../nselib/rand.lua"),
    },
    EmbeddedFile {
        path: "nselib/rdp.lua",
        data: include_bytes!("../../../nselib/rdp.lua"),
    },
    EmbeddedFile {
        path: "nselib/re.lua",
        data: include_bytes!("../../../nselib/re.lua"),
    },
    EmbeddedFile {
        path: "nselib/redis.lua",
        data: include_bytes!("../../../nselib/redis.lua"),
    },
    EmbeddedFile {
        path: "nselib/rmi.lua",
        data: include_bytes!("../../../nselib/rmi.lua"),
    },
    EmbeddedFile {
        path: "nselib/rpc.lua",
        data: include_bytes!("../../../nselib/rpc.lua"),
    },
    EmbeddedFile {
        path: "nselib/rpcap.lua",
        data: include_bytes!("../../../nselib/rpcap.lua"),
    },
    EmbeddedFile {
        path: "nselib/rsync.lua",
        data: include_bytes!("../../../nselib/rsync.lua"),
    },
    EmbeddedFile {
        path: "nselib/rtsp.lua",
        data: include_bytes!("../../../nselib/rtsp.lua"),
    },
    EmbeddedFile {
        path: "nselib/sasl.lua",
        data: include_bytes!("../../../nselib/sasl.lua"),
    },
    EmbeddedFile {
        path: "nselib/shortport.lua",
        data: include_bytes!("../../../nselib/shortport.lua"),
    },
    EmbeddedFile {
        path: "nselib/sip.lua",
        data: include_bytes!("../../../nselib/sip.lua"),
    },
    EmbeddedFile {
        path: "nselib/slaxml.lua",
        data: include_bytes!("../../../nselib/slaxml.lua"),
    },
    EmbeddedFile {
        path: "nselib/smb.lua",
        data: include_bytes!("../../../nselib/smb.lua"),
    },
    EmbeddedFile {
        path: "nselib/smb2.lua",
        data: include_bytes!("../../../nselib/smb2.lua"),
    },
    EmbeddedFile {
        path: "nselib/smbauth.lua",
        data: include_bytes!("../../../nselib/smbauth.lua"),
    },
    EmbeddedFile {
        path: "nselib/smtp.lua",
        data: include_bytes!("../../../nselib/smtp.lua"),
    },
    EmbeddedFile {
        path: "nselib/snmp.lua",
        data: include_bytes!("../../../nselib/snmp.lua"),
    },
    EmbeddedFile {
        path: "nselib/socks.lua",
        data: include_bytes!("../../../nselib/socks.lua"),
    },
    EmbeddedFile {
        path: "nselib/srvloc.lua",
        data: include_bytes!("../../../nselib/srvloc.lua"),
    },
    EmbeddedFile {
        path: "nselib/ssh1.lua",
        data: include_bytes!("../../../nselib/ssh1.lua"),
    },
    EmbeddedFile {
        path: "nselib/ssh2.lua",
        data: include_bytes!("../../../nselib/ssh2.lua"),
    },
    EmbeddedFile {
        path: "nselib/sslcert.lua",
        data: include_bytes!("../../../nselib/sslcert.lua"),
    },
    EmbeddedFile {
        path: "nselib/sslv2.lua",
        data: include_bytes!("../../../nselib/sslv2.lua"),
    },
    EmbeddedFile {
        path: "nselib/stdnse.lua",
        data: include_bytes!("../../../nselib/stdnse.lua"),
    },
    EmbeddedFile {
        path: "nselib/strbuf.lua",
        data: include_bytes!("../../../nselib/strbuf.lua"),
    },
    EmbeddedFile {
        path: "nselib/strict.lua",
        data: include_bytes!("../../../nselib/strict.lua"),
    },
    EmbeddedFile {
        path: "nselib/stringaux.lua",
        data: include_bytes!("../../../nselib/stringaux.lua"),
    },
    EmbeddedFile {
        path: "nselib/stun.lua",
        data: include_bytes!("../../../nselib/stun.lua"),
    },
    EmbeddedFile {
        path: "nselib/tab.lua",
        data: include_bytes!("../../../nselib/tab.lua"),
    },
    EmbeddedFile {
        path: "nselib/tableaux.lua",
        data: include_bytes!("../../../nselib/tableaux.lua"),
    },
    EmbeddedFile {
        path: "nselib/target.lua",
        data: include_bytes!("../../../nselib/target.lua"),
    },
    EmbeddedFile {
        path: "nselib/tftp.lua",
        data: include_bytes!("../../../nselib/tftp.lua"),
    },
    EmbeddedFile {
        path: "nselib/tls.lua",
        data: include_bytes!("../../../nselib/tls.lua"),
    },
    EmbeddedFile {
        path: "nselib/tn3270.lua",
        data: include_bytes!("../../../nselib/tn3270.lua"),
    },
    EmbeddedFile {
        path: "nselib/tns.lua",
        data: include_bytes!("../../../nselib/tns.lua"),
    },
    EmbeddedFile {
        path: "nselib/unicode.lua",
        data: include_bytes!("../../../nselib/unicode.lua"),
    },
    EmbeddedFile {
        path: "nselib/unittest.lua",
        data: include_bytes!("../../../nselib/unittest.lua"),
    },
    EmbeddedFile {
        path: "nselib/unpwdb.lua",
        data: include_bytes!("../../../nselib/unpwdb.lua"),
    },
    EmbeddedFile {
        path: "nselib/upnp.lua",
        data: include_bytes!("../../../nselib/upnp.lua"),
    },
    EmbeddedFile {
        path: "nselib/url.lua",
        data: include_bytes!("../../../nselib/url.lua"),
    },
    EmbeddedFile {
        path: "nselib/versant.lua",
        data: include_bytes!("../../../nselib/versant.lua"),
    },
    EmbeddedFile {
        path: "nselib/vnc.lua",
        data: include_bytes!("../../../nselib/vnc.lua"),
    },
    EmbeddedFile {
        path: "nselib/vulns.lua",
        data: include_bytes!("../../../nselib/vulns.lua"),
    },
    EmbeddedFile {
        path: "nselib/vuzedht.lua",
        data: include_bytes!("../../../nselib/vuzedht.lua"),
    },
    EmbeddedFile {
        path: "nselib/wsdd.lua",
        data: include_bytes!("../../../nselib/wsdd.lua"),
    },
    EmbeddedFile {
        path: "nselib/xdmcp.lua",
        data: include_bytes!("../../../nselib/xdmcp.lua"),
    },
    EmbeddedFile {
        path: "nselib/xmpp.lua",
        data: include_bytes!("../../../nselib/xmpp.lua"),
    },
    EmbeddedFile {
        path: "nselib/zlib.luadoc",
        data: include_bytes!("../../../nselib/zlib.luadoc"),
    },
    EmbeddedFile {
        path: "nselib/data/dns-srv-names",
        data: include_bytes!("../../../nselib/data/dns-srv-names"),
    },
    EmbeddedFile {
        path: "nselib/data/drupal-modules.lst",
        data: include_bytes!("../../../nselib/data/drupal-modules.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/drupal-themes.lst",
        data: include_bytes!("../../../nselib/data/drupal-themes.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/enterprise_numbers.txt",
        data: include_bytes!("../../../nselib/data/enterprise_numbers.txt"),
    },
    EmbeddedFile {
        path: "nselib/data/favicon-db",
        data: include_bytes!("../../../nselib/data/favicon-db"),
    },
    EmbeddedFile {
        path: "nselib/data/http-default-accounts-fingerprints.lua",
        data: include_bytes!("../../../nselib/data/http-default-accounts-fingerprints.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/http-devframework-fingerprints.lua",
        data: include_bytes!("../../../nselib/data/http-devframework-fingerprints.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/http-fingerprints.lua",
        data: include_bytes!("../../../nselib/data/http-fingerprints.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/http-folders.txt",
        data: include_bytes!("../../../nselib/data/http-folders.txt"),
    },
    EmbeddedFile {
        path: "nselib/data/http-sql-errors.lst",
        data: include_bytes!("../../../nselib/data/http-sql-errors.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/http-web-files-extensions.lst",
        data: include_bytes!("../../../nselib/data/http-web-files-extensions.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/idnaMappings.lua",
        data: include_bytes!("../../../nselib/data/idnaMappings.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/ike-fingerprints.lua",
        data: include_bytes!("../../../nselib/data/ike-fingerprints.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/mgroupnames.db",
        data: include_bytes!("../../../nselib/data/mgroupnames.db"),
    },
    EmbeddedFile {
        path: "nselib/data/mysql-cis.audit",
        data: include_bytes!("../../../nselib/data/mysql-cis.audit"),
    },
    EmbeddedFile {
        path: "nselib/data/oracle-default-accounts.lst",
        data: include_bytes!("../../../nselib/data/oracle-default-accounts.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/oracle-sids",
        data: include_bytes!("../../../nselib/data/oracle-sids"),
    },
    EmbeddedFile {
        path: "nselib/data/packetdecoders.lua",
        data: include_bytes!("../../../nselib/data/packetdecoders.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/passwords.lst",
        data: include_bytes!("../../../nselib/data/passwords.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/pixel.gif",
        data: include_bytes!("../../../nselib/data/pixel.gif"),
    },
    EmbeddedFile {
        path: "nselib/data/publickeydb",
        data: include_bytes!("../../../nselib/data/publickeydb"),
    },
    EmbeddedFile {
        path: "nselib/data/rtsp-urls.txt",
        data: include_bytes!("../../../nselib/data/rtsp-urls.txt"),
    },
    EmbeddedFile {
        path: "nselib/data/snmpcommunities.lst",
        data: include_bytes!("../../../nselib/data/snmpcommunities.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/ssl-fingerprints",
        data: include_bytes!("../../../nselib/data/ssl-fingerprints"),
    },
    EmbeddedFile {
        path: "nselib/data/targets-ipv6-wordlist",
        data: include_bytes!("../../../nselib/data/targets-ipv6-wordlist"),
    },
    EmbeddedFile {
        path: "nselib/data/tftp-fingerprints.lua",
        data: include_bytes!("../../../nselib/data/tftp-fingerprints.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/tftplist.txt",
        data: include_bytes!("../../../nselib/data/tftplist.txt"),
    },
    EmbeddedFile {
        path: "nselib/data/usernames.lst",
        data: include_bytes!("../../../nselib/data/usernames.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/vhosts-default.lst",
        data: include_bytes!("../../../nselib/data/vhosts-default.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/vhosts-full.lst",
        data: include_bytes!("../../../nselib/data/vhosts-full.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/wp-plugins.lst",
        data: include_bytes!("../../../nselib/data/wp-plugins.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/wp-themes.lst",
        data: include_bytes!("../../../nselib/data/wp-themes.lst"),
    },
    EmbeddedFile {
        path: "nselib/data/jdwp-class/JDWPExecCmd.class",
        data: include_bytes!("../../../nselib/data/jdwp-class/JDWPExecCmd.class"),
    },
    EmbeddedFile {
        path: "nselib/data/jdwp-class/JDWPExecCmd.java",
        data: include_bytes!("../../../nselib/data/jdwp-class/JDWPExecCmd.java"),
    },
    EmbeddedFile {
        path: "nselib/data/jdwp-class/JDWPSystemInfo.class",
        data: include_bytes!("../../../nselib/data/jdwp-class/JDWPSystemInfo.class"),
    },
    EmbeddedFile {
        path: "nselib/data/jdwp-class/JDWPSystemInfo.java",
        data: include_bytes!("../../../nselib/data/jdwp-class/JDWPSystemInfo.java"),
    },
    EmbeddedFile {
        path: "nselib/data/jdwp-class/README.txt",
        data: include_bytes!("../../../nselib/data/jdwp-class/README.txt"),
    },
    EmbeddedFile {
        path: "nselib/data/psexec/README",
        data: include_bytes!("../../../nselib/data/psexec/README"),
    },
    EmbeddedFile {
        path: "nselib/data/psexec/backdoor.lua",
        data: include_bytes!("../../../nselib/data/psexec/backdoor.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/psexec/default.lua",
        data: include_bytes!("../../../nselib/data/psexec/default.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/psexec/drives.lua",
        data: include_bytes!("../../../nselib/data/psexec/drives.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/psexec/examples.lua",
        data: include_bytes!("../../../nselib/data/psexec/examples.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/psexec/experimental.lua",
        data: include_bytes!("../../../nselib/data/psexec/experimental.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/psexec/network.lua",
        data: include_bytes!("../../../nselib/data/psexec/network.lua"),
    },
    EmbeddedFile {
        path: "nselib/data/psexec/nmap_service.c",
        data: include_bytes!("../../../nselib/data/psexec/nmap_service.c"),
    },
    EmbeddedFile {
        path: "nselib/data/psexec/nmap_service.vcproj",
        data: include_bytes!("../../../nselib/data/psexec/nmap_service.vcproj"),
    },
    EmbeddedFile {
        path: "nselib/data/psexec/pwdump.lua",
        data: include_bytes!("../../../nselib/data/psexec/pwdump.lua"),
    },
    EmbeddedFile {
        path: "scripts/acarsd-info.nse",
        data: include_bytes!("../../../scripts/acarsd-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/address-info.nse",
        data: include_bytes!("../../../scripts/address-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/afp-brute.nse",
        data: include_bytes!("../../../scripts/afp-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/afp-ls.nse",
        data: include_bytes!("../../../scripts/afp-ls.nse"),
    },
    EmbeddedFile {
        path: "scripts/afp-path-vuln.nse",
        data: include_bytes!("../../../scripts/afp-path-vuln.nse"),
    },
    EmbeddedFile {
        path: "scripts/afp-serverinfo.nse",
        data: include_bytes!("../../../scripts/afp-serverinfo.nse"),
    },
    EmbeddedFile {
        path: "scripts/afp-showmount.nse",
        data: include_bytes!("../../../scripts/afp-showmount.nse"),
    },
    EmbeddedFile {
        path: "scripts/ajp-auth.nse",
        data: include_bytes!("../../../scripts/ajp-auth.nse"),
    },
    EmbeddedFile {
        path: "scripts/ajp-brute.nse",
        data: include_bytes!("../../../scripts/ajp-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/ajp-headers.nse",
        data: include_bytes!("../../../scripts/ajp-headers.nse"),
    },
    EmbeddedFile {
        path: "scripts/ajp-methods.nse",
        data: include_bytes!("../../../scripts/ajp-methods.nse"),
    },
    EmbeddedFile {
        path: "scripts/ajp-request.nse",
        data: include_bytes!("../../../scripts/ajp-request.nse"),
    },
    EmbeddedFile {
        path: "scripts/allseeingeye-info.nse",
        data: include_bytes!("../../../scripts/allseeingeye-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/amqp-info.nse",
        data: include_bytes!("../../../scripts/amqp-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/asn-query.nse",
        data: include_bytes!("../../../scripts/asn-query.nse"),
    },
    EmbeddedFile {
        path: "scripts/auth-owners.nse",
        data: include_bytes!("../../../scripts/auth-owners.nse"),
    },
    EmbeddedFile {
        path: "scripts/auth-spoof.nse",
        data: include_bytes!("../../../scripts/auth-spoof.nse"),
    },
    EmbeddedFile {
        path: "scripts/backorifice-brute.nse",
        data: include_bytes!("../../../scripts/backorifice-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/backorifice-info.nse",
        data: include_bytes!("../../../scripts/backorifice-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/bacnet-info.nse",
        data: include_bytes!("../../../scripts/bacnet-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/banner.nse",
        data: include_bytes!("../../../scripts/banner.nse"),
    },
    EmbeddedFile {
        path: "scripts/bitcoin-getaddr.nse",
        data: include_bytes!("../../../scripts/bitcoin-getaddr.nse"),
    },
    EmbeddedFile {
        path: "scripts/bitcoin-info.nse",
        data: include_bytes!("../../../scripts/bitcoin-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/bitcoinrpc-info.nse",
        data: include_bytes!("../../../scripts/bitcoinrpc-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/bittorrent-discovery.nse",
        data: include_bytes!("../../../scripts/bittorrent-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/bjnp-discover.nse",
        data: include_bytes!("../../../scripts/bjnp-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-ataoe-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-ataoe-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-avahi-dos.nse",
        data: include_bytes!("../../../scripts/broadcast-avahi-dos.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-bjnp-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-bjnp-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-db2-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-db2-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-dhcp-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-dhcp-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-dhcp6-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-dhcp6-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-dns-service-discovery.nse",
        data: include_bytes!("../../../scripts/broadcast-dns-service-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-dropbox-listener.nse",
        data: include_bytes!("../../../scripts/broadcast-dropbox-listener.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-eigrp-discovery.nse",
        data: include_bytes!("../../../scripts/broadcast-eigrp-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-hid-discoveryd.nse",
        data: include_bytes!("../../../scripts/broadcast-hid-discoveryd.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-igmp-discovery.nse",
        data: include_bytes!("../../../scripts/broadcast-igmp-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-jenkins-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-jenkins-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-listener.nse",
        data: include_bytes!("../../../scripts/broadcast-listener.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-ms-sql-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-ms-sql-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-netbios-master-browser.nse",
        data: include_bytes!("../../../scripts/broadcast-netbios-master-browser.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-networker-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-networker-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-novell-locate.nse",
        data: include_bytes!("../../../scripts/broadcast-novell-locate.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-ospf2-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-ospf2-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-pc-anywhere.nse",
        data: include_bytes!("../../../scripts/broadcast-pc-anywhere.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-pc-duo.nse",
        data: include_bytes!("../../../scripts/broadcast-pc-duo.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-pim-discovery.nse",
        data: include_bytes!("../../../scripts/broadcast-pim-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-ping.nse",
        data: include_bytes!("../../../scripts/broadcast-ping.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-pppoe-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-pppoe-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-rip-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-rip-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-ripng-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-ripng-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-sonicwall-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-sonicwall-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-sybase-asa-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-sybase-asa-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-tellstick-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-tellstick-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-upnp-info.nse",
        data: include_bytes!("../../../scripts/broadcast-upnp-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-versant-locate.nse",
        data: include_bytes!("../../../scripts/broadcast-versant-locate.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-wake-on-lan.nse",
        data: include_bytes!("../../../scripts/broadcast-wake-on-lan.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-wpad-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-wpad-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-wsdd-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-wsdd-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/broadcast-xdmcp-discover.nse",
        data: include_bytes!("../../../scripts/broadcast-xdmcp-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/cassandra-brute.nse",
        data: include_bytes!("../../../scripts/cassandra-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/cassandra-info.nse",
        data: include_bytes!("../../../scripts/cassandra-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/cccam-version.nse",
        data: include_bytes!("../../../scripts/cccam-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/cics-enum.nse",
        data: include_bytes!("../../../scripts/cics-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/cics-info.nse",
        data: include_bytes!("../../../scripts/cics-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/cics-user-brute.nse",
        data: include_bytes!("../../../scripts/cics-user-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/cics-user-enum.nse",
        data: include_bytes!("../../../scripts/cics-user-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/citrix-brute-xml.nse",
        data: include_bytes!("../../../scripts/citrix-brute-xml.nse"),
    },
    EmbeddedFile {
        path: "scripts/citrix-enum-apps-xml.nse",
        data: include_bytes!("../../../scripts/citrix-enum-apps-xml.nse"),
    },
    EmbeddedFile {
        path: "scripts/citrix-enum-apps.nse",
        data: include_bytes!("../../../scripts/citrix-enum-apps.nse"),
    },
    EmbeddedFile {
        path: "scripts/citrix-enum-servers-xml.nse",
        data: include_bytes!("../../../scripts/citrix-enum-servers-xml.nse"),
    },
    EmbeddedFile {
        path: "scripts/citrix-enum-servers.nse",
        data: include_bytes!("../../../scripts/citrix-enum-servers.nse"),
    },
    EmbeddedFile {
        path: "scripts/clamav-exec.nse",
        data: include_bytes!("../../../scripts/clamav-exec.nse"),
    },
    EmbeddedFile {
        path: "scripts/clock-skew.nse",
        data: include_bytes!("../../../scripts/clock-skew.nse"),
    },
    EmbeddedFile {
        path: "scripts/coap-resources.nse",
        data: include_bytes!("../../../scripts/coap-resources.nse"),
    },
    EmbeddedFile {
        path: "scripts/couchdb-databases.nse",
        data: include_bytes!("../../../scripts/couchdb-databases.nse"),
    },
    EmbeddedFile {
        path: "scripts/couchdb-stats.nse",
        data: include_bytes!("../../../scripts/couchdb-stats.nse"),
    },
    EmbeddedFile {
        path: "scripts/creds-summary.nse",
        data: include_bytes!("../../../scripts/creds-summary.nse"),
    },
    EmbeddedFile {
        path: "scripts/cups-info.nse",
        data: include_bytes!("../../../scripts/cups-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/cups-queue-info.nse",
        data: include_bytes!("../../../scripts/cups-queue-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/cvs-brute-repository.nse",
        data: include_bytes!("../../../scripts/cvs-brute-repository.nse"),
    },
    EmbeddedFile {
        path: "scripts/cvs-brute.nse",
        data: include_bytes!("../../../scripts/cvs-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/daap-get-library.nse",
        data: include_bytes!("../../../scripts/daap-get-library.nse"),
    },
    EmbeddedFile {
        path: "scripts/daytime.nse",
        data: include_bytes!("../../../scripts/daytime.nse"),
    },
    EmbeddedFile {
        path: "scripts/db2-das-info.nse",
        data: include_bytes!("../../../scripts/db2-das-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/deluge-rpc-brute.nse",
        data: include_bytes!("../../../scripts/deluge-rpc-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/dhcp-discover.nse",
        data: include_bytes!("../../../scripts/dhcp-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/dicom-brute.nse",
        data: include_bytes!("../../../scripts/dicom-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/dicom-ping.nse",
        data: include_bytes!("../../../scripts/dicom-ping.nse"),
    },
    EmbeddedFile {
        path: "scripts/dict-info.nse",
        data: include_bytes!("../../../scripts/dict-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/distcc-cve2004-2687.nse",
        data: include_bytes!("../../../scripts/distcc-cve2004-2687.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-blacklist.nse",
        data: include_bytes!("../../../scripts/dns-blacklist.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-brute.nse",
        data: include_bytes!("../../../scripts/dns-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-cache-snoop.nse",
        data: include_bytes!("../../../scripts/dns-cache-snoop.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-check-zone.nse",
        data: include_bytes!("../../../scripts/dns-check-zone.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-client-subnet-scan.nse",
        data: include_bytes!("../../../scripts/dns-client-subnet-scan.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-fuzz.nse",
        data: include_bytes!("../../../scripts/dns-fuzz.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-ip6-arpa-scan.nse",
        data: include_bytes!("../../../scripts/dns-ip6-arpa-scan.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-nsec-enum.nse",
        data: include_bytes!("../../../scripts/dns-nsec-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-nsec3-enum.nse",
        data: include_bytes!("../../../scripts/dns-nsec3-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-nsid.nse",
        data: include_bytes!("../../../scripts/dns-nsid.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-random-srcport.nse",
        data: include_bytes!("../../../scripts/dns-random-srcport.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-random-txid.nse",
        data: include_bytes!("../../../scripts/dns-random-txid.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-recursion.nse",
        data: include_bytes!("../../../scripts/dns-recursion.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-service-discovery.nse",
        data: include_bytes!("../../../scripts/dns-service-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-srv-enum.nse",
        data: include_bytes!("../../../scripts/dns-srv-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-update.nse",
        data: include_bytes!("../../../scripts/dns-update.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-zeustracker.nse",
        data: include_bytes!("../../../scripts/dns-zeustracker.nse"),
    },
    EmbeddedFile {
        path: "scripts/dns-zone-transfer.nse",
        data: include_bytes!("../../../scripts/dns-zone-transfer.nse"),
    },
    EmbeddedFile {
        path: "scripts/docker-version.nse",
        data: include_bytes!("../../../scripts/docker-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/domcon-brute.nse",
        data: include_bytes!("../../../scripts/domcon-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/domcon-cmd.nse",
        data: include_bytes!("../../../scripts/domcon-cmd.nse"),
    },
    EmbeddedFile {
        path: "scripts/domino-enum-users.nse",
        data: include_bytes!("../../../scripts/domino-enum-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/dpap-brute.nse",
        data: include_bytes!("../../../scripts/dpap-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/drda-brute.nse",
        data: include_bytes!("../../../scripts/drda-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/drda-info.nse",
        data: include_bytes!("../../../scripts/drda-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/duplicates.nse",
        data: include_bytes!("../../../scripts/duplicates.nse"),
    },
    EmbeddedFile {
        path: "scripts/eap-info.nse",
        data: include_bytes!("../../../scripts/eap-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/enip-info.nse",
        data: include_bytes!("../../../scripts/enip-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/epmd-info.nse",
        data: include_bytes!("../../../scripts/epmd-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/eppc-enum-processes.nse",
        data: include_bytes!("../../../scripts/eppc-enum-processes.nse"),
    },
    EmbeddedFile {
        path: "scripts/fcrdns.nse",
        data: include_bytes!("../../../scripts/fcrdns.nse"),
    },
    EmbeddedFile {
        path: "scripts/finger.nse",
        data: include_bytes!("../../../scripts/finger.nse"),
    },
    EmbeddedFile {
        path: "scripts/fingerprint-strings.nse",
        data: include_bytes!("../../../scripts/fingerprint-strings.nse"),
    },
    EmbeddedFile {
        path: "scripts/firewalk.nse",
        data: include_bytes!("../../../scripts/firewalk.nse"),
    },
    EmbeddedFile {
        path: "scripts/firewall-bypass.nse",
        data: include_bytes!("../../../scripts/firewall-bypass.nse"),
    },
    EmbeddedFile {
        path: "scripts/flume-master-info.nse",
        data: include_bytes!("../../../scripts/flume-master-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/fox-info.nse",
        data: include_bytes!("../../../scripts/fox-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/freelancer-info.nse",
        data: include_bytes!("../../../scripts/freelancer-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/ftp-anon.nse",
        data: include_bytes!("../../../scripts/ftp-anon.nse"),
    },
    EmbeddedFile {
        path: "scripts/ftp-bounce.nse",
        data: include_bytes!("../../../scripts/ftp-bounce.nse"),
    },
    EmbeddedFile {
        path: "scripts/ftp-brute.nse",
        data: include_bytes!("../../../scripts/ftp-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/ftp-libopie.nse",
        data: include_bytes!("../../../scripts/ftp-libopie.nse"),
    },
    EmbeddedFile {
        path: "scripts/ftp-proftpd-backdoor.nse",
        data: include_bytes!("../../../scripts/ftp-proftpd-backdoor.nse"),
    },
    EmbeddedFile {
        path: "scripts/ftp-syst.nse",
        data: include_bytes!("../../../scripts/ftp-syst.nse"),
    },
    EmbeddedFile {
        path: "scripts/ftp-vsftpd-backdoor.nse",
        data: include_bytes!("../../../scripts/ftp-vsftpd-backdoor.nse"),
    },
    EmbeddedFile {
        path: "scripts/ftp-vuln-cve2010-4221.nse",
        data: include_bytes!("../../../scripts/ftp-vuln-cve2010-4221.nse"),
    },
    EmbeddedFile {
        path: "scripts/ganglia-info.nse",
        data: include_bytes!("../../../scripts/ganglia-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/giop-info.nse",
        data: include_bytes!("../../../scripts/giop-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/gkrellm-info.nse",
        data: include_bytes!("../../../scripts/gkrellm-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/gopher-ls.nse",
        data: include_bytes!("../../../scripts/gopher-ls.nse"),
    },
    EmbeddedFile {
        path: "scripts/gpsd-info.nse",
        data: include_bytes!("../../../scripts/gpsd-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hadoop-datanode-info.nse",
        data: include_bytes!("../../../scripts/hadoop-datanode-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hadoop-jobtracker-info.nse",
        data: include_bytes!("../../../scripts/hadoop-jobtracker-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hadoop-namenode-info.nse",
        data: include_bytes!("../../../scripts/hadoop-namenode-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hadoop-secondary-namenode-info.nse",
        data: include_bytes!("../../../scripts/hadoop-secondary-namenode-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hadoop-tasktracker-info.nse",
        data: include_bytes!("../../../scripts/hadoop-tasktracker-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hartip-info.nse",
        data: include_bytes!("../../../scripts/hartip-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hbase-master-info.nse",
        data: include_bytes!("../../../scripts/hbase-master-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hbase-region-info.nse",
        data: include_bytes!("../../../scripts/hbase-region-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hddtemp-info.nse",
        data: include_bytes!("../../../scripts/hddtemp-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hnap-info.nse",
        data: include_bytes!("../../../scripts/hnap-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/hostmap-bfk.nse",
        data: include_bytes!("../../../scripts/hostmap-bfk.nse"),
    },
    EmbeddedFile {
        path: "scripts/hostmap-crtsh.nse",
        data: include_bytes!("../../../scripts/hostmap-crtsh.nse"),
    },
    EmbeddedFile {
        path: "scripts/hostmap-robtex.nse",
        data: include_bytes!("../../../scripts/hostmap-robtex.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-adobe-coldfusion-apsa1301.nse",
        data: include_bytes!("../../../scripts/http-adobe-coldfusion-apsa1301.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-affiliate-id.nse",
        data: include_bytes!("../../../scripts/http-affiliate-id.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-apache-negotiation.nse",
        data: include_bytes!("../../../scripts/http-apache-negotiation.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-apache-server-status.nse",
        data: include_bytes!("../../../scripts/http-apache-server-status.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-aspnet-debug.nse",
        data: include_bytes!("../../../scripts/http-aspnet-debug.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-auth-finder.nse",
        data: include_bytes!("../../../scripts/http-auth-finder.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-auth.nse",
        data: include_bytes!("../../../scripts/http-auth.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-avaya-ipoffice-users.nse",
        data: include_bytes!("../../../scripts/http-avaya-ipoffice-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-awstatstotals-exec.nse",
        data: include_bytes!("../../../scripts/http-awstatstotals-exec.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-axis2-dir-traversal.nse",
        data: include_bytes!("../../../scripts/http-axis2-dir-traversal.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-backup-finder.nse",
        data: include_bytes!("../../../scripts/http-backup-finder.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-barracuda-dir-traversal.nse",
        data: include_bytes!("../../../scripts/http-barracuda-dir-traversal.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-bigip-cookie.nse",
        data: include_bytes!("../../../scripts/http-bigip-cookie.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-brute.nse",
        data: include_bytes!("../../../scripts/http-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-cakephp-version.nse",
        data: include_bytes!("../../../scripts/http-cakephp-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-chrono.nse",
        data: include_bytes!("../../../scripts/http-chrono.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-cisco-anyconnect.nse",
        data: include_bytes!("../../../scripts/http-cisco-anyconnect.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-coldfusion-subzero.nse",
        data: include_bytes!("../../../scripts/http-coldfusion-subzero.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-comments-displayer.nse",
        data: include_bytes!("../../../scripts/http-comments-displayer.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-config-backup.nse",
        data: include_bytes!("../../../scripts/http-config-backup.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-cookie-flags.nse",
        data: include_bytes!("../../../scripts/http-cookie-flags.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-cors.nse",
        data: include_bytes!("../../../scripts/http-cors.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-cross-domain-policy.nse",
        data: include_bytes!("../../../scripts/http-cross-domain-policy.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-csrf.nse",
        data: include_bytes!("../../../scripts/http-csrf.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-date.nse",
        data: include_bytes!("../../../scripts/http-date.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-default-accounts.nse",
        data: include_bytes!("../../../scripts/http-default-accounts.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-devframework.nse",
        data: include_bytes!("../../../scripts/http-devframework.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-dlink-backdoor.nse",
        data: include_bytes!("../../../scripts/http-dlink-backdoor.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-dombased-xss.nse",
        data: include_bytes!("../../../scripts/http-dombased-xss.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-domino-enum-passwords.nse",
        data: include_bytes!("../../../scripts/http-domino-enum-passwords.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-drupal-enum-users.nse",
        data: include_bytes!("../../../scripts/http-drupal-enum-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-drupal-enum.nse",
        data: include_bytes!("../../../scripts/http-drupal-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-enum.nse",
        data: include_bytes!("../../../scripts/http-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-errors.nse",
        data: include_bytes!("../../../scripts/http-errors.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-exif-spider.nse",
        data: include_bytes!("../../../scripts/http-exif-spider.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-favicon.nse",
        data: include_bytes!("../../../scripts/http-favicon.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-feed.nse",
        data: include_bytes!("../../../scripts/http-feed.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-fetch.nse",
        data: include_bytes!("../../../scripts/http-fetch.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-fileupload-exploiter.nse",
        data: include_bytes!("../../../scripts/http-fileupload-exploiter.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-form-brute.nse",
        data: include_bytes!("../../../scripts/http-form-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-form-fuzzer.nse",
        data: include_bytes!("../../../scripts/http-form-fuzzer.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-frontpage-login.nse",
        data: include_bytes!("../../../scripts/http-frontpage-login.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-generator.nse",
        data: include_bytes!("../../../scripts/http-generator.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-git.nse",
        data: include_bytes!("../../../scripts/http-git.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-gitweb-projects-enum.nse",
        data: include_bytes!("../../../scripts/http-gitweb-projects-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-google-malware.nse",
        data: include_bytes!("../../../scripts/http-google-malware.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-grep.nse",
        data: include_bytes!("../../../scripts/http-grep.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-headers.nse",
        data: include_bytes!("../../../scripts/http-headers.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-hp-ilo-info.nse",
        data: include_bytes!("../../../scripts/http-hp-ilo-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-huawei-hg5xx-vuln.nse",
        data: include_bytes!("../../../scripts/http-huawei-hg5xx-vuln.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-icloud-findmyiphone.nse",
        data: include_bytes!("../../../scripts/http-icloud-findmyiphone.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-icloud-sendmsg.nse",
        data: include_bytes!("../../../scripts/http-icloud-sendmsg.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-iis-short-name-brute.nse",
        data: include_bytes!("../../../scripts/http-iis-short-name-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-iis-webdav-vuln.nse",
        data: include_bytes!("../../../scripts/http-iis-webdav-vuln.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-internal-ip-disclosure.nse",
        data: include_bytes!("../../../scripts/http-internal-ip-disclosure.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-joomla-brute.nse",
        data: include_bytes!("../../../scripts/http-joomla-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-jsonp-detection.nse",
        data: include_bytes!("../../../scripts/http-jsonp-detection.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-litespeed-sourcecode-download.nse",
        data: include_bytes!("../../../scripts/http-litespeed-sourcecode-download.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-ls.nse",
        data: include_bytes!("../../../scripts/http-ls.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-majordomo2-dir-traversal.nse",
        data: include_bytes!("../../../scripts/http-majordomo2-dir-traversal.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-malware-host.nse",
        data: include_bytes!("../../../scripts/http-malware-host.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-mcmp.nse",
        data: include_bytes!("../../../scripts/http-mcmp.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-method-tamper.nse",
        data: include_bytes!("../../../scripts/http-method-tamper.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-methods.nse",
        data: include_bytes!("../../../scripts/http-methods.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-mobileversion-checker.nse",
        data: include_bytes!("../../../scripts/http-mobileversion-checker.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-ntlm-info.nse",
        data: include_bytes!("../../../scripts/http-ntlm-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-open-proxy.nse",
        data: include_bytes!("../../../scripts/http-open-proxy.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-open-redirect.nse",
        data: include_bytes!("../../../scripts/http-open-redirect.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-passwd.nse",
        data: include_bytes!("../../../scripts/http-passwd.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-php-version.nse",
        data: include_bytes!("../../../scripts/http-php-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-phpmyadmin-dir-traversal.nse",
        data: include_bytes!("../../../scripts/http-phpmyadmin-dir-traversal.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-phpself-xss.nse",
        data: include_bytes!("../../../scripts/http-phpself-xss.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-proxy-brute.nse",
        data: include_bytes!("../../../scripts/http-proxy-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-put.nse",
        data: include_bytes!("../../../scripts/http-put.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-qnap-nas-info.nse",
        data: include_bytes!("../../../scripts/http-qnap-nas-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-referer-checker.nse",
        data: include_bytes!("../../../scripts/http-referer-checker.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-rfi-spider.nse",
        data: include_bytes!("../../../scripts/http-rfi-spider.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-robots.txt.nse",
        data: include_bytes!("../../../scripts/http-robots.txt.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-robtex-reverse-ip.nse",
        data: include_bytes!("../../../scripts/http-robtex-reverse-ip.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-robtex-shared-ns.nse",
        data: include_bytes!("../../../scripts/http-robtex-shared-ns.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-sap-netweaver-leak.nse",
        data: include_bytes!("../../../scripts/http-sap-netweaver-leak.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-security-headers.nse",
        data: include_bytes!("../../../scripts/http-security-headers.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-server-header.nse",
        data: include_bytes!("../../../scripts/http-server-header.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-shellshock.nse",
        data: include_bytes!("../../../scripts/http-shellshock.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-sitemap-generator.nse",
        data: include_bytes!("../../../scripts/http-sitemap-generator.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-slowloris-check.nse",
        data: include_bytes!("../../../scripts/http-slowloris-check.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-slowloris.nse",
        data: include_bytes!("../../../scripts/http-slowloris.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-sql-injection.nse",
        data: include_bytes!("../../../scripts/http-sql-injection.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-stored-xss.nse",
        data: include_bytes!("../../../scripts/http-stored-xss.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-svn-enum.nse",
        data: include_bytes!("../../../scripts/http-svn-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-svn-info.nse",
        data: include_bytes!("../../../scripts/http-svn-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-title.nse",
        data: include_bytes!("../../../scripts/http-title.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-tplink-dir-traversal.nse",
        data: include_bytes!("../../../scripts/http-tplink-dir-traversal.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-trace.nse",
        data: include_bytes!("../../../scripts/http-trace.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-traceroute.nse",
        data: include_bytes!("../../../scripts/http-traceroute.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-trane-info.nse",
        data: include_bytes!("../../../scripts/http-trane-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-unsafe-output-escaping.nse",
        data: include_bytes!("../../../scripts/http-unsafe-output-escaping.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-useragent-tester.nse",
        data: include_bytes!("../../../scripts/http-useragent-tester.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-userdir-enum.nse",
        data: include_bytes!("../../../scripts/http-userdir-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vhosts.nse",
        data: include_bytes!("../../../scripts/http-vhosts.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-virustotal.nse",
        data: include_bytes!("../../../scripts/http-virustotal.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vlcstreamer-ls.nse",
        data: include_bytes!("../../../scripts/http-vlcstreamer-ls.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vmware-path-vuln.nse",
        data: include_bytes!("../../../scripts/http-vmware-path-vuln.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2006-3392.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2006-3392.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2009-3960.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2009-3960.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2010-0738.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2010-0738.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2010-2861.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2010-2861.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2011-3192.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2011-3192.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2011-3368.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2011-3368.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2012-1823.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2012-1823.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2013-0156.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2013-0156.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2013-6786.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2013-6786.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2013-7091.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2013-7091.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2014-2126.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2014-2126.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2014-2127.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2014-2127.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2014-2128.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2014-2128.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2014-2129.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2014-2129.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2014-3704.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2014-3704.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2014-8877.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2014-8877.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2015-1427.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2015-1427.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2015-1635.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2015-1635.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2017-1001000.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2017-1001000.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2017-5638.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2017-5638.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2017-5689.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2017-5689.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-cve2017-8917.nse",
        data: include_bytes!("../../../scripts/http-vuln-cve2017-8917.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-misfortune-cookie.nse",
        data: include_bytes!("../../../scripts/http-vuln-misfortune-cookie.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-vuln-wnr1000-creds.nse",
        data: include_bytes!("../../../scripts/http-vuln-wnr1000-creds.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-waf-detect.nse",
        data: include_bytes!("../../../scripts/http-waf-detect.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-waf-fingerprint.nse",
        data: include_bytes!("../../../scripts/http-waf-fingerprint.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-webdav-scan.nse",
        data: include_bytes!("../../../scripts/http-webdav-scan.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-wordpress-brute.nse",
        data: include_bytes!("../../../scripts/http-wordpress-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-wordpress-enum.nse",
        data: include_bytes!("../../../scripts/http-wordpress-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-wordpress-users.nse",
        data: include_bytes!("../../../scripts/http-wordpress-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/http-xssed.nse",
        data: include_bytes!("../../../scripts/http-xssed.nse"),
    },
    EmbeddedFile {
        path: "scripts/https-redirect.nse",
        data: include_bytes!("../../../scripts/https-redirect.nse"),
    },
    EmbeddedFile {
        path: "scripts/iax2-brute.nse",
        data: include_bytes!("../../../scripts/iax2-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/iax2-version.nse",
        data: include_bytes!("../../../scripts/iax2-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/icap-info.nse",
        data: include_bytes!("../../../scripts/icap-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/iec-identify.nse",
        data: include_bytes!("../../../scripts/iec-identify.nse"),
    },
    EmbeddedFile {
        path: "scripts/iec61850-mms.nse",
        data: include_bytes!("../../../scripts/iec61850-mms.nse"),
    },
    EmbeddedFile {
        path: "scripts/ike-version.nse",
        data: include_bytes!("../../../scripts/ike-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/imap-brute.nse",
        data: include_bytes!("../../../scripts/imap-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/imap-capabilities.nse",
        data: include_bytes!("../../../scripts/imap-capabilities.nse"),
    },
    EmbeddedFile {
        path: "scripts/imap-ntlm-info.nse",
        data: include_bytes!("../../../scripts/imap-ntlm-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/impress-remote-discover.nse",
        data: include_bytes!("../../../scripts/impress-remote-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/informix-brute.nse",
        data: include_bytes!("../../../scripts/informix-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/informix-query.nse",
        data: include_bytes!("../../../scripts/informix-query.nse"),
    },
    EmbeddedFile {
        path: "scripts/informix-tables.nse",
        data: include_bytes!("../../../scripts/informix-tables.nse"),
    },
    EmbeddedFile {
        path: "scripts/ip-forwarding.nse",
        data: include_bytes!("../../../scripts/ip-forwarding.nse"),
    },
    EmbeddedFile {
        path: "scripts/ip-geolocation-geoplugin.nse",
        data: include_bytes!("../../../scripts/ip-geolocation-geoplugin.nse"),
    },
    EmbeddedFile {
        path: "scripts/ip-geolocation-ipinfodb.nse",
        data: include_bytes!("../../../scripts/ip-geolocation-ipinfodb.nse"),
    },
    EmbeddedFile {
        path: "scripts/ip-geolocation-map-bing.nse",
        data: include_bytes!("../../../scripts/ip-geolocation-map-bing.nse"),
    },
    EmbeddedFile {
        path: "scripts/ip-geolocation-map-google.nse",
        data: include_bytes!("../../../scripts/ip-geolocation-map-google.nse"),
    },
    EmbeddedFile {
        path: "scripts/ip-geolocation-map-kml.nse",
        data: include_bytes!("../../../scripts/ip-geolocation-map-kml.nse"),
    },
    EmbeddedFile {
        path: "scripts/ip-geolocation-maxmind.nse",
        data: include_bytes!("../../../scripts/ip-geolocation-maxmind.nse"),
    },
    EmbeddedFile {
        path: "scripts/ip-https-discover.nse",
        data: include_bytes!("../../../scripts/ip-https-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/ipidseq.nse",
        data: include_bytes!("../../../scripts/ipidseq.nse"),
    },
    EmbeddedFile {
        path: "scripts/ipmi-brute.nse",
        data: include_bytes!("../../../scripts/ipmi-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/ipmi-cipher-zero.nse",
        data: include_bytes!("../../../scripts/ipmi-cipher-zero.nse"),
    },
    EmbeddedFile {
        path: "scripts/ipmi-version.nse",
        data: include_bytes!("../../../scripts/ipmi-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/ipv6-multicast-mld-list.nse",
        data: include_bytes!("../../../scripts/ipv6-multicast-mld-list.nse"),
    },
    EmbeddedFile {
        path: "scripts/ipv6-node-info.nse",
        data: include_bytes!("../../../scripts/ipv6-node-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/ipv6-ra-flood.nse",
        data: include_bytes!("../../../scripts/ipv6-ra-flood.nse"),
    },
    EmbeddedFile {
        path: "scripts/irc-botnet-channels.nse",
        data: include_bytes!("../../../scripts/irc-botnet-channels.nse"),
    },
    EmbeddedFile {
        path: "scripts/irc-brute.nse",
        data: include_bytes!("../../../scripts/irc-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/irc-info.nse",
        data: include_bytes!("../../../scripts/irc-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/irc-sasl-brute.nse",
        data: include_bytes!("../../../scripts/irc-sasl-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/irc-unrealircd-backdoor.nse",
        data: include_bytes!("../../../scripts/irc-unrealircd-backdoor.nse"),
    },
    EmbeddedFile {
        path: "scripts/iscsi-brute.nse",
        data: include_bytes!("../../../scripts/iscsi-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/iscsi-info.nse",
        data: include_bytes!("../../../scripts/iscsi-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/isns-info.nse",
        data: include_bytes!("../../../scripts/isns-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/jdwp-exec.nse",
        data: include_bytes!("../../../scripts/jdwp-exec.nse"),
    },
    EmbeddedFile {
        path: "scripts/jdwp-info.nse",
        data: include_bytes!("../../../scripts/jdwp-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/jdwp-inject.nse",
        data: include_bytes!("../../../scripts/jdwp-inject.nse"),
    },
    EmbeddedFile {
        path: "scripts/jdwp-version.nse",
        data: include_bytes!("../../../scripts/jdwp-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/knx-gateway-discover.nse",
        data: include_bytes!("../../../scripts/knx-gateway-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/knx-gateway-info.nse",
        data: include_bytes!("../../../scripts/knx-gateway-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/krb5-enum-users.nse",
        data: include_bytes!("../../../scripts/krb5-enum-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/ldap-brute.nse",
        data: include_bytes!("../../../scripts/ldap-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/ldap-novell-getpass.nse",
        data: include_bytes!("../../../scripts/ldap-novell-getpass.nse"),
    },
    EmbeddedFile {
        path: "scripts/ldap-rootdse.nse",
        data: include_bytes!("../../../scripts/ldap-rootdse.nse"),
    },
    EmbeddedFile {
        path: "scripts/ldap-search.nse",
        data: include_bytes!("../../../scripts/ldap-search.nse"),
    },
    EmbeddedFile {
        path: "scripts/lexmark-config.nse",
        data: include_bytes!("../../../scripts/lexmark-config.nse"),
    },
    EmbeddedFile {
        path: "scripts/llmnr-resolve.nse",
        data: include_bytes!("../../../scripts/llmnr-resolve.nse"),
    },
    EmbeddedFile {
        path: "scripts/lltd-discovery.nse",
        data: include_bytes!("../../../scripts/lltd-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/lu-enum.nse",
        data: include_bytes!("../../../scripts/lu-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/maxdb-info.nse",
        data: include_bytes!("../../../scripts/maxdb-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/mcafee-epo-agent.nse",
        data: include_bytes!("../../../scripts/mcafee-epo-agent.nse"),
    },
    EmbeddedFile {
        path: "scripts/membase-brute.nse",
        data: include_bytes!("../../../scripts/membase-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/membase-http-info.nse",
        data: include_bytes!("../../../scripts/membase-http-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/memcached-info.nse",
        data: include_bytes!("../../../scripts/memcached-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/metasploit-info.nse",
        data: include_bytes!("../../../scripts/metasploit-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/metasploit-msgrpc-brute.nse",
        data: include_bytes!("../../../scripts/metasploit-msgrpc-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/metasploit-xmlrpc-brute.nse",
        data: include_bytes!("../../../scripts/metasploit-xmlrpc-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/mikrotik-routeros-brute.nse",
        data: include_bytes!("../../../scripts/mikrotik-routeros-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/mikrotik-routeros-username-brute.nse",
        data: include_bytes!("../../../scripts/mikrotik-routeros-username-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/mikrotik-routeros-version.nse",
        data: include_bytes!("../../../scripts/mikrotik-routeros-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/mmouse-brute.nse",
        data: include_bytes!("../../../scripts/mmouse-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/mmouse-exec.nse",
        data: include_bytes!("../../../scripts/mmouse-exec.nse"),
    },
    EmbeddedFile {
        path: "scripts/modbus-discover.nse",
        data: include_bytes!("../../../scripts/modbus-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/mongodb-brute.nse",
        data: include_bytes!("../../../scripts/mongodb-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/mongodb-databases.nse",
        data: include_bytes!("../../../scripts/mongodb-databases.nse"),
    },
    EmbeddedFile {
        path: "scripts/mongodb-info.nse",
        data: include_bytes!("../../../scripts/mongodb-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/mqtt-subscribe.nse",
        data: include_bytes!("../../../scripts/mqtt-subscribe.nse"),
    },
    EmbeddedFile {
        path: "scripts/mrinfo.nse",
        data: include_bytes!("../../../scripts/mrinfo.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-brute.nse",
        data: include_bytes!("../../../scripts/ms-sql-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-config.nse",
        data: include_bytes!("../../../scripts/ms-sql-config.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-dac.nse",
        data: include_bytes!("../../../scripts/ms-sql-dac.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-dump-hashes.nse",
        data: include_bytes!("../../../scripts/ms-sql-dump-hashes.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-empty-password.nse",
        data: include_bytes!("../../../scripts/ms-sql-empty-password.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-hasdbaccess.nse",
        data: include_bytes!("../../../scripts/ms-sql-hasdbaccess.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-info.nse",
        data: include_bytes!("../../../scripts/ms-sql-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-ntlm-info.nse",
        data: include_bytes!("../../../scripts/ms-sql-ntlm-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-query.nse",
        data: include_bytes!("../../../scripts/ms-sql-query.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-tables.nse",
        data: include_bytes!("../../../scripts/ms-sql-tables.nse"),
    },
    EmbeddedFile {
        path: "scripts/ms-sql-xp-cmdshell.nse",
        data: include_bytes!("../../../scripts/ms-sql-xp-cmdshell.nse"),
    },
    EmbeddedFile {
        path: "scripts/msrpc-enum.nse",
        data: include_bytes!("../../../scripts/msrpc-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/mtrace.nse",
        data: include_bytes!("../../../scripts/mtrace.nse"),
    },
    EmbeddedFile {
        path: "scripts/multicast-profinet-discovery.nse",
        data: include_bytes!("../../../scripts/multicast-profinet-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/murmur-version.nse",
        data: include_bytes!("../../../scripts/murmur-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-audit.nse",
        data: include_bytes!("../../../scripts/mysql-audit.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-brute.nse",
        data: include_bytes!("../../../scripts/mysql-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-databases.nse",
        data: include_bytes!("../../../scripts/mysql-databases.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-dump-hashes.nse",
        data: include_bytes!("../../../scripts/mysql-dump-hashes.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-empty-password.nse",
        data: include_bytes!("../../../scripts/mysql-empty-password.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-enum.nse",
        data: include_bytes!("../../../scripts/mysql-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-info.nse",
        data: include_bytes!("../../../scripts/mysql-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-query.nse",
        data: include_bytes!("../../../scripts/mysql-query.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-users.nse",
        data: include_bytes!("../../../scripts/mysql-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-variables.nse",
        data: include_bytes!("../../../scripts/mysql-variables.nse"),
    },
    EmbeddedFile {
        path: "scripts/mysql-vuln-cve2012-2122.nse",
        data: include_bytes!("../../../scripts/mysql-vuln-cve2012-2122.nse"),
    },
    EmbeddedFile {
        path: "scripts/nat-pmp-info.nse",
        data: include_bytes!("../../../scripts/nat-pmp-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/nat-pmp-mapport.nse",
        data: include_bytes!("../../../scripts/nat-pmp-mapport.nse"),
    },
    EmbeddedFile {
        path: "scripts/nbd-info.nse",
        data: include_bytes!("../../../scripts/nbd-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/nbns-interfaces.nse",
        data: include_bytes!("../../../scripts/nbns-interfaces.nse"),
    },
    EmbeddedFile {
        path: "scripts/nbstat.nse",
        data: include_bytes!("../../../scripts/nbstat.nse"),
    },
    EmbeddedFile {
        path: "scripts/ncp-enum-users.nse",
        data: include_bytes!("../../../scripts/ncp-enum-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/ncp-serverinfo.nse",
        data: include_bytes!("../../../scripts/ncp-serverinfo.nse"),
    },
    EmbeddedFile {
        path: "scripts/ndmp-fs-info.nse",
        data: include_bytes!("../../../scripts/ndmp-fs-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/ndmp-version.nse",
        data: include_bytes!("../../../scripts/ndmp-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/nessus-brute.nse",
        data: include_bytes!("../../../scripts/nessus-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/nessus-xmlrpc-brute.nse",
        data: include_bytes!("../../../scripts/nessus-xmlrpc-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/netbus-auth-bypass.nse",
        data: include_bytes!("../../../scripts/netbus-auth-bypass.nse"),
    },
    EmbeddedFile {
        path: "scripts/netbus-brute.nse",
        data: include_bytes!("../../../scripts/netbus-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/netbus-info.nse",
        data: include_bytes!("../../../scripts/netbus-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/netbus-version.nse",
        data: include_bytes!("../../../scripts/netbus-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/nexpose-brute.nse",
        data: include_bytes!("../../../scripts/nexpose-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/nfs-ls.nse",
        data: include_bytes!("../../../scripts/nfs-ls.nse"),
    },
    EmbeddedFile {
        path: "scripts/nfs-showmount.nse",
        data: include_bytes!("../../../scripts/nfs-showmount.nse"),
    },
    EmbeddedFile {
        path: "scripts/nfs-statfs.nse",
        data: include_bytes!("../../../scripts/nfs-statfs.nse"),
    },
    EmbeddedFile {
        path: "scripts/nje-node-brute.nse",
        data: include_bytes!("../../../scripts/nje-node-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/nje-pass-brute.nse",
        data: include_bytes!("../../../scripts/nje-pass-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/nntp-ntlm-info.nse",
        data: include_bytes!("../../../scripts/nntp-ntlm-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/nping-brute.nse",
        data: include_bytes!("../../../scripts/nping-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/nrpe-enum.nse",
        data: include_bytes!("../../../scripts/nrpe-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/ntp-info.nse",
        data: include_bytes!("../../../scripts/ntp-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/ntp-monlist.nse",
        data: include_bytes!("../../../scripts/ntp-monlist.nse"),
    },
    EmbeddedFile {
        path: "scripts/omp2-brute.nse",
        data: include_bytes!("../../../scripts/omp2-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/omp2-enum-targets.nse",
        data: include_bytes!("../../../scripts/omp2-enum-targets.nse"),
    },
    EmbeddedFile {
        path: "scripts/omron-info.nse",
        data: include_bytes!("../../../scripts/omron-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/openflow-info.nse",
        data: include_bytes!("../../../scripts/openflow-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/openlookup-info.nse",
        data: include_bytes!("../../../scripts/openlookup-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/openvas-otp-brute.nse",
        data: include_bytes!("../../../scripts/openvas-otp-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/openwebnet-discovery.nse",
        data: include_bytes!("../../../scripts/openwebnet-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/oracle-brute-stealth.nse",
        data: include_bytes!("../../../scripts/oracle-brute-stealth.nse"),
    },
    EmbeddedFile {
        path: "scripts/oracle-brute.nse",
        data: include_bytes!("../../../scripts/oracle-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/oracle-enum-users.nse",
        data: include_bytes!("../../../scripts/oracle-enum-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/oracle-sid-brute.nse",
        data: include_bytes!("../../../scripts/oracle-sid-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/oracle-tns-version.nse",
        data: include_bytes!("../../../scripts/oracle-tns-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/ovs-agent-version.nse",
        data: include_bytes!("../../../scripts/ovs-agent-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/p2p-conficker.nse",
        data: include_bytes!("../../../scripts/p2p-conficker.nse"),
    },
    EmbeddedFile {
        path: "scripts/path-mtu.nse",
        data: include_bytes!("../../../scripts/path-mtu.nse"),
    },
    EmbeddedFile {
        path: "scripts/pcanywhere-brute.nse",
        data: include_bytes!("../../../scripts/pcanywhere-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/pcworx-info.nse",
        data: include_bytes!("../../../scripts/pcworx-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/pgsql-brute.nse",
        data: include_bytes!("../../../scripts/pgsql-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/pjl-ready-message.nse",
        data: include_bytes!("../../../scripts/pjl-ready-message.nse"),
    },
    EmbeddedFile {
        path: "scripts/pop3-brute.nse",
        data: include_bytes!("../../../scripts/pop3-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/pop3-capabilities.nse",
        data: include_bytes!("../../../scripts/pop3-capabilities.nse"),
    },
    EmbeddedFile {
        path: "scripts/pop3-ntlm-info.nse",
        data: include_bytes!("../../../scripts/pop3-ntlm-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/port-states.nse",
        data: include_bytes!("../../../scripts/port-states.nse"),
    },
    EmbeddedFile {
        path: "scripts/pptp-version.nse",
        data: include_bytes!("../../../scripts/pptp-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/profinet-cm-lookup.nse",
        data: include_bytes!("../../../scripts/profinet-cm-lookup.nse"),
    },
    EmbeddedFile {
        path: "scripts/puppet-naivesigning.nse",
        data: include_bytes!("../../../scripts/puppet-naivesigning.nse"),
    },
    EmbeddedFile {
        path: "scripts/qconn-exec.nse",
        data: include_bytes!("../../../scripts/qconn-exec.nse"),
    },
    EmbeddedFile {
        path: "scripts/qscan.nse",
        data: include_bytes!("../../../scripts/qscan.nse"),
    },
    EmbeddedFile {
        path: "scripts/quake1-info.nse",
        data: include_bytes!("../../../scripts/quake1-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/quake3-info.nse",
        data: include_bytes!("../../../scripts/quake3-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/quake3-master-getservers.nse",
        data: include_bytes!("../../../scripts/quake3-master-getservers.nse"),
    },
    EmbeddedFile {
        path: "scripts/rdp-enum-encryption.nse",
        data: include_bytes!("../../../scripts/rdp-enum-encryption.nse"),
    },
    EmbeddedFile {
        path: "scripts/rdp-ntlm-info.nse",
        data: include_bytes!("../../../scripts/rdp-ntlm-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/rdp-vuln-ms12-020.nse",
        data: include_bytes!("../../../scripts/rdp-vuln-ms12-020.nse"),
    },
    EmbeddedFile {
        path: "scripts/realvnc-auth-bypass.nse",
        data: include_bytes!("../../../scripts/realvnc-auth-bypass.nse"),
    },
    EmbeddedFile {
        path: "scripts/redis-brute.nse",
        data: include_bytes!("../../../scripts/redis-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/redis-info.nse",
        data: include_bytes!("../../../scripts/redis-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/resolveall.nse",
        data: include_bytes!("../../../scripts/resolveall.nse"),
    },
    EmbeddedFile {
        path: "scripts/reverse-index.nse",
        data: include_bytes!("../../../scripts/reverse-index.nse"),
    },
    EmbeddedFile {
        path: "scripts/rexec-brute.nse",
        data: include_bytes!("../../../scripts/rexec-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/rfc868-time.nse",
        data: include_bytes!("../../../scripts/rfc868-time.nse"),
    },
    EmbeddedFile {
        path: "scripts/riak-http-info.nse",
        data: include_bytes!("../../../scripts/riak-http-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/rlogin-brute.nse",
        data: include_bytes!("../../../scripts/rlogin-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/rmi-dumpregistry.nse",
        data: include_bytes!("../../../scripts/rmi-dumpregistry.nse"),
    },
    EmbeddedFile {
        path: "scripts/rmi-vuln-classloader.nse",
        data: include_bytes!("../../../scripts/rmi-vuln-classloader.nse"),
    },
    EmbeddedFile {
        path: "scripts/rpc-grind.nse",
        data: include_bytes!("../../../scripts/rpc-grind.nse"),
    },
    EmbeddedFile {
        path: "scripts/rpcap-brute.nse",
        data: include_bytes!("../../../scripts/rpcap-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/rpcap-info.nse",
        data: include_bytes!("../../../scripts/rpcap-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/rpcinfo.nse",
        data: include_bytes!("../../../scripts/rpcinfo.nse"),
    },
    EmbeddedFile {
        path: "scripts/rsa-vuln-roca.nse",
        data: include_bytes!("../../../scripts/rsa-vuln-roca.nse"),
    },
    EmbeddedFile {
        path: "scripts/rsync-brute.nse",
        data: include_bytes!("../../../scripts/rsync-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/rsync-list-modules.nse",
        data: include_bytes!("../../../scripts/rsync-list-modules.nse"),
    },
    EmbeddedFile {
        path: "scripts/rtsp-methods.nse",
        data: include_bytes!("../../../scripts/rtsp-methods.nse"),
    },
    EmbeddedFile {
        path: "scripts/rtsp-url-brute.nse",
        data: include_bytes!("../../../scripts/rtsp-url-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/rusers.nse",
        data: include_bytes!("../../../scripts/rusers.nse"),
    },
    EmbeddedFile {
        path: "scripts/s7-info.nse",
        data: include_bytes!("../../../scripts/s7-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/samba-vuln-cve-2012-1182.nse",
        data: include_bytes!("../../../scripts/samba-vuln-cve-2012-1182.nse"),
    },
    EmbeddedFile {
        path: "scripts/script.db",
        data: include_bytes!("../../../scripts/script.db"),
    },
    EmbeddedFile {
        path: "scripts/servicetags.nse",
        data: include_bytes!("../../../scripts/servicetags.nse"),
    },
    EmbeddedFile {
        path: "scripts/shodan-api.nse",
        data: include_bytes!("../../../scripts/shodan-api.nse"),
    },
    EmbeddedFile {
        path: "scripts/sip-brute.nse",
        data: include_bytes!("../../../scripts/sip-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/sip-call-spoof.nse",
        data: include_bytes!("../../../scripts/sip-call-spoof.nse"),
    },
    EmbeddedFile {
        path: "scripts/sip-enum-users.nse",
        data: include_bytes!("../../../scripts/sip-enum-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/sip-methods.nse",
        data: include_bytes!("../../../scripts/sip-methods.nse"),
    },
    EmbeddedFile {
        path: "scripts/skypev2-version.nse",
        data: include_bytes!("../../../scripts/skypev2-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-brute.nse",
        data: include_bytes!("../../../scripts/smb-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-double-pulsar-backdoor.nse",
        data: include_bytes!("../../../scripts/smb-double-pulsar-backdoor.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-enum-domains.nse",
        data: include_bytes!("../../../scripts/smb-enum-domains.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-enum-groups.nse",
        data: include_bytes!("../../../scripts/smb-enum-groups.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-enum-processes.nse",
        data: include_bytes!("../../../scripts/smb-enum-processes.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-enum-services.nse",
        data: include_bytes!("../../../scripts/smb-enum-services.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-enum-sessions.nse",
        data: include_bytes!("../../../scripts/smb-enum-sessions.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-enum-shares.nse",
        data: include_bytes!("../../../scripts/smb-enum-shares.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-enum-users.nse",
        data: include_bytes!("../../../scripts/smb-enum-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-flood.nse",
        data: include_bytes!("../../../scripts/smb-flood.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-ls.nse",
        data: include_bytes!("../../../scripts/smb-ls.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-mbenum.nse",
        data: include_bytes!("../../../scripts/smb-mbenum.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-os-discovery.nse",
        data: include_bytes!("../../../scripts/smb-os-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-print-text.nse",
        data: include_bytes!("../../../scripts/smb-print-text.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-protocols.nse",
        data: include_bytes!("../../../scripts/smb-protocols.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-psexec.nse",
        data: include_bytes!("../../../scripts/smb-psexec.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-security-mode.nse",
        data: include_bytes!("../../../scripts/smb-security-mode.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-server-stats.nse",
        data: include_bytes!("../../../scripts/smb-server-stats.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-system-info.nse",
        data: include_bytes!("../../../scripts/smb-system-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-conficker.nse",
        data: include_bytes!("../../../scripts/smb-vuln-conficker.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-cve-2017-7494.nse",
        data: include_bytes!("../../../scripts/smb-vuln-cve-2017-7494.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-cve2009-3103.nse",
        data: include_bytes!("../../../scripts/smb-vuln-cve2009-3103.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-ms06-025.nse",
        data: include_bytes!("../../../scripts/smb-vuln-ms06-025.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-ms07-029.nse",
        data: include_bytes!("../../../scripts/smb-vuln-ms07-029.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-ms08-067.nse",
        data: include_bytes!("../../../scripts/smb-vuln-ms08-067.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-ms10-054.nse",
        data: include_bytes!("../../../scripts/smb-vuln-ms10-054.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-ms10-061.nse",
        data: include_bytes!("../../../scripts/smb-vuln-ms10-061.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-ms17-010.nse",
        data: include_bytes!("../../../scripts/smb-vuln-ms17-010.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-regsvc-dos.nse",
        data: include_bytes!("../../../scripts/smb-vuln-regsvc-dos.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-vuln-webexec.nse",
        data: include_bytes!("../../../scripts/smb-vuln-webexec.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb-webexec-exploit.nse",
        data: include_bytes!("../../../scripts/smb-webexec-exploit.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb2-capabilities.nse",
        data: include_bytes!("../../../scripts/smb2-capabilities.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb2-security-mode.nse",
        data: include_bytes!("../../../scripts/smb2-security-mode.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb2-time.nse",
        data: include_bytes!("../../../scripts/smb2-time.nse"),
    },
    EmbeddedFile {
        path: "scripts/smb2-vuln-uptime.nse",
        data: include_bytes!("../../../scripts/smb2-vuln-uptime.nse"),
    },
    EmbeddedFile {
        path: "scripts/smtp-brute.nse",
        data: include_bytes!("../../../scripts/smtp-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/smtp-commands.nse",
        data: include_bytes!("../../../scripts/smtp-commands.nse"),
    },
    EmbeddedFile {
        path: "scripts/smtp-enum-users.nse",
        data: include_bytes!("../../../scripts/smtp-enum-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/smtp-ntlm-info.nse",
        data: include_bytes!("../../../scripts/smtp-ntlm-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/smtp-open-relay.nse",
        data: include_bytes!("../../../scripts/smtp-open-relay.nse"),
    },
    EmbeddedFile {
        path: "scripts/smtp-strangeport.nse",
        data: include_bytes!("../../../scripts/smtp-strangeport.nse"),
    },
    EmbeddedFile {
        path: "scripts/smtp-vuln-cve2010-4344.nse",
        data: include_bytes!("../../../scripts/smtp-vuln-cve2010-4344.nse"),
    },
    EmbeddedFile {
        path: "scripts/smtp-vuln-cve2011-1720.nse",
        data: include_bytes!("../../../scripts/smtp-vuln-cve2011-1720.nse"),
    },
    EmbeddedFile {
        path: "scripts/smtp-vuln-cve2011-1764.nse",
        data: include_bytes!("../../../scripts/smtp-vuln-cve2011-1764.nse"),
    },
    EmbeddedFile {
        path: "scripts/sniffer-detect.nse",
        data: include_bytes!("../../../scripts/sniffer-detect.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-brute.nse",
        data: include_bytes!("../../../scripts/snmp-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-hh3c-logins.nse",
        data: include_bytes!("../../../scripts/snmp-hh3c-logins.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-info.nse",
        data: include_bytes!("../../../scripts/snmp-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-interfaces.nse",
        data: include_bytes!("../../../scripts/snmp-interfaces.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-ios-config.nse",
        data: include_bytes!("../../../scripts/snmp-ios-config.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-netstat.nse",
        data: include_bytes!("../../../scripts/snmp-netstat.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-processes.nse",
        data: include_bytes!("../../../scripts/snmp-processes.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-sysdescr.nse",
        data: include_bytes!("../../../scripts/snmp-sysdescr.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-win32-services.nse",
        data: include_bytes!("../../../scripts/snmp-win32-services.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-win32-shares.nse",
        data: include_bytes!("../../../scripts/snmp-win32-shares.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-win32-software.nse",
        data: include_bytes!("../../../scripts/snmp-win32-software.nse"),
    },
    EmbeddedFile {
        path: "scripts/snmp-win32-users.nse",
        data: include_bytes!("../../../scripts/snmp-win32-users.nse"),
    },
    EmbeddedFile {
        path: "scripts/socks-auth-info.nse",
        data: include_bytes!("../../../scripts/socks-auth-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/socks-brute.nse",
        data: include_bytes!("../../../scripts/socks-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/socks-open-proxy.nse",
        data: include_bytes!("../../../scripts/socks-open-proxy.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssh-auth-methods.nse",
        data: include_bytes!("../../../scripts/ssh-auth-methods.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssh-brute.nse",
        data: include_bytes!("../../../scripts/ssh-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssh-hostkey.nse",
        data: include_bytes!("../../../scripts/ssh-hostkey.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssh-publickey-acceptance.nse",
        data: include_bytes!("../../../scripts/ssh-publickey-acceptance.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssh-run.nse",
        data: include_bytes!("../../../scripts/ssh-run.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssh2-enum-algos.nse",
        data: include_bytes!("../../../scripts/ssh2-enum-algos.nse"),
    },
    EmbeddedFile {
        path: "scripts/sshv1.nse",
        data: include_bytes!("../../../scripts/sshv1.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssl-ccs-injection.nse",
        data: include_bytes!("../../../scripts/ssl-ccs-injection.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssl-cert-intaddr.nse",
        data: include_bytes!("../../../scripts/ssl-cert-intaddr.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssl-cert.nse",
        data: include_bytes!("../../../scripts/ssl-cert.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssl-date.nse",
        data: include_bytes!("../../../scripts/ssl-date.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssl-dh-params.nse",
        data: include_bytes!("../../../scripts/ssl-dh-params.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssl-enum-ciphers.nse",
        data: include_bytes!("../../../scripts/ssl-enum-ciphers.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssl-heartbleed.nse",
        data: include_bytes!("../../../scripts/ssl-heartbleed.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssl-known-key.nse",
        data: include_bytes!("../../../scripts/ssl-known-key.nse"),
    },
    EmbeddedFile {
        path: "scripts/ssl-poodle.nse",
        data: include_bytes!("../../../scripts/ssl-poodle.nse"),
    },
    EmbeddedFile {
        path: "scripts/sslv2-drown.nse",
        data: include_bytes!("../../../scripts/sslv2-drown.nse"),
    },
    EmbeddedFile {
        path: "scripts/sslv2.nse",
        data: include_bytes!("../../../scripts/sslv2.nse"),
    },
    EmbeddedFile {
        path: "scripts/sstp-discover.nse",
        data: include_bytes!("../../../scripts/sstp-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/stun-info.nse",
        data: include_bytes!("../../../scripts/stun-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/stun-version.nse",
        data: include_bytes!("../../../scripts/stun-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/stuxnet-detect.nse",
        data: include_bytes!("../../../scripts/stuxnet-detect.nse"),
    },
    EmbeddedFile {
        path: "scripts/supermicro-ipmi-conf.nse",
        data: include_bytes!("../../../scripts/supermicro-ipmi-conf.nse"),
    },
    EmbeddedFile {
        path: "scripts/svn-brute.nse",
        data: include_bytes!("../../../scripts/svn-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-asn.nse",
        data: include_bytes!("../../../scripts/targets-asn.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-ipv6-eui64.nse",
        data: include_bytes!("../../../scripts/targets-ipv6-eui64.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-ipv6-map4to6.nse",
        data: include_bytes!("../../../scripts/targets-ipv6-map4to6.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-ipv6-multicast-echo.nse",
        data: include_bytes!("../../../scripts/targets-ipv6-multicast-echo.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-ipv6-multicast-invalid-dst.nse",
        data: include_bytes!("../../../scripts/targets-ipv6-multicast-invalid-dst.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-ipv6-multicast-mld.nse",
        data: include_bytes!("../../../scripts/targets-ipv6-multicast-mld.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-ipv6-multicast-slaac.nse",
        data: include_bytes!("../../../scripts/targets-ipv6-multicast-slaac.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-ipv6-wordlist.nse",
        data: include_bytes!("../../../scripts/targets-ipv6-wordlist.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-sniffer.nse",
        data: include_bytes!("../../../scripts/targets-sniffer.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-traceroute.nse",
        data: include_bytes!("../../../scripts/targets-traceroute.nse"),
    },
    EmbeddedFile {
        path: "scripts/targets-xml.nse",
        data: include_bytes!("../../../scripts/targets-xml.nse"),
    },
    EmbeddedFile {
        path: "scripts/teamspeak2-version.nse",
        data: include_bytes!("../../../scripts/teamspeak2-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/telnet-brute.nse",
        data: include_bytes!("../../../scripts/telnet-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/telnet-encryption.nse",
        data: include_bytes!("../../../scripts/telnet-encryption.nse"),
    },
    EmbeddedFile {
        path: "scripts/telnet-ntlm-info.nse",
        data: include_bytes!("../../../scripts/telnet-ntlm-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/tftp-enum.nse",
        data: include_bytes!("../../../scripts/tftp-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/tftp-version.nse",
        data: include_bytes!("../../../scripts/tftp-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/tls-alpn.nse",
        data: include_bytes!("../../../scripts/tls-alpn.nse"),
    },
    EmbeddedFile {
        path: "scripts/tls-nextprotoneg.nse",
        data: include_bytes!("../../../scripts/tls-nextprotoneg.nse"),
    },
    EmbeddedFile {
        path: "scripts/tls-ticketbleed.nse",
        data: include_bytes!("../../../scripts/tls-ticketbleed.nse"),
    },
    EmbeddedFile {
        path: "scripts/tn3270-screen.nse",
        data: include_bytes!("../../../scripts/tn3270-screen.nse"),
    },
    EmbeddedFile {
        path: "scripts/tor-consensus-checker.nse",
        data: include_bytes!("../../../scripts/tor-consensus-checker.nse"),
    },
    EmbeddedFile {
        path: "scripts/traceroute-geolocation.nse",
        data: include_bytes!("../../../scripts/traceroute-geolocation.nse"),
    },
    EmbeddedFile {
        path: "scripts/tso-brute.nse",
        data: include_bytes!("../../../scripts/tso-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/tso-enum.nse",
        data: include_bytes!("../../../scripts/tso-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/ubiquiti-discovery.nse",
        data: include_bytes!("../../../scripts/ubiquiti-discovery.nse"),
    },
    EmbeddedFile {
        path: "scripts/unittest.nse",
        data: include_bytes!("../../../scripts/unittest.nse"),
    },
    EmbeddedFile {
        path: "scripts/unusual-port.nse",
        data: include_bytes!("../../../scripts/unusual-port.nse"),
    },
    EmbeddedFile {
        path: "scripts/upnp-info.nse",
        data: include_bytes!("../../../scripts/upnp-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/uptime-agent-info.nse",
        data: include_bytes!("../../../scripts/uptime-agent-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/url-snarf.nse",
        data: include_bytes!("../../../scripts/url-snarf.nse"),
    },
    EmbeddedFile {
        path: "scripts/ventrilo-info.nse",
        data: include_bytes!("../../../scripts/ventrilo-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/versant-info.nse",
        data: include_bytes!("../../../scripts/versant-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/vmauthd-brute.nse",
        data: include_bytes!("../../../scripts/vmauthd-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/vmware-version.nse",
        data: include_bytes!("../../../scripts/vmware-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/vnc-brute.nse",
        data: include_bytes!("../../../scripts/vnc-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/vnc-info.nse",
        data: include_bytes!("../../../scripts/vnc-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/vnc-title.nse",
        data: include_bytes!("../../../scripts/vnc-title.nse"),
    },
    EmbeddedFile {
        path: "scripts/voldemort-info.nse",
        data: include_bytes!("../../../scripts/voldemort-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/vtam-enum.nse",
        data: include_bytes!("../../../scripts/vtam-enum.nse"),
    },
    EmbeddedFile {
        path: "scripts/vulners.nse",
        data: include_bytes!("../../../scripts/vulners.nse"),
    },
    EmbeddedFile {
        path: "scripts/vuze-dht-info.nse",
        data: include_bytes!("../../../scripts/vuze-dht-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/wdb-version.nse",
        data: include_bytes!("../../../scripts/wdb-version.nse"),
    },
    EmbeddedFile {
        path: "scripts/weblogic-t3-info.nse",
        data: include_bytes!("../../../scripts/weblogic-t3-info.nse"),
    },
    EmbeddedFile {
        path: "scripts/whois-domain.nse",
        data: include_bytes!("../../../scripts/whois-domain.nse"),
    },
    EmbeddedFile {
        path: "scripts/whois-ip.nse",
        data: include_bytes!("../../../scripts/whois-ip.nse"),
    },
    EmbeddedFile {
        path: "scripts/wsdd-discover.nse",
        data: include_bytes!("../../../scripts/wsdd-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/x11-access.nse",
        data: include_bytes!("../../../scripts/x11-access.nse"),
    },
    EmbeddedFile {
        path: "scripts/xdmcp-discover.nse",
        data: include_bytes!("../../../scripts/xdmcp-discover.nse"),
    },
    EmbeddedFile {
        path: "scripts/xmlrpc-methods.nse",
        data: include_bytes!("../../../scripts/xmlrpc-methods.nse"),
    },
    EmbeddedFile {
        path: "scripts/xmpp-brute.nse",
        data: include_bytes!("../../../scripts/xmpp-brute.nse"),
    },
    EmbeddedFile {
        path: "scripts/xmpp-info.nse",
        data: include_bytes!("../../../scripts/xmpp-info.nse"),
    },
];
