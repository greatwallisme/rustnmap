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

//! UDP service payloads for port scanning.
//!
//! When scanning UDP ports, sending an empty packet often produces no response
//! even when a service is listening. Many services (DNS, NTP, SNMP, etc.)
//! only respond to well-formed protocol-specific requests.
//!
//! This module provides service-specific UDP payloads, matching nmap's
//! `payload.cc` behavior. Payloads are sourced from `nmap-service-probes`.
//!
//! # How nmap does it
//!
//! 1. `init_payloads()` loads UDP probes from `nmap-service-probes`
//! 2. For each port, `get_udp_payload(dport)` returns the matching payload
//! 3. `scan_engine_raw.cc:1242`: `payload = get_udp_payload(dport, &len, i)`
//! 4. If no specific payload exists, empty (0-byte) payload is used
//! 5. Multiple payloads per port are sent sequentially (up to `MAX_PAYLOADS_PER_PORT`)

/// A UDP probe payload with its associated port mapping.
#[derive(Debug, Clone)]
struct UdpPayloadEntry {
    /// Destination port this payload targets.
    port: u16,
    /// Raw payload bytes to send.
    data: &'static [u8],
}

// Payload data from nmap's nmap-service-probes file.
// Each entry maps a specific payload to a destination port.

/// DNS Version Bind Request payload for port 53.
/// Source: `nmap-service-probes` line 12677 - `Probe UDP DNSVersionBindReq`
const DNS_VERSION_BIND_REQ: &[u8] = &[
    0x00, 0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x76, 0x65, 0x72,
    0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, 0x00, 0x10, 0x00, 0x03,
];

/// DNS Status Request payload for port 53.
/// Source: `nmap-service-probes` line 13023 - `Probe UDP DNSStatusRequest`
const DNS_STATUS_REQUEST: &[u8] = &[
    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// NTP Request payload for port 123.
/// Source: `nmap-service-probes` line 15299 - `Probe UDP NTPRequest`
const NTP_REQUEST: &[u8] = &[
    0xe3, 0x00, 0x04, 0xfa, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc5, 0x4f, 0x23, 0x4b, 0x71, 0xb1, 0x52, 0xf3,
];

/// SNMP v1 public community `GetRequest` payload for port 161.
const SNMP_V1_PUBLIC: &[u8] = &[
    0x30, 0x82, 0x00, 0x2f, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0,
    0x82, 0x00, 0x20, 0x02, 0x04, 0x4c, 0x33, 0xa7, 0x56, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
    0x82, 0x00, 0x10, 0x30, 0x82, 0x00, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05,
    0x00, 0x05, 0x00,
];

/// RPC Check payload for port 111 (portmapper) and others.
/// Source: `nmap-service-probes` line 12572 - `Probe UDP RPCCheck`
const RPC_CHECK: &[u8] = &[
    0x72, 0xfe, 0x1d, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0,
    0x00, 0x01, 0x97, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// `NetBIOS` Name Service (`NBSTAT`) payload for port 137.
/// Source: `nmap-service-probes` line 13105 - `Probe UDP NBTStat`
const NBT_STAT: &[u8] = &[
    0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
];

/// Help request payload for echo/chargen/daytime ports.
/// Source: `nmap-service-probes` line 13215 - `Probe UDP Help`
const HELP_REQUEST: &[u8] = &[0x68, 0x65, 0x6c, 0x70, 0x0d, 0x0a, 0x0d, 0x0a]; // "help\r\n\r\n"

/// SIP Options payload for port 5060.
/// Source: `nmap-service-probes` line 15015 - `Probe UDP SIPOptions`
const SIP_OPTIONS: &[u8] = &[
    0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 0x20, 0x73, 0x69, 0x70, 0x3a, 0x6e, 0x6d, 0x20, 0x53,
    0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x56, 0x69, 0x61, 0x3a, 0x20, 0x53, 0x49, 0x50,
    0x2f, 0x32, 0x2e, 0x30, 0x2f, 0x55, 0x44, 0x50, 0x20, 0x6e, 0x6d, 0x3b, 0x62, 0x72, 0x61, 0x6e,
    0x63, 0x68, 0x3d, 0x66, 0x6f, 0x6f, 0x3b, 0x72, 0x70, 0x6f, 0x72, 0x74, 0x0d, 0x0a, 0x46, 0x72,
    0x6f, 0x6d, 0x3a, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a, 0x6e, 0x6d, 0x40, 0x6e, 0x6d, 0x3e, 0x3b,
    0x74, 0x61, 0x67, 0x3d, 0x72, 0x6f, 0x6f, 0x74, 0x0d, 0x0a, 0x54, 0x6f, 0x3a, 0x20, 0x3c, 0x73,
    0x69, 0x70, 0x3a, 0x6e, 0x6d, 0x32, 0x40, 0x6e, 0x6d, 0x32, 0x3e, 0x0d, 0x0a, 0x43, 0x61, 0x6c,
    0x6c, 0x2d, 0x49, 0x44, 0x3a, 0x20, 0x35, 0x30, 0x30, 0x30, 0x30, 0x0d, 0x0a, 0x43, 0x53, 0x65,
    0x71, 0x3a, 0x20, 0x34, 0x32, 0x20, 0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 0x0d, 0x0a, 0x4d,
    0x61, 0x78, 0x2d, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x73, 0x3a, 0x20, 0x37, 0x30, 0x0d,
    0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a,
    0x20, 0x30, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74, 0x3a, 0x20, 0x3c, 0x73, 0x69,
    0x70, 0x3a, 0x6e, 0x6d, 0x40, 0x6e, 0x6d, 0x3e, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74,
    0x3a, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x73, 0x64,
    0x70, 0x0d, 0x0a, 0x0d, 0x0a,
];

/// LDAP Search Request payload for port 389.
/// Source: `nmap-service-probes` line 14758 - `Probe UDP LDAPSearchReqUDP`
const LDAP_SEARCH_REQ: &[u8] = &[
    0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, 0x02, 0x01, 0x07, 0x63, 0x84, 0x00, 0x00, 0x00, 0x24, 0x04,
    0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x64, 0x01, 0x01, 0x00,
    0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x84, 0x00,
    0x00, 0x00, 0x00,
];

/// mDNS/DNS-SD query payload for port 5353.
/// Source: `nmap-service-probes` line 15904 - `Probe UDP DNS-SD`
const DNS_SD: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x5f, 0x73, 0x65,
    0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, 0x04, 0x5f,
    0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01,
];

/// XDMCP payload for port 177.
/// Source: `nmap-service-probes` line 15525 - `Probe UDP xdmcp`
const XDMCP: &[u8] = &[0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00];

/// MEMCACHED version request for port 11211.
/// Source: `nmap-service-probes` line 17111 - `Probe UDP MEMCACHED_VERSION`
const MEMCACHED_VERSION: &[u8] = &[
    0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x0d,
    0x0a,
];

/// DB2 DAS discovery for port 523.
/// Source: `nmap-service-probes` line 15885 - `Probe UDP ibm-db2-das-udp`
const DB2_DAS: &[u8] = &[
    0x44, 0x42, 0x32, 0x47, 0x45, 0x54, 0x41, 0x44, 0x44, 0x52, 0x00, 0x53, 0x51, 0x4c, 0x30, 0x38,
    0x30, 0x31, 0x30, 0x00,
];

/// AFS version request for port 7000.
/// Source: `nmap-service-probes` line 15539 - `Probe UDP AFSVersionRequest`
const AFS_VERSION: &[u8] = &[
    0x00, 0x00, 0x03, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// SQL Server browser payload for port 1434.
/// Source: `nmap-service-probes` line 15282 - `Probe UDP Sqlping`
const SQL_PING: &[u8] = &[0x02];

/// NAT-PMP external address request for port 5351.
/// Source: `nmap-service-probes` line 17084 - `Probe UDP NAT_PMP_ADDR`
const NAT_PMP: &[u8] = &[0x00, 0x00];

/// PC Anywhere status for port 5632.
/// Source: `nmap-service-probes` line 17090 - `Probe UDP PCANY_STATUS`
const PCANY_STATUS: &[u8] = &[0x53, 0x54]; // "ST"

/// Citrix payload for port 1604.
/// Source: `nmap-service-probes` line 15958 - `Probe UDP Citrix`
const CITRIX: &[u8] = &[
    0x1e, 0x00, 0x01, 0x30, 0x02, 0xfd, 0xa8, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x30, 0x02, 0xfd, 0xa8, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Complete payload lookup table.
///
/// Ordered by port number. Multiple payloads for the same port are listed
/// sequentially (e.g., DNS has `DNSVersionBindReq` and `DNSStatusRequest` for port 53).
///
/// Port assignments from `nmap-service-probes`:
/// - Port 7, 13, 37, 42: `Help`
/// - Port 17, 88, 111, 407, 500, 517, 518, 1419, 2427, 4045, 10000, 10080, 32750-32810: `RPCCheck`
/// - Port 53, 1967, 2967, 26198: `DNSVersionBindReq` + `DNSStatusRequest`
/// - Port 123, 5353, 9100: `NTPRequest`
/// - Port 137: `NBTStat`
/// - Port 161, 260, 3401: `SNMPv1public` + `SNMPv3GetRequest`
/// - Port 389: `LDAPSearchReqUDP`
/// - Port 5060: `SIPOptions`
/// - Port 5353: `DNS-SD`
/// - Port 11211: `MEMCACHED_VERSION`
/// - Port 1434: `Sqlping`
const PAYLOAD_TABLE: &[UdpPayloadEntry] = &[
    // Port 7, 13, 37, 42: Help ("help\r\n\r\n")
    UdpPayloadEntry {
        port: 7,
        data: HELP_REQUEST,
    },
    UdpPayloadEntry {
        port: 13,
        data: HELP_REQUEST,
    },
    UdpPayloadEntry {
        port: 37,
        data: HELP_REQUEST,
    },
    UdpPayloadEntry {
        port: 42,
        data: HELP_REQUEST,
    },
    // Port 17 (qotd), 111 (portmapper), etc.: RPCCheck
    UdpPayloadEntry {
        port: 17,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 88,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 111,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 407,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 500,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 517,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 518,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 1419,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 2427,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 4045,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 10000,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 10080,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32750,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32751,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32752,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32753,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32754,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32755,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32756,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32757,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32758,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32759,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32760,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32761,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32762,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32763,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32764,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32765,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32766,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32767,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32768,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32769,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32770,
        data: RPC_CHECK,
    },
    UdpPayloadEntry {
        port: 32771,
        data: RPC_CHECK,
    },
    // Port 53: DNS (two probes, like nmap)
    UdpPayloadEntry {
        port: 53,
        data: DNS_VERSION_BIND_REQ,
    },
    // Port 69 (tftp): DNSStatusRequest
    UdpPayloadEntry {
        port: 69,
        data: DNS_STATUS_REQUEST,
    },
    // Port 123: NTP
    UdpPayloadEntry {
        port: 123,
        data: NTP_REQUEST,
    },
    // Port 135: DNSStatusRequest
    UdpPayloadEntry {
        port: 135,
        data: DNS_STATUS_REQUEST,
    },
    // Port 137: NetBIOS
    UdpPayloadEntry {
        port: 137,
        data: NBT_STAT,
    },
    // Port 161: SNMP (two probes)
    UdpPayloadEntry {
        port: 161,
        data: SNMP_V1_PUBLIC,
    },
    // Port 177: XDMCP
    UdpPayloadEntry {
        port: 177,
        data: XDMCP,
    },
    // Port 260: SNMP
    UdpPayloadEntry {
        port: 260,
        data: SNMP_V1_PUBLIC,
    },
    // Port 389: LDAP
    UdpPayloadEntry {
        port: 389,
        data: LDAP_SEARCH_REQ,
    },
    // Port 523: DB2 DAS
    UdpPayloadEntry {
        port: 523,
        data: DB2_DAS,
    },
    // Port 1434: SQL Server browser
    UdpPayloadEntry {
        port: 1434,
        data: SQL_PING,
    },
    // Port 1604: Citrix
    UdpPayloadEntry {
        port: 1604,
        data: CITRIX,
    },
    // Port 1761: DNSStatusRequest
    UdpPayloadEntry {
        port: 1761,
        data: DNS_STATUS_REQUEST,
    },
    // Port 3401: SNMP
    UdpPayloadEntry {
        port: 3401,
        data: SNMP_V1_PUBLIC,
    },
    // Port 5060: SIP
    UdpPayloadEntry {
        port: 5060,
        data: SIP_OPTIONS,
    },
    // Port 5351: NAT-PMP
    UdpPayloadEntry {
        port: 5351,
        data: NAT_PMP,
    },
    // Port 5353: mDNS
    UdpPayloadEntry {
        port: 5353,
        data: DNS_SD,
    },
    // Port 5632: PCAnywhere
    UdpPayloadEntry {
        port: 5632,
        data: PCANY_STATUS,
    },
    // Port 7000: AFS
    UdpPayloadEntry {
        port: 7000,
        data: AFS_VERSION,
    },
    // Port 9100: NTP (secondary ports from nmap)
    UdpPayloadEntry {
        port: 9100,
        data: NTP_REQUEST,
    },
    // Port 11211: Memcached
    UdpPayloadEntry {
        port: 11211,
        data: MEMCACHED_VERSION,
    },
    // Port 12203: RPCCheck
    UdpPayloadEntry {
        port: 12203,
        data: RPC_CHECK,
    },
    // Port 1967: DNSVersionBindReq
    UdpPayloadEntry {
        port: 1967,
        data: DNS_VERSION_BIND_REQ,
    },
    // Port 26198: DNSVersionBindReq
    UdpPayloadEntry {
        port: 26198,
        data: DNS_VERSION_BIND_REQ,
    },
    // Port 27960: RPCCheck
    UdpPayloadEntry {
        port: 27960,
        data: RPC_CHECK,
    },
    // Port 38978: RPCCheck
    UdpPayloadEntry {
        port: 38978,
        data: RPC_CHECK,
    },
];

/// Returns the first UDP payload for the given destination port.
///
/// If no specific payload is defined for the port, returns an empty slice
/// (matching nmap's behavior: `udp_port2payload` returns NULL for unknown ports).
///
/// This is equivalent to nmap's `get_udp_payload(dport, &length, 0)`.
#[must_use]
pub fn get_udp_payload(port: u16) -> &'static [u8] {
    PAYLOAD_TABLE
        .iter()
        .find(|entry| entry.port == port)
        .map_or(&[], |entry| entry.data)
}

/// Returns the number of payloads defined for a given port.
///
/// Currently we only send one payload per port (the first match from the table).
/// Nmap supports multiple payloads per port but we simplify to just the most
/// effective one.
#[must_use]
pub fn udp_payload_count(port: u16) -> usize {
    usize::from(PAYLOAD_TABLE.iter().any(|entry| entry.port == port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_payload() {
        let payload = get_udp_payload(53);
        assert!(!payload.is_empty(), "DNS port 53 should have a payload");
        // First bytes of DNSVersionBindReq
        assert_eq!(payload[0], 0x00);
        assert_eq!(payload[1], 0x06);
    }

    #[test]
    fn test_ntp_payload() {
        let payload = get_udp_payload(123);
        assert!(!payload.is_empty(), "NTP port 123 should have a payload");
        assert_eq!(payload[0], 0xe3);
    }

    #[test]
    fn test_snmp_payload() {
        let payload = get_udp_payload(161);
        assert!(!payload.is_empty(), "SNMP port 161 should have a payload");
        // SNMP starts with 0x30 (SEQUENCE tag)
        assert_eq!(payload[0], 0x30);
    }

    #[test]
    fn test_portmapper_payload() {
        let payload = get_udp_payload(111);
        assert!(
            !payload.is_empty(),
            "Portmapper port 111 should have RPC payload"
        );
        assert_eq!(payload[0], 0x72);
    }

    #[test]
    fn test_no_payload_for_unknown_port() {
        let payload = get_udp_payload(9999);
        assert!(
            payload.is_empty(),
            "Unknown port should return empty payload"
        );
    }

    #[test]
    fn test_payload_count() {
        assert_eq!(udp_payload_count(53), 1);
        assert_eq!(udp_payload_count(123), 1);
        assert_eq!(udp_payload_count(9999), 0);
    }

    #[test]
    fn test_ldap_payload() {
        let payload = get_udp_payload(389);
        assert!(!payload.is_empty());
        assert_eq!(payload[0], 0x30);
    }

    #[test]
    fn test_sip_payload() {
        let payload = get_udp_payload(5060);
        assert!(!payload.is_empty());
        // "OPTIONS" in ASCII
        assert_eq!(&payload[..7], b"OPTIONS");
    }

    #[test]
    fn test_sql_ping_payload() {
        let payload = get_udp_payload(1434);
        assert_eq!(payload, &[0x02]);
    }
}
