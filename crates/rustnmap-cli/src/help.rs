// rustnmap-cli
// Copyright (C) 2026  greatwallisme
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Help output for `RustNmap` CLI.
//!
//! This module provides nmap-compatible help text for all command-line options.

use std::io::{self, Write};

/// Prints the main help message.
///
/// # Errors
///
/// Returns an error if writing to stdout fails.
#[expect(
    clippy::too_many_lines,
    reason = "Help output is inherently long due to comprehensive option listing"
)]
pub fn print_help() -> io::Result<()> {
    let mut stdout = io::stdout().lock();

    writeln!(
        stdout,
        "RustNmap v{} - Modern Network Mapper",
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(stdout, "https://github.com/greatwalllisme/rustnmap")?;
    writeln!(stdout)?;

    writeln!(stdout, "USAGE:")?;
    writeln!(
        stdout,
        "    rustnmap [Scan Type(s)] [Options] {{target specification}}"
    )?;
    writeln!(stdout)?;

    writeln!(stdout, "TARGET SPECIFICATION:")?;
    writeln!(
        stdout,
        "    Can pass hostnames, IP addresses, networks, etc."
    )?;
    writeln!(
        stdout,
        "    Example: rustnmap scanme.nmap.org, 192.168.0.0/16, 10.0.0-255.1-254"
    )?;
    writeln!(stdout)?;

    writeln!(stdout, "SCAN TECHNIQUES:")?;
    writeln!(
        stdout,
        "    -sS/sT/sU/sN/sF/sX/sA  TCP SYN/Connect/UDP/Null/FIN/Xmas/ACK scans"
    )?;
    writeln!(
        stdout,
        "                           -sS is default with root, -sT without"
    )?;
    writeln!(
        stdout,
        "    -sW                     TCP Window scan (requires root)"
    )?;
    writeln!(
        stdout,
        "    -sM                     TCP Maimon scan (requires root)"
    )?;
    writeln!(stdout)?;

    writeln!(stdout, "SERVICE/VERSION DETECTION:")?;
    writeln!(
        stdout,
        "    -sV                     Probe open ports to determine service/version info"
    )?;
    writeln!(stdout, "        --version-intensity <0-9>")?;
    writeln!(
        stdout,
        "                            Set from 0 (light) to 9 (try all probes)"
    )?;
    writeln!(stdout)?;

    writeln!(stdout, "OS DETECTION:")?;
    writeln!(
        stdout,
        "    -O                      Enable OS detection (requires root)"
    )?;
    writeln!(
        stdout,
        "        --osscan-limit       Limit OS detection to promising targets"
    )?;
    writeln!(
        stdout,
        "        --osscan-guess       Guess OS more aggressively"
    )?;
    writeln!(stdout)?;

    writeln!(stdout, "TIMING AND PERFORMANCE:")?;
    writeln!(
        stdout,
        "    -T<0-5>                 Set timing template (higher is faster)"
    )?;
    writeln!(
        stdout,
        "        --min-rate <rate>    Send packets no slower than <rate> per second"
    )?;
    writeln!(
        stdout,
        "        --max-rate <rate>    Send packets no faster than <rate> per second"
    )?;
    writeln!(stdout)?;

    writeln!(stdout, "FIREWALL/IDS EVASION AND SPOOFING:")?;
    writeln!(
        stdout,
        "    -f; -f <mtu>            Fragment packets (optionally with given MTU)"
    )?;
    writeln!(stdout, "    -D <decoy1[,decoy2][,ME]>")?;
    writeln!(
        stdout,
        "                            Cloak a scan with decoys"
    )?;
    writeln!(stdout, "    -S <IP_Address>         Spoof source address")?;
    writeln!(
        stdout,
        "    -e <iface>              Use specified interface"
    )?;
    writeln!(stdout, "    -g/--source-port <portnumber>")?;
    writeln!(stdout, "                            Use given port number")?;
    writeln!(
        stdout,
        "        --data-length <num> Append random data to sent packets"
    )?;
    writeln!(stdout, "        --data-string <hex>")?;
    writeln!(
        stdout,
        "                            Append a custom string to sent packets"
    )?;
    writeln!(stdout)?;

    writeln!(stdout, "OUTPUT:")?;
    writeln!(
        stdout,
        "    -oN/-oX/-oG/-oA <file>  Output scan in normal, XML, grepable, or all formats"
    )?;
    writeln!(stdout, "        --output-json <file>")?;
    writeln!(
        stdout,
        "                            Output in JSON format (rustnmap extension)"
    )?;
    writeln!(stdout, "        --output-ndjson <file>")?;
    writeln!(
        stdout,
        "                            Output in NDJSON format (newline-delimited JSON)"
    )?;
    writeln!(stdout, "        --output-markdown <file>")?;
    writeln!(
        stdout,
        "                            Output in Markdown format (rustnmap extension)"
    )?;
    writeln!(
        stdout,
        "    -v/-vv/-vvv             Increase verbosity level"
    )?;
    writeln!(
        stdout,
        "    -d/-dd/-ddd             Increase debugging level"
    )?;
    writeln!(
        stdout,
        "    --reason                Display the reason a port is in a particular state"
    )?;
    writeln!(
        stdout,
        "    --open                  Only show open (or possibly open) ports"
    )?;
    writeln!(
        stdout,
        "    --packet-trace          Show all packets sent and received"
    )?;
    writeln!(
        stdout,
        "    --iflist                Print host interfaces and routes (for debugging)"
    )?;
    writeln!(
        stdout,
        "    --append-output         Append to rather than clobber specified output files"
    )?;
    writeln!(stdout)?;

    writeln!(stdout, "MISC:")?;
    writeln!(
        stdout,
        "    -sC                     equivalent to --script=default"
    )?;
    writeln!(stdout, "        --script <Lua scripts>")?;
    writeln!(stdout, "                            <scripts> is comma separated, directories, or scripts with args")?;
    writeln!(
        stdout,
        "        --script-help       Show help about scripts"
    )?;
    writeln!(
        stdout,
        "        --script-updatedb   Update the script database."
    )?;
    writeln!(
        stdout,
        "    -oN/-oX/-oG/-oA <file>  Output scan in normal, XML, grepable, or all formats"
    )?;
    writeln!(
        stdout,
        "    -p <port ranges>        Only scan specified ports"
    )?;
    writeln!(stdout, "        --exclude-ports <ports>")?;
    writeln!(
        stdout,
        "                            Exclude the specified ports from scanning"
    )?;
    writeln!(
        stdout,
        "    -F                      Fast scan - fewer ports than the default scan"
    )?;
    writeln!(
        stdout,
        "    -r                      Scan ports consecutively - don't randomize"
    )?;
    writeln!(stdout, "        --top-ports <number>")?;
    writeln!(
        stdout,
        "                            Scan <number> most common ports"
    )?;
    writeln!(
        stdout,
        "    -n/-R                   Never do DNS resolution/Always resolve [default: maybe]"
    )?;
    writeln!(stdout, "        --dns-servers <serv1[,serv2],...>")?;
    writeln!(
        stdout,
        "                            Specify custom DNS servers"
    )?;
    writeln!(stdout, "    -6                      Enable IPv6 scanning")?;
    writeln!(stdout, "    --system-dns            Use OS's DNS resolver")?;
    writeln!(
        stdout,
        "    --traceroute            Trace hop path to each host"
    )?;
    writeln!(stdout)?;

    writeln!(stdout, "HOST DISCOVERY:")?;
    writeln!(
        stdout,
        "    -Pn                     Treat all hosts as online -- skip host discovery"
    )?;
    writeln!(
        stdout,
        "    -PS/PA/PU <portlist>    TCP SYN/ACK/UDP Ping discovers hosts"
    )?;
    writeln!(
        stdout,
        "    -PE/-PP/PM              ICMP echo, timestamp, and address mask request Pings"
    )?;
    writeln!(stdout)?;

    writeln!(stdout, "INTERACTIVITY:")?;
    writeln!(stdout, "    --help                  Display this help")?;
    writeln!(stdout, "    -V/--version            Print version number")?;
    writeln!(stdout)?;

    writeln!(stdout, "EXAMPLES:")?;
    writeln!(stdout, "    rustnmap -v -sS 192.168.1.1")?;
    writeln!(stdout, "    rustnmap -sS -sV -O -T4 192.168.1.1")?;
    writeln!(stdout, "    rustnmap -sS -sV -O -A scanme.nmap.org")?;
    writeln!(
        stdout,
        "    rustnmap -sS -sV -O -T4 -oA scanresults 192.168.1.0/24"
    )?;
    writeln!(stdout)?;

    writeln!(
        stdout,
        "See the man page (https://nmap.org/book/man.html) for more options and examples"
    )?;

    Ok(())
}

/// Prints the version information.
///
/// # Errors
///
/// Returns an error if writing to stdout fails.
pub fn print_version() -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "RustNmap version {} ({})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    )?;
    writeln!(
        stdout,
        "Platform: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )?;
    writeln!(stdout, "Rust: {}", env!("CARGO_PKG_RUST_VERSION"))?;
    Ok(())
}
