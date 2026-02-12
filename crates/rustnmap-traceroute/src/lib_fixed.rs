# Create a clean version of lib.rs without the syntax issues
head -50 /home/greatwallimse/Private/rust-nmap/crates/rustnmap-traceroute/src/lib.rs | tail -n +50 > /dev/null

# Now fix the problematic section - write probe_hop and send_probe functions
cat << 'RUSTFIX' >> /home/greatwallimse/Private/rust-nmap/crates/rustnmap-traceroute/src/lib.rs

# Beginning of functions to fix (after line 304)
cat << 'PROBE_FUNCTIONS'
    /// Sends a single probe packet.
    async fn send_probe(
        &self,
        target: Ipv4Addr,
        ttl: u8,
    ) -> Result<Option<ProbeResponse>> {
        use tokio::time::timeout;

        let result = match self.config.probe_type {
            ProbeType::Udp => {
                let tracer = UdpTraceroute::new(&self.config)?;
                tracer.send_probe(target, ttl).await
            }
            ProbeType::TcpSyn => {
                let tracer = TcpSynTraceroute::new(&self.config)?;
                tracer.send_probe(target, ttl).await
            }
            ProbeType::TcpAck => {
                let tracer = TcpAckTraceroute::new(&self.config)?;
                tracer.send_probe(target, ttl).await
            }
            ProbeType::Icmp => {
                let tracer = IcmpTraceroute::new(&self.config)?;
                tracer.send_probe(target, ttl).await
            }
        };

        let timeout_result = timeout(self.config.probe_timeout, result).await;

        timeout_result.map_err(|_| TracerouteError::Timeout)
    }

    /// Sends probes for a single hop (TTL value).
    async fn probe_hop(&self, target: Ipv4Addr, ttl: u8) -> Result<HopInfo> {
        use tokio::time::{timeout, sleep};
        use rand::Rng;

        let mut rtts = Vec::with_capacity(self.config.probes_per_hop as usize);
        let mut last_ip: Option<Ipv4Addr> = None;
        let mut last_hostname: Option<String> = None;
        let mut probes_sent = 0;
        let mut probes_received = 0;

        for probe_num in 0..self.config.probes_per_hop {
            let start = std::time::Instant::now();

            match self.send_probe(target, ttl).await {
                Ok(Some(response)) => {
                    let rtt = start.elapsed();
                    rtts.push(rtt);
                    last_ip = Some(response.ip());
                    probes_received += 1;
                }
                Ok(None) => {
                    // Timeout - no response
                }
                Err(_) => {
                    // Error sending probe
                }
            }

            probes_sent += 1;

            // Wait between probes if not the last one
            if probe_num < self.config.probes_per_hop - 1 {
                let wait = if self.config.max_wait > self.config.min_wait {
                    let mut rng = rand::thread_rng();
                    let diff = self.config.max_wait.as_millis() as u64
                        - self.config.min_wait.as_millis() as u64;
                    self.config.min_wait
                        + Duration::from_millis(rng.gen_range(0..=diff))
                } else {
                    self.config.min_wait
                };
                sleep(wait).await;
            }
        }

        // Calculate packet loss
        let loss = if probes_sent > 0 {
            1.0 - (probes_received as f32 / probes_sent as f32)
        } else {
            1.0
        };

        Ok(HopInfo::new(ttl, last_ip, last_hostname, rtts, loss))
    }
'RUSTFIX

# Now write the rest of the file
tail -n +51 /home/greatwallimse/Private/rust-nmap/crates/rustnmap-traceroute/src/lib.rs >> /home/greatwallimse/Private/rust-nmap/crates/rustnmap-traceroute/src/lib_fixed.rs

mv /home/greatwallimse/Private/rust-nmap/crates/rustnmap-traceroute/src/lib.rs /home/greatwallimse/Private/rust-nmap/crates/rustnmap-traceroute/src/lib_broken.rs
mv /home/greatwallimse/Private/rust-nmap/crates/rustnmap-traceroute/src/lib_fixed.rs /home/greatwallimse/Private/rust-nmap/crates/rustnmap-traceroute/src/lib.rs
