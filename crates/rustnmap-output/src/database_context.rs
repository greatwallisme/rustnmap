//! Database context for service, protocol, and RPC lookups.

use std::sync::Arc;

use rustnmap_fingerprint::database::{ProtocolDatabase, RpcDatabase, ServiceDatabase};

/// Context holding optional database references for name lookups.
#[derive(Clone, Default)]
pub struct DatabaseContext {
    pub services: Option<Arc<ServiceDatabase>>,
    pub protocols: Option<Arc<ProtocolDatabase>>,
    pub rpc: Option<Arc<RpcDatabase>>,
}

impl DatabaseContext {
    /// Create empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lookup service name by port and protocol.
    #[must_use]
    pub fn lookup_service(&self, port: u16, protocol: &str) -> Option<&str> {
        self.services.as_ref()?.lookup(port, protocol)
    }

    /// Lookup protocol name by number.
    #[must_use]
    pub fn lookup_protocol(&self, number: u8) -> Option<&str> {
        self.protocols.as_ref()?.lookup(number)
    }

    /// Lookup RPC service name by program number.
    #[must_use]
    pub fn lookup_rpc(&self, number: u32) -> Option<&str> {
        self.rpc.as_ref()?.lookup(number)
    }
}
