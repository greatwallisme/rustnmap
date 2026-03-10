//! Database context for protocol and RPC lookups.
//!
//! Service name lookups use `rustnmap_common::ServiceDatabase::global()` instead.

use std::sync::Arc;

use rustnmap_fingerprint::database::{ProtocolDatabase, RpcDatabase};

/// Context holding optional database references for name lookups.
///
/// Note: Service names are looked up using `rustnmap_common::ServiceDatabase::global()`
/// rather than being stored in this context.
#[derive(Clone, Default)]
pub struct DatabaseContext {
    pub protocols: Option<Arc<ProtocolDatabase>>,
    pub rpc: Option<Arc<RpcDatabase>>,
}

impl DatabaseContext {
    /// Create empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
