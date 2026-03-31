/// Bitcoin protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion(pub u32);

impl ProtocolVersion {
    /// Current protocol version
    pub const CURRENT: ProtocolVersion = ProtocolVersion(70016);

    /// Minimum supported protocol version
    pub const MIN_SUPPORTED: ProtocolVersion = ProtocolVersion(31800);

    /// Version that introduced sendheaders
    pub const SENDHEADERS: ProtocolVersion = ProtocolVersion(70012);

    /// Version that introduced compact blocks
    pub const COMPACT_BLOCKS: ProtocolVersion = ProtocolVersion(70014);

    /// Version that introduced wtxid relay
    pub const WTXID_RELAY: ProtocolVersion = ProtocolVersion(70016);
}

/// Service flags advertised by nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceFlags(pub u64);

impl ServiceFlags {
    pub const NONE: ServiceFlags = ServiceFlags(0);
    pub const NETWORK: ServiceFlags = ServiceFlags(1 << 0);
    pub const GETUTXO: ServiceFlags = ServiceFlags(1 << 1);
    pub const BLOOM: ServiceFlags = ServiceFlags(1 << 2);
    pub const WITNESS: ServiceFlags = ServiceFlags(1 << 3);
    pub const COMPACT_FILTERS: ServiceFlags = ServiceFlags(1 << 6);
    pub const NETWORK_LIMITED: ServiceFlags = ServiceFlags(1 << 10);

    pub fn has(self, flag: ServiceFlags) -> bool {
        self.0 & flag.0 == flag.0
    }
}

/// User agent string for our node
pub const USER_AGENT: &str = "/btc-rust:0.1.0/";
