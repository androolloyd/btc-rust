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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_current() {
        assert_eq!(ProtocolVersion::CURRENT.0, 70016);
    }

    #[test]
    fn test_protocol_version_min_supported() {
        assert_eq!(ProtocolVersion::MIN_SUPPORTED.0, 31800);
    }

    #[test]
    fn test_protocol_version_sendheaders() {
        assert_eq!(ProtocolVersion::SENDHEADERS.0, 70012);
    }

    #[test]
    fn test_protocol_version_compact_blocks() {
        assert_eq!(ProtocolVersion::COMPACT_BLOCKS.0, 70014);
    }

    #[test]
    fn test_protocol_version_wtxid_relay() {
        assert_eq!(ProtocolVersion::WTXID_RELAY.0, 70016);
    }

    #[test]
    fn test_protocol_version_ordering() {
        assert!(ProtocolVersion::MIN_SUPPORTED < ProtocolVersion::SENDHEADERS);
        assert!(ProtocolVersion::SENDHEADERS < ProtocolVersion::COMPACT_BLOCKS);
        assert!(ProtocolVersion::COMPACT_BLOCKS < ProtocolVersion::WTXID_RELAY);
    }

    #[test]
    fn test_protocol_version_equality() {
        assert_eq!(ProtocolVersion::CURRENT, ProtocolVersion::WTXID_RELAY);
        assert_ne!(ProtocolVersion::CURRENT, ProtocolVersion::MIN_SUPPORTED);
    }

    #[test]
    fn test_protocol_version_copy() {
        let v = ProtocolVersion::CURRENT;
        let copy = v;
        assert_eq!(v, copy);
    }

    #[test]
    fn test_service_flags_none() {
        assert_eq!(ServiceFlags::NONE.0, 0);
    }

    #[test]
    fn test_service_flags_network() {
        assert_eq!(ServiceFlags::NETWORK.0, 1);
    }

    #[test]
    fn test_service_flags_getutxo() {
        assert_eq!(ServiceFlags::GETUTXO.0, 2);
    }

    #[test]
    fn test_service_flags_bloom() {
        assert_eq!(ServiceFlags::BLOOM.0, 4);
    }

    #[test]
    fn test_service_flags_witness() {
        assert_eq!(ServiceFlags::WITNESS.0, 8);
    }

    #[test]
    fn test_service_flags_compact_filters() {
        assert_eq!(ServiceFlags::COMPACT_FILTERS.0, 64);
    }

    #[test]
    fn test_service_flags_network_limited() {
        assert_eq!(ServiceFlags::NETWORK_LIMITED.0, 1024);
    }

    #[test]
    fn test_service_flags_has() {
        let flags = ServiceFlags(ServiceFlags::NETWORK.0 | ServiceFlags::WITNESS.0);
        assert!(flags.has(ServiceFlags::NETWORK));
        assert!(flags.has(ServiceFlags::WITNESS));
        assert!(!flags.has(ServiceFlags::BLOOM));
        assert!(!flags.has(ServiceFlags::GETUTXO));
    }

    #[test]
    fn test_service_flags_has_none() {
        let flags = ServiceFlags::NONE;
        assert!(flags.has(ServiceFlags::NONE));
        assert!(!flags.has(ServiceFlags::NETWORK));
    }

    #[test]
    fn test_service_flags_has_all_combined() {
        let all = ServiceFlags(
            ServiceFlags::NETWORK.0
                | ServiceFlags::GETUTXO.0
                | ServiceFlags::BLOOM.0
                | ServiceFlags::WITNESS.0
                | ServiceFlags::COMPACT_FILTERS.0
                | ServiceFlags::NETWORK_LIMITED.0,
        );
        assert!(all.has(ServiceFlags::NETWORK));
        assert!(all.has(ServiceFlags::GETUTXO));
        assert!(all.has(ServiceFlags::BLOOM));
        assert!(all.has(ServiceFlags::WITNESS));
        assert!(all.has(ServiceFlags::COMPACT_FILTERS));
        assert!(all.has(ServiceFlags::NETWORK_LIMITED));
    }

    #[test]
    fn test_user_agent() {
        assert_eq!(USER_AGENT, "/btc-rust:0.1.0/");
        assert!(USER_AGENT.starts_with('/'));
        assert!(USER_AGENT.ends_with('/'));
    }
}
