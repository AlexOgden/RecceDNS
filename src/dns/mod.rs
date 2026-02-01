pub mod async_resolver;
pub mod error;
pub mod format;
pub mod protocol;
pub mod resolver_selector;

/// Default DNS port used when none is specified
pub const DEFAULT_DNS_PORT: u16 = 53;
