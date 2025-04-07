use thiserror::Error;

#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug, PartialEq, Eq, Hash)]
pub enum DnsError {
    #[error("No records found")]
    NoRecordsFound,
    #[error("None existent domain")]
    NonExistentDomain,
    #[error("Nameserver Error: {0}")]
    Nameserver(String),
    #[error("Network Error: {0}")]
    Network(String),
    #[error("Invalid Data: {0}")]
    InvalidData(String),
    #[error("Protocol Error: {0}")]
    ProtocolData(String),
    #[error("Internal Error: {0}")]
    Internal(String),
    #[error("Connection Timeout")]
    Timeout,
}
