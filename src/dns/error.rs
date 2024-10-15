use thiserror::Error;

#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum DnsError {
    #[error("No records found")]
    NoRecordsFound,
    #[error("Network error: {0}")]
    Network(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Protocol error: {0}")]
    ProtocolData(String),
}
