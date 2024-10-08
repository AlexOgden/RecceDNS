use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No records found")]
    NoRecordsFound,
    #[error("Network error: {0}")]
    Network(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Protocol error: {0}")]
    ProtocolData(String),
}
