use clap::ValueEnum;
use strum_macros::Display;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Clone, ValueEnum, Display, Hash)]
pub enum TransportProtocol {
    UDP,
    TCP,
}
