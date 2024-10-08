use clap::ValueEnum;
use strum_macros::Display;

#[derive(Debug, PartialEq, Eq, Clone, ValueEnum, Display, Hash)]
pub enum TransportProtocol {
    UDP,
    TCP,
}
