use std::net::{Ipv4Addr, Ipv6Addr};

use strum_macros::Display;
use clap::ValueEnum;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Clone, ValueEnum, Display, Hash)]
pub enum QueryType {
    #[strum(to_string = "A")]
    A,
    #[strum(to_string = "AAAA")]
    AAAA,
    #[strum(to_string = "MX")]
    MX,
	#[strum(to_string = "TXT")]
    TXT,
    #[strum(to_string = "CNAME")]
    CNAME,
    #[strum(to_string = "any")]
    Any,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Eq, PartialEq, Hash)]
pub enum ResponseType {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    MX(MXResponse),
	TXT(String),
    CanonicalName(String),
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct MXResponse {
    pub priority: u16,
    pub domain: String,
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct QueryResponse {
    pub query_type: QueryType,
    pub response_content: ResponseType,
}