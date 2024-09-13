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
    #[strum(to_string = "SOA")]
    SOA,
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
    CNAME(String),
    SOA(SOAResponse)
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct MXResponse {
    pub priority: u16,
    pub domain: String,
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct SOAResponse {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct QueryResponse {
    pub query_type: QueryType,
    pub response_content: ResponseType,
}