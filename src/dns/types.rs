use std::net::{Ipv4Addr, Ipv6Addr};

use clap::ValueEnum;
use strum_macros::Display;

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

impl QueryType {
    pub const fn from_number(num: u16) -> Self {
        match num {
            1 => Self::A,
            28 => Self::AAAA,
            15 => Self::MX,
            16 => Self::TXT,
            5 => Self::CNAME,
            6 => Self::SOA,
            _ => Self::Any,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Eq, PartialEq, Hash)]
pub enum ResponseType {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    MX(MXResponse),
    TXT(String),
    CNAME(String),
    SOA(SOAResponse),
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
    pub minimum: u32,
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct QueryResponse {
    pub query_type: QueryType,
    pub response_content: ResponseType,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_number_to_enum() {
        assert_eq!(QueryType::from_number(1), QueryType::A);
        assert_eq!(QueryType::from_number(28), QueryType::AAAA);
        assert_eq!(QueryType::from_number(15), QueryType::MX);
        assert_eq!(QueryType::from_number(16), QueryType::TXT);
        assert_eq!(QueryType::from_number(5), QueryType::CNAME);
        assert_eq!(QueryType::from_number(6), QueryType::SOA);
        assert_eq!(QueryType::from_number(3), QueryType::Any);
        assert_eq!(QueryType::from_number(255), QueryType::Any);
    }
}
