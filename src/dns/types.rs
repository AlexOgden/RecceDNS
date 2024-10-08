#![allow(clippy::upper_case_acronyms)]

use clap::ValueEnum;
use std::net::{Ipv4Addr, Ipv6Addr};
use strum_macros::Display;

#[derive(Debug, PartialEq, Eq, Clone, ValueEnum, Display, Hash, PartialOrd, Ord)]
pub enum QueryType {
    #[strum(to_string = "A")]
    A = 1,
    #[strum(to_string = "AAAA")]
    AAAA = 28,
    #[strum(to_string = "MX")]
    MX = 15,
    #[strum(to_string = "TXT")]
    TXT = 16,
    #[strum(to_string = "CNAME")]
    CNAME = 5,
    #[strum(to_string = "SOA")]
    SOA = 6,
    #[strum(to_string = "NS")]
    NS = 2,
    #[strum(to_string = "any")]
    Any = 0,
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
            2 => Self::NS,
            _ => Self::Any,
        }
    }

    pub const fn to_number(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::AAAA => 28,
            Self::MX => 15,
            Self::TXT => 16,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::NS => 2,
            Self::Any => 0,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub enum ResponseType {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    MX(MXResponse),
    TXT(String),
    CNAME(String),
    SOA(SOAResponse),
    NS(String),
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
        assert_eq!(QueryType::from_number(2), QueryType::NS);
        assert_eq!(QueryType::from_number(3), QueryType::Any);
        assert_eq!(QueryType::from_number(255), QueryType::Any);
    }

    #[test]
    fn test_to_number() {
        assert_eq!(QueryType::A.to_number(), 1);
        assert_eq!(QueryType::AAAA.to_number(), 28);
        assert_eq!(QueryType::MX.to_number(), 15);
        assert_eq!(QueryType::TXT.to_number(), 16);
        assert_eq!(QueryType::CNAME.to_number(), 5);
        assert_eq!(QueryType::SOA.to_number(), 6);
        assert_eq!(QueryType::NS.to_number(), 2);
        assert_eq!(QueryType::Any.to_number(), 0);
    }
}
