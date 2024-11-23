#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]

use anyhow::Result;
use clap::ValueEnum;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use strum_macros::Display;

use crate::io::packet_buffer::PacketBuffer;

use super::error::DnsError;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    ValueEnum,
    Display,
    Hash,
    PartialOrd,
    Ord,
    IntoPrimitive,
    TryFromPrimitive,
    Serialize,
)]
#[repr(u16)]
pub enum QueryType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    DNSKEY = 48,
    PTR = 12,
    ANY = 255,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, IntoPrimitive, TryFromPrimitive, Serialize)]
#[repr(u8)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsHeader {
    pub id: u16,

    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub response: bool,

    pub rescode: ResultCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,

    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl DnsHeader {
    pub const fn new() -> Self {
        Self {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut PacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::try_from(b & 0x0F)?;
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7),
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub qclass: u16,
}

impl DnsQuestion {
    pub const fn new(name: String, qtype: QueryType) -> Self {
        Self {
            name,
            qtype,
            qclass: 1,
        }
    }

    pub fn read(&mut self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::try_from(buffer.read_u16()?)?;
        self.qclass = buffer.read_u16()?;
        Ok(())
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.qtype.clone() as u16)?;
        buffer.write_u16(self.qclass)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Hash)]
pub struct ResourceRecord {
    pub name: String,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

impl ResourceRecord {
    pub fn read(buffer: &mut PacketBuffer) -> Result<Self> {
        let mut name = String::new();
        buffer.read_qname(&mut name)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::try_from(qtype_num)?;
        let class = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()? as usize;

        let data = match qtype {
            QueryType::A => {
                let ip_raw = buffer.read_u32()?;
                let ip = Ipv4Addr::from(ip_raw);
                RData::A(ip)
            }
            QueryType::AAAA => {
                let mut segments = [0u16; 8];
                for segment in &mut segments {
                    *segment = buffer.read_u16()?;
                }
                let ip = Ipv6Addr::from(segments);
                RData::AAAA(ip)
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;
                RData::NS(ns)
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;
                RData::CNAME(cname)
            }
            QueryType::MX => {
                let preference = buffer.read_u16()?;
                let mut exchange = String::new();
                buffer.read_qname(&mut exchange)?;
                RData::MX {
                    preference,
                    exchange,
                }
            }
            QueryType::TXT => {
                let txt_len = buffer.read_u8()? as usize;
                let mut txt_data = String::new();

                for _ in 0..txt_len {
                    txt_data.push(buffer.read_u8()? as char);
                }
                RData::TXT(txt_data)
            }
            QueryType::SOA => {
                let mut mname = String::new();
                buffer.read_qname(&mut mname)?;
                let mut rname = String::new();
                buffer.read_qname(&mut rname)?;
                let serial = buffer.read_u32()?;
                let refresh = buffer.read_u32()?;
                let retry = buffer.read_u32()?;
                let expire = buffer.read_u32()?;
                let minimum = buffer.read_u32()?;
                RData::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }
            QueryType::SRV => {
                let priority = buffer.read_u16()?;
                let weight = buffer.read_u16()?;
                let port = buffer.read_u16()?;
                let mut target = String::new();
                buffer.read_qname(&mut target)?;
                RData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            QueryType::DNSKEY => {
                let flags = buffer.read_u16()?;
                let protocol = buffer.read_u8()?;
                let algorithm = buffer.read_u8()?;
                let key_len = data_len - 4;
                let public_key = buffer.read_bytes(key_len)?;
                RData::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                }
            }
            QueryType::PTR => {
                let mut ptr = String::new();
                buffer.read_qname(&mut ptr)?;
                RData::PTR(ptr)
            }
            QueryType::ANY => {
                buffer.step(data_len)?;
                RData::Unknown { qtype, data_len }
            }
        };

        Ok(Self {
            name,
            class,
            ttl,
            data,
        })
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.data.to_qtype() as u16)?;
        buffer.write_u16(self.class)?;
        buffer.write_u32(self.ttl)?;

        // Placeholder for the length
        let length_pos = buffer.pos();
        buffer.write_u16(0)?;

        let start_pos = buffer.pos();
        match &self.data {
            RData::A(ip) => {
                buffer.write_u32(u32::from(*ip))?;
            }
            RData::AAAA(ip) => {
                for segment in &ip.segments() {
                    buffer.write_u16(*segment)?;
                }
            }
            RData::NS(ns) | RData::CNAME(ns) => {
                buffer.write_qname(ns)?;
            }
            RData::MX {
                preference,
                exchange,
            } => {
                buffer.write_u16(*preference)?;
                buffer.write_qname(exchange)?;
            }
            RData::TXT(txt) => {
                buffer.write_u8(u8::try_from(txt.len())?)?;
                for byte in txt.as_bytes() {
                    buffer.write_u8(*byte)?;
                }
            }
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                buffer.write_qname(mname)?;
                buffer.write_qname(rname)?;
                buffer.write_u32(*serial)?;
                buffer.write_u32(*refresh)?;
                buffer.write_u32(*retry)?;
                buffer.write_u32(*expire)?;
                buffer.write_u32(*minimum)?;
            }
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                buffer.write_u16(*priority)?;
                buffer.write_u16(*weight)?;
                buffer.write_u16(*port)?;
                buffer.write_qname(target)?;
            }
            RData::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                buffer.write_u16(*flags)?;
                buffer.write_u8(*protocol)?;
                buffer.write_u8(*algorithm)?;
                for byte in public_key {
                    buffer.write_u8(*byte)?;
                }
            }
            RData::PTR(ptr) => {
                buffer.write_qname(ptr)?;
            }
            RData::Unknown { data_len, .. } => {
                for _ in 0..*data_len {
                    buffer.write_u8(0)?;
                }
            }
        }

        let end_pos = buffer.pos();
        let size = u16::try_from(end_pos - start_pos)?;

        buffer.set_u16(length_pos, size)?;

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Hash)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(String),
    CNAME(String),
    MX {
        preference: u16,
        exchange: String,
    },
    TXT(String),
    PTR(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    Unknown {
        qtype: QueryType,
        data_len: usize,
    },
}

impl RData {
    pub fn to_qtype(&self) -> QueryType {
        match self {
            Self::A(_) => QueryType::A,
            Self::AAAA(_) => QueryType::AAAA,
            Self::NS(_) => QueryType::NS,
            Self::CNAME(_) => QueryType::CNAME,
            Self::MX { .. } => QueryType::MX,
            Self::TXT(_) => QueryType::TXT,
            Self::SOA { .. } => QueryType::SOA,
            Self::SRV { .. } => QueryType::SRV,
            Self::DNSKEY { .. } => QueryType::DNSKEY,
            Self::PTR(_) => QueryType::PTR,
            Self::Unknown { qtype, .. } => qtype.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub resources: Vec<ResourceRecord>,
}

impl DnsPacket {
    pub const fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut PacketBuffer) -> Result<Self, DnsError> {
        let mut result = Self::new();
        result
            .header
            .read(buffer)
            .map_err(|_| DnsError::ProtocolData("Failed to read DNS header".to_owned()))?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new(String::new(), QueryType::ANY);
            question
                .read(buffer)
                .map_err(|_| DnsError::ProtocolData("Failed to read DNS question".to_owned()))?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = ResourceRecord::read(buffer)
                .map_err(|_| DnsError::ProtocolData("Failed to read DNS answer".to_owned()))?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = ResourceRecord::read(buffer).map_err(|_| {
                DnsError::ProtocolData("Failed to read DNS authoritive entry".to_owned())
            })?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = ResourceRecord::read(buffer).map_err(|_| {
                DnsError::ProtocolData("Failed to read DNS resource entry".to_owned())
            })?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write(&mut self, buffer: &mut PacketBuffer) -> Result<(), DnsError> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header
            .write(buffer)
            .map_err(|_| DnsError::ProtocolData("Failed to write DNS header".to_owned()))?;

        for question in &self.questions {
            question
                .write(buffer)
                .map_err(|_| DnsError::ProtocolData("Failed to write DNS question".to_owned()))?;
        }
        for rec in &self.answers {
            rec.write(buffer)
                .map_err(|_| DnsError::ProtocolData("Failed to write DNS answer".to_owned()))?;
        }
        for rec in &self.authorities {
            rec.write(buffer)
                .map_err(|_| DnsError::ProtocolData("Failed to write DNS authority".to_owned()))?;
        }
        for rec in &self.resources {
            rec.write(buffer)
                .map_err(|_| DnsError::ProtocolData("Failed to write DNS resources".to_owned()))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::packet_buffer::PacketBuffer;

    #[test]
    fn test_query_type_from_number() {
        assert_eq!(QueryType::try_from(1_u16).unwrap(), QueryType::A);
        assert_eq!(QueryType::try_from(28_u16).unwrap(), QueryType::AAAA);
        assert_eq!(QueryType::try_from(15_u16).unwrap(), QueryType::MX);
        assert_eq!(QueryType::try_from(16_u16).unwrap(), QueryType::TXT);
        assert_eq!(QueryType::try_from(5_u16).unwrap(), QueryType::CNAME);
        assert_eq!(QueryType::try_from(6_u16).unwrap(), QueryType::SOA);
        assert_eq!(QueryType::try_from(2_u16).unwrap(), QueryType::NS);
        assert_eq!(QueryType::try_from(33_u16).unwrap(), QueryType::SRV);
        assert_eq!(QueryType::try_from(48_u16).unwrap(), QueryType::DNSKEY);
        assert_eq!(QueryType::try_from(12_u16).unwrap(), QueryType::PTR);
        assert_eq!(QueryType::try_from(255_u16).unwrap(), QueryType::ANY);
    }

    #[test]
    fn test_query_type_to_number() {
        assert_eq!(QueryType::A as u16, 1);
        assert_eq!(QueryType::NS as u16, 2);
        assert_eq!(QueryType::CNAME as u16, 5);
        assert_eq!(QueryType::SOA as u16, 6);
        assert_eq!(QueryType::MX as u16, 15);
        assert_eq!(QueryType::TXT as u16, 16);
        assert_eq!(QueryType::AAAA as u16, 28);
        assert_eq!(QueryType::SRV as u16, 33);
        assert_eq!(QueryType::DNSKEY as u16, 48);
        assert_eq!(QueryType::PTR as u16, 12);
        assert_eq!(QueryType::ANY as u16, 255);
    }

    #[test]
    fn test_result_code_from_number() {
        assert_eq!(ResultCode::try_from(0).unwrap(), ResultCode::NOERROR);
        assert_eq!(ResultCode::try_from(1).unwrap(), ResultCode::FORMERR);
        assert_eq!(ResultCode::try_from(2).unwrap(), ResultCode::SERVFAIL);
        assert_eq!(ResultCode::try_from(3).unwrap(), ResultCode::NXDOMAIN);
        assert_eq!(ResultCode::try_from(4).unwrap(), ResultCode::NOTIMP);
        assert_eq!(ResultCode::try_from(5).unwrap(), ResultCode::REFUSED);
    }

    #[test]
    fn test_result_code_to_number() {
        assert_eq!(ResultCode::NOERROR as u8, 0);
        assert_eq!(ResultCode::FORMERR as u8, 1);
        assert_eq!(ResultCode::SERVFAIL as u8, 2);
        assert_eq!(ResultCode::NXDOMAIN as u8, 3);
        assert_eq!(ResultCode::NOTIMP as u8, 4);
        assert_eq!(ResultCode::REFUSED as u8, 5);
    }

    #[test]
    fn test_dns_header_read_write() {
        let mut buffer = PacketBuffer::new();
        let mut header = DnsHeader::new();
        header.id = 1234;
        header.recursion_desired = true;
        header.questions = 1;
        header.answers = 2;
        header.authoritative_entries = 3;
        header.resource_entries = 4;

        header.write(&mut buffer).unwrap();
        buffer.set_pos(0).unwrap();
        let mut read_header = DnsHeader::new();
        read_header.read(&mut buffer).unwrap();

        assert_eq!(header, read_header);
    }

    #[test]
    fn test_dns_question_read_write() {
        let mut buffer = PacketBuffer::new();
        let question = DnsQuestion::new("example.com".to_string(), QueryType::A);

        question.write(&mut buffer).unwrap();
        buffer.set_pos(0).unwrap();
        let mut read_question = DnsQuestion::new(String::new(), QueryType::A);
        read_question.read(&mut buffer).unwrap();

        assert_eq!(question, read_question);
    }

    #[test]
    fn test_resource_record_read_write() {
        let mut buffer = PacketBuffer::new();
        let record = ResourceRecord {
            name: "example.com".to_string(),
            class: 1,
            ttl: 3600,
            data: RData::A(Ipv4Addr::new(127, 0, 0, 1)),
        };

        record.write(&mut buffer).unwrap();
        buffer.set_pos(0).unwrap();
        let read_record = ResourceRecord::read(&mut buffer).unwrap();

        assert_eq!(record, read_record);
    }

    #[test]
    fn test_dns_packet_read_write() {
        let mut buffer = PacketBuffer::new();
        let mut packet = DnsPacket::new();
        packet.header.id = 1234;
        packet
            .questions
            .push(DnsQuestion::new("example.com".to_string(), QueryType::A));
        packet.answers.push(ResourceRecord {
            name: "example.com".to_string(),
            class: 1,
            ttl: 3600,
            data: RData::A(Ipv4Addr::new(127, 0, 0, 1)),
        });

        packet.write(&mut buffer).unwrap();
        buffer.set_pos(0).unwrap();
        let read_packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        assert_eq!(packet, read_packet);
    }
}
