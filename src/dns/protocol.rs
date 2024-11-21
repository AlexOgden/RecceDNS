#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::struct_excessive_bools)]

use anyhow::{anyhow, Context, Result};
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

// Structs and their implementations
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
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
    pub domain: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub const fn new(domain: String, qtype: QueryType) -> Self {
        Self { domain, qtype }
    }

    pub fn read(&mut self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.domain)?;
        self.qtype = QueryType::try_from(buffer.read_u16()?)?;
        let _qclass = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.write_qname(&self.domain)?;

        let typenum = self.qtype.clone() as u16;
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub enum DnsRecord {
    A(DnsRecordA),
    AAAA(DnsRecordAAAA),
    MX(DnsRecordMX),
    TXT(DnsRecordTXT),
    CNAME(DnsRecordQNAME),
    SOA(DnsRecordSOA),
    NS(DnsRecordQNAME),
    SRV(DnsRecordSRV),
    DNSKEY(DnsRecordDNSKEY),
}

impl DnsRecord {
    pub fn read(buffer: &mut PacketBuffer) -> Result<DnsQueryResponse> {
        let mut domain = String::new();
        buffer
            .read_qname(&mut domain)
            .context("Failed to read domain name")?;

        let qtype_num = buffer.read_u16().context("Failed to read query type")?;
        let qtype = QueryType::try_from(qtype_num)?;
        let _class = buffer.read_u16().context("Failed to read class")?;
        let ttl = buffer.read_u32().context("Failed to read TTL")?;
        let data_len = buffer.read_u16().context("Failed to read data length")?;

        match qtype {
            QueryType::A => Self::parse_a_record(buffer, domain, ttl),
            QueryType::AAAA => Self::parse_aaaa_record(buffer, domain, ttl),
            QueryType::MX => Self::parse_mx_record(buffer, ttl),
            QueryType::TXT => Self::parse_txt_record(buffer, ttl),
            QueryType::CNAME => Self::parse_cname_record(buffer, ttl),
            QueryType::NS => Self::parse_ns_record(buffer, ttl),
            QueryType::SOA => Self::parse_soa_record(buffer),
            QueryType::SRV => Self::parse_srv_record(buffer),
            QueryType::DNSKEY => Self::parse_dnskey_record(buffer, data_len),
            QueryType::ANY => Err(anyhow!("Unsupported query type {qtype}")),
        }
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            Self::A(DnsRecordA {
                ref domain,
                ref addr,
                ttl,
            }) => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A as u16)?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            _ => unimplemented!(),
        }

        Ok(buffer.pos() - start_pos)
    }

    fn parse_a_record(
        buffer: &mut PacketBuffer,
        domain: String,
        ttl: u32,
    ) -> Result<DnsQueryResponse> {
        let raw_addr = buffer.read_u32()?;
        let addr = Ipv4Addr::new(
            ((raw_addr >> 24) & 0xFF) as u8,
            ((raw_addr >> 16) & 0xFF) as u8,
            ((raw_addr >> 8) & 0xFF) as u8,
            (raw_addr & 0xFF) as u8,
        );

        Ok(DnsQueryResponse {
            query_type: QueryType::A,
            response_content: Self::A(DnsRecordA { ttl, domain, addr }),
        })
    }

    fn parse_aaaa_record(
        buffer: &mut PacketBuffer,
        domain: String,
        ttl: u32,
    ) -> Result<DnsQueryResponse> {
        let raw_addr1 = buffer.read_u32()?;
        let raw_addr2 = buffer.read_u32()?;
        let raw_addr3 = buffer.read_u32()?;
        let raw_addr4 = buffer.read_u32()?;
        let addr = Ipv6Addr::new(
            ((raw_addr1 >> 16) & 0xFFFF) as u16,
            (raw_addr1 & 0xFFFF) as u16,
            ((raw_addr2 >> 16) & 0xFFFF) as u16,
            (raw_addr2 & 0xFFFF) as u16,
            ((raw_addr3 >> 16) & 0xFFFF) as u16,
            (raw_addr3 & 0xFFFF) as u16,
            ((raw_addr4 >> 16) & 0xFFFF) as u16,
            (raw_addr4 & 0xFFFF) as u16,
        );

        Ok(DnsQueryResponse {
            query_type: QueryType::AAAA,
            response_content: Self::AAAA(DnsRecordAAAA { ttl, domain, addr }),
        })
    }

    fn parse_mx_record(buffer: &mut PacketBuffer, ttl: u32) -> Result<DnsQueryResponse> {
        let priority = buffer.read_u16()?;
        let mut mx_domain = String::new();
        buffer.read_qname(&mut mx_domain)?;

        Ok(DnsQueryResponse {
            query_type: QueryType::MX,
            response_content: Self::MX(DnsRecordMX {
                ttl,
                priority,
                domain: mx_domain,
            }),
        })
    }

    fn parse_txt_record(buffer: &mut PacketBuffer, ttl: u32) -> Result<DnsQueryResponse> {
        let mut txt_data = String::new();

        let data_len = buffer.read_u8()?;
        for _ in 0..data_len {
            txt_data.push(buffer.read_u8()? as char);
        }

        Ok(DnsQueryResponse {
            query_type: QueryType::TXT,
            response_content: Self::TXT(DnsRecordTXT {
                ttl,
                data: txt_data,
            }),
        })
    }

    fn parse_cname_record(buffer: &mut PacketBuffer, ttl: u32) -> Result<DnsQueryResponse> {
        let mut cname = String::new();
        buffer.read_qname(&mut cname)?;

        Ok(DnsQueryResponse {
            query_type: QueryType::CNAME,
            response_content: Self::CNAME(DnsRecordTXT { ttl, data: cname }),
        })
    }

    fn parse_ns_record(buffer: &mut PacketBuffer, ttl: u32) -> Result<DnsQueryResponse> {
        let mut ns_domain = String::new();
        buffer.read_qname(&mut ns_domain)?;

        Ok(DnsQueryResponse {
            query_type: QueryType::NS,
            response_content: Self::NS(DnsRecordTXT {
                ttl,
                data: ns_domain,
            }),
        })
    }

    fn parse_soa_record(buffer: &mut PacketBuffer) -> Result<DnsQueryResponse> {
        let mut mname = String::new();
        buffer.read_qname(&mut mname)?;

        let mut rname = String::new();
        buffer.read_qname(&mut rname)?;

        let serial = buffer.read_u32()?;
        let refresh = buffer.read_u32()?;
        let retry = buffer.read_u32()?;
        let expire = buffer.read_u32()?;
        let minimum = buffer.read_u32()?;

        Ok(DnsQueryResponse {
            query_type: QueryType::SOA,
            response_content: Self::SOA(DnsRecordSOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            }),
        })
    }

    fn parse_srv_record(buffer: &mut PacketBuffer) -> Result<DnsQueryResponse> {
        let priority = buffer.read_u16()?;
        let weight = buffer.read_u16()?;
        let port = buffer.read_u16()?;
        let mut target = String::new();
        buffer.read_qname(&mut target)?;

        Ok(DnsQueryResponse {
            query_type: QueryType::SRV,
            response_content: Self::SRV(DnsRecordSRV {
                priority,
                weight,
                port,
                target,
            }),
        })
    }

    fn parse_dnskey_record(buffer: &mut PacketBuffer, data_len: u16) -> Result<DnsQueryResponse> {
        let flags = buffer.read_u16()?;
        let protocol = buffer.read_u8()?;
        let algorithm = buffer.read_u8()?;

        // Read the remaining bytes as the public key
        let public_key = buffer.read_bytes((data_len - 4).into())?;

        Ok(DnsQueryResponse {
            query_type: QueryType::DNSKEY,
            response_content: Self::DNSKEY(DnsRecordDNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            }),
        })
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub struct DnsRecordA {
    pub ttl: u32,
    pub domain: String,
    pub addr: Ipv4Addr,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub struct DnsRecordAAAA {
    pub ttl: u32,
    pub domain: String,
    pub addr: Ipv6Addr,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub struct DnsRecordMX {
    pub ttl: u32,
    pub priority: u16,
    pub domain: String,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub struct DnsRecordSOA {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub struct DnsRecordTXT {
    pub ttl: u32,
    pub data: String,
}

pub type DnsRecordQNAME = DnsRecordTXT;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub struct DnsRecordSRV {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub struct DnsRecordDNSKEY {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize)]
pub struct DnsQueryResponse {
    pub query_type: QueryType,
    pub response_content: DnsRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsQueryResponse>,
    pub authorities: Vec<DnsQueryResponse>,
    pub resources: Vec<DnsQueryResponse>,
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
            let rec = DnsRecord::read(buffer)
                .map_err(|_| DnsError::ProtocolData("Failed to read DNS answer".to_owned()))?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer).map_err(|_| {
                DnsError::ProtocolData("Failed to read DNS authoritative entry".to_owned())
            })?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer).map_err(|_| {
                DnsError::ProtocolData("Failed to read DNS resource entry".to_owned())
            })?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut PacketBuffer) -> Result<(), DnsError> {
        self.header.questions = u16::try_from(self.questions.len()).unwrap_or(0);
        self.header.answers = u16::try_from(self.answers.len()).unwrap_or(0);
        self.header.authoritative_entries = u16::try_from(self.authorities.len()).unwrap_or(0);
        self.header.resource_entries = u16::try_from(self.resources.len()).unwrap_or(0);

        self.header
            .write(buffer)
            .map_err(|_| DnsError::ProtocolData("Failed to write DNS header".to_owned()))?;

        for question in &self.questions {
            question
                .write(buffer)
                .map_err(|_| DnsError::ProtocolData("Failed to write DNS question".to_owned()))?;
        }
        for rec in &self.answers {
            rec.response_content
                .write(buffer)
                .map_err(|_| DnsError::ProtocolData("Failed to write DNS answer".to_owned()))?;
        }
        for rec in &self.authorities {
            rec.response_content.write(buffer).map_err(|_| {
                DnsError::ProtocolData("Failed to write DNS authoritative entry".to_owned())
            })?;
        }
        for rec in &self.resources {
            rec.response_content.write(buffer).map_err(|_| {
                DnsError::ProtocolData("Failed to write DNS resource entry".to_owned())
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_dns_record_read_write() {
        let mut buffer = PacketBuffer::new();
        let record = DnsRecord::A(DnsRecordA {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(127, 0, 0, 1),
            ttl: 3600,
        });

        record.write(&mut buffer).unwrap();
        buffer.set_pos(0).unwrap();
        let read_record = DnsRecord::read(&mut buffer).unwrap();

        assert_eq!(record, read_record.response_content);
    }

    #[test]
    fn test_dns_packet_read_write() {
        let mut buffer = PacketBuffer::new();
        let mut packet = DnsPacket::new();
        packet.header.id = 1234;
        packet
            .questions
            .push(DnsQuestion::new("example.com".to_string(), QueryType::A));
        packet.answers.push(DnsQueryResponse {
            query_type: QueryType::A,
            response_content: DnsRecord::A(DnsRecordA {
                domain: "example.com".to_string(),
                addr: Ipv4Addr::new(127, 0, 0, 1),
                ttl: 3600,
            }),
        });

        packet.write(&mut buffer).unwrap();
        buffer.set_pos(0).unwrap();
        let read_packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        assert_eq!(packet, read_packet);
    }

    // Test reading a DNS packet from a byte array with record type A
    #[test]
    fn test_dns_packet_read_response_a() {
        // Mock DNS response byte array
        let response_bytes: [u8; 45] = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Question section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            // Answer section
            0xc0, 0x0c, // Name (pointer to offset 12)
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x0e, 0x10, // TTL (3600 seconds)
            0x00, 0x04, // Data length
            0x7f, 0x00, 0x00, 0x01, // Address 127.0.0.1
        ];

        let mut buffer = PacketBuffer::new();
        buffer.set_data(&response_bytes).unwrap();
        let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        // Assertions
        assert_eq!(packet.header.id, 0x1234);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.header.answers, 1);
        assert_eq!(packet.header.authoritative_entries, 0);
        assert_eq!(packet.header.resource_entries, 0);

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].domain, "example.com");
        assert_eq!(packet.questions[0].qtype, QueryType::A);

        assert_eq!(packet.answers.len(), 1);
        if let DnsRecord::A(ref a_record) = packet.answers[0].response_content {
            assert_eq!(a_record.domain, "example.com");
            assert_eq!(a_record.addr, Ipv4Addr::new(127, 0, 0, 1));
            assert_eq!(a_record.ttl, 3600);
        } else {
            panic!("Expected A record");
        }
    }

    // Test reading a DNS packet from a byte array with record type AAAA
    #[test]
    fn test_dns_packet_read_response_aaaa() {
        // Mock DNS response byte array with AAAA record
        let response_bytes: [u8; 55] = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Question section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x00, 0x1c, // Type AAAA
            0x00, 0x01, // Class IN
            // Answer section
            0xc0, 0x0c, // Name (pointer to offset 12)
            0x00, 0x1c, // Type AAAA
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x0e, 0x10, // TTL (3600 seconds)
            0x00, 0x10, // Data length
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00,
            0x00, // Address 2001:db8:85a3::8a2e:370:7334
            0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ];

        let mut buffer = PacketBuffer::new();
        buffer.set_data(&response_bytes).unwrap();
        let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        // Assertions
        assert_eq!(packet.header.id, 0x1234);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.header.answers, 1);
        assert_eq!(packet.header.authoritative_entries, 0);
        assert_eq!(packet.header.resource_entries, 0);

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].domain, "example.com");
        assert_eq!(packet.questions[0].qtype, QueryType::AAAA);

        assert_eq!(packet.answers.len(), 1);
        if let DnsRecord::AAAA(ref aaaa_record) = packet.answers[0].response_content {
            assert_eq!(aaaa_record.domain, "example.com");
            assert_eq!(
                aaaa_record.addr,
                Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x8a2e, 0x0370, 0x7334, 0x0000)
            );
            assert_eq!(aaaa_record.ttl, 3600);
        } else {
            panic!("Expected AAAA record");
        }
    }

    // Test reading a DNS packet from a byte array with record type MX
    #[test]
    fn test_dns_packet_read_response_mx() {
        // Mock DNS response byte array with MX record
        let response_bytes: [u8; 50] = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Question section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x00, 0x0f, // Type MX
            0x00, 0x01, // Class IN
            // Answer section
            0xc0, 0x0c, // Name (pointer to offset 12)
            0x00, 0x0f, // Type MX
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x0e, 0x10, // TTL (3600 seconds)
            0x00, 0x11, // Data length
            0x00, 0x0a, // Preference
            0x04, 0x6d, 0x61, 0x69, 0x6c, // "mail"
            0xc0, 0x0c, // Pointer to "example.com"
        ];

        let mut buffer = PacketBuffer::new();
        buffer.set_data(&response_bytes).unwrap();
        let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        // Assertions
        assert_eq!(packet.header.id, 0x1234);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.header.answers, 1);
        assert_eq!(packet.header.authoritative_entries, 0);
        assert_eq!(packet.header.resource_entries, 0);

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].domain, "example.com");
        assert_eq!(packet.questions[0].qtype, QueryType::MX);

        assert_eq!(packet.answers.len(), 1);
        if let DnsRecord::MX(ref mx_record) = packet.answers[0].response_content {
            assert_eq!(mx_record.domain, "mail.example.com");
            assert_eq!(mx_record.priority, 10);
            assert_eq!(mx_record.ttl, 3600);
        } else {
            panic!("Expected MX record");
        }
    }

    // Test reading a DNS packet from a byte array with record type TXT
    #[test]
    fn test_dns_packet_read_response_txt() {
        // Mock DNS response byte array with TXT record
        let response_bytes: [u8; 78] = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Question section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x00, 0x10, // Type TXT
            0x00, 0x01, // Class IN
            // Answer section
            0xc0, 0x0c, // Name (pointer to offset 12)
            0x00, 0x10, // Type TXT
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x0e, 0x10, // TTL (3600 seconds)
            0x00, 0x1c, // Data length (28 bytes)
            0x24, // TXT data length (27 bytes)
            0x76, 0x3d, 0x73, 0x70, 0x66, 0x31, 0x20, 0x69, // "v=spf1 i"
            0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x5f, // "nclude:_"
            0x73, 0x70, 0x66, 0x2e, 0x65, 0x78, 0x61, 0x6d, // "spf.exam"
            0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x20, // "ple.com "
            0x7e, 0x61, 0x6c, 0x6c, // "~all"
        ];

        let mut buffer = PacketBuffer::new();
        buffer.set_data(&response_bytes).unwrap();
        let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        // Assertions
        assert_eq!(packet.header.id, 0x1234);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.header.answers, 1);
        assert_eq!(packet.header.authoritative_entries, 0);
        assert_eq!(packet.header.resource_entries, 0);

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].domain, "example.com");
        assert_eq!(packet.questions[0].qtype, QueryType::TXT);

        assert_eq!(packet.answers.len(), 1);
        if let DnsRecord::TXT(ref txt_record) = packet.answers[0].response_content {
            assert_eq!(txt_record.data, "v=spf1 include:_spf.example.com ~all");
            assert_eq!(txt_record.ttl, 3600);
        } else {
            panic!("Expected TXT record");
        }
    }

    // Test reading a DNS packet from a byte array with record type CNAME
    #[test]
    fn test_dns_packet_read_response_cname() {
        // Mock DNS response byte array with CNAME record
        let response_bytes: [u8; 58] = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Question section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x00, 0x05, // Type CNAME
            0x00, 0x01, // Class IN
            // Answer section
            0xc0, 0x0c, // Name (pointer to offset 12)
            0x00, 0x05, // Type CNAME
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x0e, 0x10, // TTL (3600 seconds)
            0x00, 0x0f, // Data length
            0x03, 0x77, 0x77, 0x77, // "www"
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
        ];

        let mut buffer = PacketBuffer::new();
        buffer.set_data(&response_bytes).unwrap();
        let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        // Assertions
        assert_eq!(packet.header.id, 0x1234);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.header.answers, 1);
        assert_eq!(packet.header.authoritative_entries, 0);
        assert_eq!(packet.header.resource_entries, 0);

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].domain, "example.com");
        assert_eq!(packet.questions[0].qtype, QueryType::CNAME);

        assert_eq!(packet.answers.len(), 1);
        if let DnsRecord::CNAME(ref cname_record) = packet.answers[0].response_content {
            assert_eq!(cname_record.data, "www.example.com");
            assert_eq!(cname_record.ttl, 3600);
        } else {
            panic!("Expected CNAME record");
        }
    }

    // Test reading a DNS packet from a byte array with record type SOA
    #[test]
    fn test_dns_packet_read_response_soa() {
        // Mock DNS response byte array with SOA record
        let response_bytes: [u8; 95] = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Question section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x00, 0x06, // Type SOA
            0x00, 0x01, // Class IN
            // Answer section
            0xc0, 0x0c, // Name (pointer to offset 12)
            0x00, 0x06, // Type SOA
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x0e, 0x10, // TTL (3600 seconds)
            0x00, 0x22, // Data length
            0x03, 0x6e, 0x73, 0x31, // "ns1"
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x03, 0x61, 0x64, 0x6d, // "adm"
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x00, 0x00, 0x00, 0x01, // Serial
            0x00, 0x00, 0x0e, 0x10, // Refresh
            0x00, 0x00, 0x0e, 0x10, // Retry
            0x00, 0x00, 0x0e, 0x10, // Expire
            0x00, 0x00, 0x0e, 0x10, // Minimum
        ];

        let mut buffer = PacketBuffer::new();
        buffer.set_data(&response_bytes).unwrap();
        let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        // Assertions
        assert_eq!(packet.header.id, 0x1234);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.header.answers, 1);
        assert_eq!(packet.header.authoritative_entries, 0);
        assert_eq!(packet.header.resource_entries, 0);

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].domain, "example.com");
        assert_eq!(packet.questions[0].qtype, QueryType::SOA);

        assert_eq!(packet.answers.len(), 1);
        if let DnsRecord::SOA(ref soa_record) = packet.answers[0].response_content {
            assert_eq!(soa_record.mname, "ns1.example.com");
            assert_eq!(soa_record.rname, "adm.example.com");
            assert_eq!(soa_record.serial, 1);
            assert_eq!(soa_record.refresh, 3600);
            assert_eq!(soa_record.retry, 3600);
            assert_eq!(soa_record.expire, 3600);
            assert_eq!(soa_record.minimum, 3600);
        } else {
            panic!("Expected SOA record");
        }
    }

    // Test reading a DNS packet from a byte array with record type NS
    #[test]
    fn test_dns_packet_read_response_ns() {
        // Mock DNS response byte array with NS record
        let response_bytes: [u8; 58] = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Question section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x00, 0x02, // Type NS
            0x00, 0x01, // Class IN
            // Answer section
            0xc0, 0x0c, // Name (pointer to offset 12)
            0x00, 0x02, // Type NS
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x0e, 0x10, // TTL (3600 seconds)
            0x00, 0x0f, // Data length
            0x03, 0x6e, 0x73, 0x31, // "ns1"
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
        ];

        let mut buffer = PacketBuffer::new();
        buffer.set_data(&response_bytes).unwrap();
        let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        // Assertions
        assert_eq!(packet.header.id, 0x1234);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.header.answers, 1);
        assert_eq!(packet.header.authoritative_entries, 0);
        assert_eq!(packet.header.resource_entries, 0);

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].domain, "example.com");
        assert_eq!(packet.questions[0].qtype, QueryType::NS);

        assert_eq!(packet.answers.len(), 1);
        if let DnsRecord::NS(ref ns_record) = packet.answers[0].response_content {
            assert_eq!(ns_record.data, "ns1.example.com");
            assert_eq!(ns_record.ttl, 3600);
        } else {
            panic!("Expected NS record");
        }
    }

    // Test reading a DNS packet from a byte array with record type SRV
    #[test]
    fn test_dns_packet_read_response_srv() {
        // Mock DNS response byte array with SRV record
        let response_bytes: [u8; 64] = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Question section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x00, 0x21, // Type SRV
            0x00, 0x01, // Class IN
            // Answer section
            0xc0, 0x0c, // Name (pointer to offset 12)
            0x00, 0x21, // Type SRV
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x0e, 0x10, // TTL (3600 seconds)
            0x00, 0x15, // Data length
            0x00, 0x05, // Priority
            0x00, 0x0a, // Weight
            0x1f, 0x90, // Port (8080)
            0x03, 0x77, 0x77, 0x77, // "www"
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
        ];

        let mut buffer = PacketBuffer::new();
        buffer.set_data(&response_bytes).unwrap();
        let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        // Assertions
        assert_eq!(packet.header.id, 0x1234);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.header.answers, 1);
        assert_eq!(packet.header.authoritative_entries, 0);
        assert_eq!(packet.header.resource_entries, 0);

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].domain, "example.com");
        assert_eq!(packet.questions[0].qtype, QueryType::SRV);

        assert_eq!(packet.answers.len(), 1);
        if let DnsRecord::SRV(ref srv_record) = packet.answers[0].response_content {
            assert_eq!(srv_record.priority, 5);
            assert_eq!(srv_record.weight, 10);
            assert_eq!(srv_record.port, 8080);
            assert_eq!(srv_record.target, "www.example.com");
        } else {
            panic!("Expected SRV record");
        }
    }

    // Test reading a DNS packet from a byte array with record type DNSKEY
    #[test]
    fn test_dns_packet_read_response_dnskey() {
        // Mock DNS response byte array with DNSKEY record
        let response_bytes: [u8; 77] = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Question section
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, 0x00, // "com"
            0x00, 0x30, // Type DNSKEY
            0x00, 0x01, // Class IN
            // Answer section
            0xc0, 0x0c, // Name (pointer to offset 12)
            0x00, 0x30, // Type DNSKEY
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x0e, 0x10, // TTL (3600 seconds)
            0x00, 0x24, // Data length (36 bytes)
            // DNSKEY data
            0x01, 0x01, // Flags
            0x03, // Protocol
            0x08, // Algorithm (Ed25519)
            // Key (32 bytes)
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xFF,
        ];

        let mut buffer = PacketBuffer::new();
        buffer.set_data(&response_bytes).unwrap();
        let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        // Assertions
        assert_eq!(packet.header.id, 0x1234);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.header.questions, 1);
        assert_eq!(packet.header.answers, 1);
        assert_eq!(packet.header.authoritative_entries, 0);
        assert_eq!(packet.header.resource_entries, 0);

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].domain, "example.com");
        assert_eq!(packet.questions[0].qtype, QueryType::DNSKEY);

        assert_eq!(packet.answers.len(), 1);
        if let DnsRecord::DNSKEY(ref dnskey_record) = packet.answers[0].response_content {
            assert_eq!(dnskey_record.flags, 0x0101);
            assert_eq!(dnskey_record.protocol, 3);
            assert_eq!(dnskey_record.algorithm, 8);
            assert_eq!(
                dnskey_record.public_key,
                [
                    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xFF,
                ]
            );
        } else {
            panic!("Expected DNSKEY record");
        }
    }
}
