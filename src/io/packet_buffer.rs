#![allow(dead_code)]

use anyhow::{anyhow, Ok, Result};

pub struct PacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl PacketBuffer {
    pub const fn new() -> Self {
        Self {
            buf: [0; 512],
            pos: 0,
        }
    }

    pub fn get_buffer_to_pos(&self) -> &[u8] {
        &self.buf[0..self.pos]
    }

    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > 512 {
            return Err(anyhow!("Data too large"));
        }

        self.buf[..data.len()].copy_from_slice(data);
        self.pos = 0;

        Ok(())
    }

    pub const fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    pub fn set_pos(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err(anyhow!("End of buffer"));
        }
        let result: u8 = self.buf[self.pos];
        self.pos += 1;

        Ok(result)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        if self.pos + 1 >= 512 {
            return Err(anyhow!("End of buffer"));
        }
        let result: u16 = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;

        Ok(result)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 3 >= 512 {
            return Err(anyhow!("End of buffer"));
        }
        let result: u32 = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;

        Ok(result)
    }

    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";
        loop {
            // Set max jumps to 5 to prevent infinite loops DoS attacks
            if jumps_performed > max_jumps {
                return Err(anyhow!("Limit of {max_jumps} jumps exceeded"));
            }

            let len = self.get_byte(pos)?;

            // If len has the two most significant bit are set, there is a compression jump
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current label
                if !jumped {
                    self.set_pos(pos + 2)?;
                }

                let b2 = self.get_byte(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // Move a single byte forward to move past the length byte.
            pos += 1;

            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let str_buffer = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            // Move forward the full length of the label.
            pos += len as usize;
        }

        if !jumped {
            self.set_pos(pos)?;
        }

        Ok(())
    }

    pub fn get_byte(&self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err(anyhow!("End of buffer"));
        }
        Ok(self.buf[pos])
    }

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err(anyhow!("End of buffer"));
        }
        Ok(&self.buf[start..start + len])
    }

    pub fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(anyhow!("End of buffer"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_qname(&mut self, domain: &str) -> Result<()> {
        for part in domain.split('.') {
            let q_length = u8::try_from(part.len()).map_err(|_| anyhow!("Domain part too long"))?;
            self.write_u8(q_length)?;
            for byte in part.bytes() {
                self.write_u8(byte)?;
            }
        }
        // Terminate the domain name
        self.write_u8(0)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let buffer = PacketBuffer::new();
        assert_eq!(buffer.pos, 0);
        assert_eq!(buffer.buf.len(), 512);
    }

    #[test]
    fn test_set_data() {
        let mut buffer = PacketBuffer::new();
        let data = [1, 2, 3, 4, 5];
        buffer.set_data(&data).unwrap();
        assert_eq!(&buffer.buf[0..5], &data);
        assert_eq!(buffer.pos, 0);
    }

    #[test]
    fn test_read_u8() {
        let mut buffer = PacketBuffer::new();
        buffer.set_data(&[1, 2, 3]).unwrap();
        assert_eq!(buffer.read_u8().unwrap(), 1);
        assert_eq!(buffer.read_u8().unwrap(), 2);
        assert_eq!(buffer.read_u8().unwrap(), 3);
    }

    #[test]
    fn test_read_u16() {
        let mut buffer = PacketBuffer::new();
        buffer.set_data(&[0x12, 0x34]).unwrap();
        assert_eq!(buffer.read_u16().unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u32() {
        let mut buffer = PacketBuffer::new();
        buffer.set_data(&[0x12, 0x34, 0x56, 0x78]).unwrap();
        assert_eq!(buffer.read_u32().unwrap(), 0x1234_5678);
    }

    #[test]
    fn test_write_u8() {
        let mut buffer = PacketBuffer::new();
        buffer.write_u8(0x12).unwrap();
        assert_eq!(buffer.buf[0], 0x12);
    }

    #[test]
    fn test_write_u16() {
        let mut buffer = PacketBuffer::new();
        buffer.write_u16(0x1234).unwrap();
        assert_eq!(buffer.buf[0], 0x12);
        assert_eq!(buffer.buf[1], 0x34);
    }

    #[test]
    fn test_write_u32() {
        let mut buffer = PacketBuffer::new();
        buffer.write_u32(0x1234_5678).unwrap();
        assert_eq!(buffer.buf[0], 0x12);
        assert_eq!(buffer.buf[1], 0x34);
        assert_eq!(buffer.buf[2], 0x56);
        assert_eq!(buffer.buf[3], 0x78);
    }

    #[test]
    fn test_write_qname() {
        let mut buffer = PacketBuffer::new();
        buffer.write_qname("example.com").unwrap();
        assert_eq!(buffer.buf[0], 7); // length of "example"
        assert_eq!(&buffer.buf[1..8], b"example");
        assert_eq!(buffer.buf[8], 3); // length of "com"
        assert_eq!(&buffer.buf[9..12], b"com");
        assert_eq!(buffer.buf[12], 0); // null terminator
    }

    #[test]
    fn test_read_qname() {
        let mut buffer = PacketBuffer::new();
        buffer.write_qname("example.com").unwrap();
        buffer.set_pos(0).unwrap();
        let mut outstr = String::new();
        buffer.read_qname(&mut outstr).unwrap();
        assert_eq!(outstr, "example.com");
    }

    #[test]
    fn test_step() {
        let mut buffer = PacketBuffer::new();
        buffer.step(5).unwrap();
        assert_eq!(buffer.pos, 5);
    }

    #[test]
    fn test_set_pos() {
        let mut buffer = PacketBuffer::new();
        buffer.set_pos(10).unwrap();
        assert_eq!(buffer.pos, 10);
    }

    #[test]
    fn test_get_buffer_to_pos() {
        let mut buffer = PacketBuffer::new();
        buffer.set_data(&[1, 2, 3, 4, 5]).unwrap();
        buffer.set_pos(3).unwrap();
        assert_eq!(buffer.get_buffer_to_pos(), &[1, 2, 3]);
    }
}
