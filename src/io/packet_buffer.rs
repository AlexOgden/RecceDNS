#![allow(dead_code)]

use anyhow::{Result, anyhow};

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

    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let mut buffer = Self::new();
        buffer.set_data(data)?;
        Ok(buffer)
    }

    pub fn get_buffer_to_pos(&self) -> &[u8] {
        &self.buf[0..self.pos]
    }

    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.buf.len() {
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
        let new_pos = self
            .pos
            .checked_add(steps)
            .ok_or_else(|| anyhow!("Position overflow"))?;
        if new_pos > self.buf.len() {
            return Err(anyhow!("End of buffer"));
        }
        self.pos = new_pos;

        Ok(())
    }

    pub fn set_pos(&mut self, pos: usize) -> Result<()> {
        if pos > self.buf.len() {
            return Err(anyhow!("Position out of bounds"));
        }
        self.pos = pos;

        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        if pos + 1 >= self.buf.len() {
            return Err(anyhow!("Position out of bounds"));
        }
        self.buf[pos] = (val >> 8) as u8;
        self.buf[pos + 1] = u8::try_from(val)?;
        Ok(())
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(anyhow!("End of buffer"));
        }
        let result = self.buf[self.pos];
        self.pos += 1;

        Ok(result)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let new_pos = self
            .pos
            .checked_add(1)
            .ok_or_else(|| anyhow!("Position overflow"))?;
        if new_pos >= self.buf.len() {
            return Err(anyhow!("End of buffer"));
        }
        let result = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;

        Ok(result)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let new_pos = self
            .pos
            .checked_add(3)
            .ok_or_else(|| anyhow!("Position overflow"))?;
        if new_pos >= self.buf.len() {
            return Err(anyhow!("End of buffer"));
        }
        let result = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;

        Ok(result)
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        let new_pos = self
            .pos
            .checked_add(len)
            .ok_or_else(|| anyhow!("Position overflow"))?;
        if new_pos > self.buf.len() {
            return Err(anyhow!("End of buffer"));
        }
        let result = self.buf[self.pos..new_pos].to_vec();
        self.pos = new_pos;

        Ok(result)
    }

    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";
        loop {
            if jumps_performed > max_jumps {
                return Err(anyhow!("Limit of {max_jumps} jumps exceeded"));
            }

            let len = self.get_byte(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.set_pos(pos + 2)?;
                }

                let b2 = self.get_byte(pos + 1)? as u16;
                let offset = (((len as u16) & 0x3F) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            }
            pos += 1;

            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let label_bytes = self.get_range(pos, len as usize)?;
            for &b in label_bytes {
                outstr.push((b as char).to_ascii_lowercase());
            }

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.set_pos(pos)?;
        }

        Ok(())
    }

    pub fn get_byte(&self, pos: usize) -> Result<u8> {
        if pos >= self.buf.len() {
            return Err(anyhow!("End of buffer"));
        }
        Ok(self.buf[pos])
    }

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| anyhow!("Range overflow"))?;
        if end > self.buf.len() {
            return Err(anyhow!("End of buffer"));
        }
        Ok(&self.buf[start..end])
    }

    pub fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= self.buf.len() {
            return Err(anyhow!("End of buffer"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)
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
            if part.len() > 63 {
                return Err(anyhow!("Domain part too long"));
            }
            let q_length = u8::try_from(part.len()).map_err(|_| anyhow!("Domain part too long"))?;
            self.write_u8(q_length)?;
            for &byte in part.as_bytes() {
                self.write_u8(byte)?;
            }
        }
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
    fn test_set_data_too_large() {
        let mut buffer = PacketBuffer::new();
        let data = [0u8; 513];
        assert!(buffer.set_data(&data).is_err());
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
    fn test_read_u8_out_of_bounds() {
        let mut buffer = PacketBuffer::new();
        buffer.set_data(&[1, 2]).unwrap();
        let _ = buffer.step(513);
        assert!(buffer.read_u8().is_ok());
    }

    #[test]
    fn test_read_u16() {
        let mut buffer = PacketBuffer::new();
        buffer.set_data(&[0x12, 0x34]).unwrap();
        assert_eq!(buffer.read_u16().unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u16_out_of_bounds() {
        let mut buffer = PacketBuffer::new();
        buffer.set_data(&[0x12]).unwrap();
        let _ = buffer.step(511);
        assert!(buffer.read_u16().is_err());
    }

    #[test]
    fn test_read_u32() {
        let mut buffer = PacketBuffer::new();
        buffer.set_data(&[0x12, 0x34, 0x56, 0x78]).unwrap();
        assert_eq!(buffer.read_u32().unwrap(), 0x1234_5678);
    }

    #[test]
    fn test_read_u32_out_of_bounds() {
        let mut buffer = PacketBuffer::new();
        buffer.set_data(&[0x12, 0x34, 0x56]).unwrap();
        let _ = buffer.step(509);
        assert!(buffer.read_u32().is_err());
    }

    #[test]
    fn test_write_u8() {
        let mut buffer = PacketBuffer::new();
        buffer.write_u8(0x12).unwrap();
        assert_eq!(buffer.buf[0], 0x12);
    }

    #[test]
    fn test_write_u8_out_of_bounds() {
        let mut buffer = PacketBuffer::new();
        buffer.set_pos(512).unwrap();
        assert!(buffer.write_u8(0x12).is_err());
    }

    #[test]
    fn test_write_u16() {
        let mut buffer = PacketBuffer::new();
        buffer.write_u16(0x1234).unwrap();
        assert_eq!(buffer.buf[0], 0x12);
        assert_eq!(buffer.buf[1], 0x34);
    }

    #[test]
    fn test_write_u16_out_of_bounds() {
        let mut buffer = PacketBuffer::new();
        buffer.set_pos(511).unwrap();
        assert!(buffer.write_u16(0x1234).is_err());
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
    fn test_write_u32_out_of_bounds() {
        let mut buffer = PacketBuffer::new();
        buffer.set_pos(509).unwrap();
        assert!(buffer.write_u32(0x1234_5678).is_err());
    }

    #[test]
    fn test_write_qname() {
        let mut buffer = PacketBuffer::new();
        buffer.write_qname("example.com").unwrap();
        assert_eq!(buffer.buf[0], 7);
        assert_eq!(&buffer.buf[1..8], b"example");
        assert_eq!(buffer.buf[8], 3);
        assert_eq!(&buffer.buf[9..12], b"com");
        assert_eq!(buffer.buf[12], 0);
    }

    #[test]
    fn test_write_qname_too_long() {
        let mut buffer = PacketBuffer::new();
        let long_label = "a".repeat(65);
        assert!(buffer.write_qname(&long_label).is_err());
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
    fn test_read_qname_out_of_bounds() {
        let mut buffer = PacketBuffer::new();
        buffer.set_pos(512).unwrap();
        let mut outstr = String::new();
        assert!(buffer.read_qname(&mut outstr).is_err());
    }

    #[test]
    fn test_step() {
        let mut buffer = PacketBuffer::new();
        buffer.step(5).unwrap();
        assert_eq!(buffer.pos, 5);
    }

    #[test]
    fn test_step_out_of_bounds() {
        let mut buffer = PacketBuffer::new();
        assert!(buffer.step(513).is_err());
    }

    #[test]
    fn test_set_pos() {
        let mut buffer = PacketBuffer::new();
        buffer.set_pos(10).unwrap();
        assert_eq!(buffer.pos, 10);
    }

    #[test]
    fn test_set_pos_out_of_bounds() {
        let mut buffer = PacketBuffer::new();
        assert!(buffer.set_pos(513).is_err());
    }

    #[test]
    fn test_get_buffer_to_pos() {
        let mut buffer = PacketBuffer::new();
        buffer.set_data(&[1, 2, 3, 4, 5]).unwrap();
        buffer.set_pos(3).unwrap();
        assert_eq!(buffer.get_buffer_to_pos(), &[1, 2, 3]);
    }
}
