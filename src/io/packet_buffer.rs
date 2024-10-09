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
