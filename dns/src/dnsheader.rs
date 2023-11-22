use std::error::Error;

use crate::{resultcode::ResultCode, buffer::BytePacketBuffer};

#[derive(Clone, Debug)]
pub struct DNSHeader {
    pub id: u16, 

    pub recursion_desired: bool, 
    pub truncated: bool, 
    pub auth_ansr: bool, 
    pub op_code: u8, 
    pub response: bool, 

    pub res_code: ResultCode, 
    pub checking: bool, 
    pub authed_data: bool, 
    pub z: bool, 
    pub recursion_available: bool, 

    pub question: u16, 
    pub answer: u16, 
    pub auth_entries: u16, 
    pub res_entries: u16
}

impl DNSHeader {
    pub fn new() -> Self {
        DNSHeader {
            id: 0,

            recursion_desired: false,
            truncated: false,
            auth_ansr: false,
            op_code: 0,
            response: false,

            res_code: ResultCode::NOERROR,
            checking: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            question: 0,
            answer: 0,
            auth_entries: 0,
            res_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), Box<dyn Error>> {
        self.id = buffer.read_u16().unwrap();

        let flags = buffer.read_u16().unwrap();
        let a = (flags >> 8) as u8; 
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated = (a & (1 << 1)) > 0;
        self.auth_ansr = (a & (1 << 2)) > 0;
        self.op_code = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.res_code = ResultCode::from_num(b & 0x0F);
        self.checking = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.question = buffer.read_u16()?;
        self.answer = buffer.read_u16()?;
        self.auth_entries = buffer.read_u16()?;
        self.res_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), Box<dyn Error>> {
        buffer.write_u16(self.id)?;
        let _ = buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated as u8) << 1)
                | ((self.auth_ansr as u8) << 2)
                | (self.op_code << 3)
                | ((self.response as u8) << 7) as u8
        );
        let _ = buffer.write_u8(
            (self.res_code as u8)
                | ((self.checking as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7) as u8
        );
        
        buffer.write_u16(self.question)?;
        buffer.write_u16(self.answer)?;
        buffer.write_u16(self.auth_entries)?;
        buffer.write_u16(self.res_entries)?;

        Ok(())
    }
}
