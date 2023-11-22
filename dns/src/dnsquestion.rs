use std::error::Error;

use crate::{querytype::QueryType, buffer::BytePacketBuffer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSQuestion {
    pub name: String, 
    pub query_type: QueryType
}

impl DNSQuestion {
    pub fn new(name: String, query_type: QueryType) -> DNSQuestion {
        DNSQuestion { name: name, query_type: query_type }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), Box<dyn Error>> {
        buffer.read_qname(&mut self.name)?;
        self.query_type = QueryType::from_num(buffer.read_u16().unwrap());
        let _ = buffer.read_u16().unwrap();

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), Box<dyn Error>> {
        buffer.write_qname(&self.name)?;
        let type_num = self.query_type.to_num();
        buffer.write_u16(type_num)?;
        buffer.write_u16(1)?;
        Ok(())
    }
}
