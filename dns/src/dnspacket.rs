use std::{error::Error, net::Ipv4Addr};

use crate::{dnsheader::DNSHeader, dnsquestion::DNSQuestion, dnsrecord::DNSRecord, buffer::BytePacketBuffer, querytype::QueryType};

#[derive(Clone, Debug)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub resources: Vec<DNSRecord>
}

impl DNSPacket {
    pub fn new() -> Self {
        DNSPacket { 
            header: DNSHeader::new(), 
            questions: Vec::new(), 
            answers: Vec::new(), 
            authorities: Vec::new(), 
            resources: Vec::new() 
        }
    }

    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DNSPacket, Box<dyn Error>> {
        let mut result = DNSPacket::new();
        let _ = result.header.read(buffer);

        for _ in 0..result.header.question {
            let mut question = DNSQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            let _ = question.read(buffer);
            result.questions.push(question);
        }

        for _ in 0..result.header.answer {
            let rec = DNSRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.auth_entries {
            let rec = DNSRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.res_entries {
            let rec = DNSRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), Box<dyn Error>> {
        self.header.question = self.questions.len() as u16;
        self.header.answer = self.answers.len() as u16;
        self.header.auth_entries = self.authorities.len() as u16;
        self.header.res_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

    // useful to be able to pick random A record from packet
    // when we get multiple IPs, doesn't matter which one
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().filter_map(|record| match record {
            DNSRecord::A { addr, .. } => Some(*addr),
            _ => None
        }).next()
    }

    // helper that returns iter over all name servers in auth section
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        // in practice, always NS in well formed packages
        // convert NS records to tuple which has only data we need 
        self.authorities.iter().filter_map(|record| match record {
            DNSRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
            _ => None
        })
        // discard servers that aren't authoritative to our query
        .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    // use fact that name servers often bundle the corresponding A records when replying to NS query
    // to implement function that returns an actual IP for an NS if possible
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        // get iterator over nameservers in authorities section
        self.get_ns(qname)
            // look for matching A record in additional section
            // since we just want first valid record, just build stream of matching records
            .flat_map(|(_, host)| {
                self.resources.iter()
                    // filter for A records where domain match host of NS record that we are currently processing
                    .filter_map(move |record| match record {
                        DNSRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            .next() // pick the first valid entry
    }

    
}
