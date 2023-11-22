// https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf

use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::net::{UdpSocket, Ipv4Addr};

use buffer::BytePacketBuffer;
use dnspacket::DNSPacket;

use crate::dnsquestion::DNSQuestion;
use crate::querytype::QueryType;
use crate::resultcode::ResultCode;

pub mod buffer;
pub mod resultcode;
pub mod querytype;
pub mod dnsheader;
pub mod dnspacket;
pub mod dnsquestion;
pub mod dnsrecord;

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DNSPacket, Box<dyn Error>> {
    // Bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210)).unwrap();

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut packet = DNSPacket::new();

    packet.header.id = 6666;
    packet.header.question = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DNSQuestion::new(qname.to_string(), qtype));

    // Use our new write method to write the packet to a buffer...
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();

    // ...and send it off to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server).unwrap();

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    // As per the previous section, `DnsPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response.
    let res_packet = DNSPacket::read(&mut res_buffer).unwrap();
    Ok(res_packet)
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DNSPacket, Box<dyn Error>> {
    // for now we're always starting with *a.root-servers.net*
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    // since may take arbitarary number of steps, enter a loop
    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        // send query to active server
        let ns_copy = ns;
        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        // if there are entires in answer section and no errors, done !
        if !response.answers.is_empty() && response.header.res_code == ResultCode::NOERROR {
            return Ok(response);
        }

        // might also get a NXDOMAIN reply, which is authoritative name server's way of telling us name doesn't exist
        if response.header.res_code == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // otherwise, try to find new nameserver based on NS and corresponding A record in additional
        // if succeed, switch name server and retry loop

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns; 
            continue;
        }

        // if not, resolve ip of a NS record. if no NS record exists, go with what last server told us
        let new_ns_name = match response.get_resolved_ns(qname) {
            Some(x) => x, 
            None => return Ok(response)
        };

        // go down rabbit hole by starting another loopup sequence
        let recursive_response = recursive_lookup(qname, QueryType::A)?;

        // pick random ip from the result, and restart loop
        // no such result => return last result we got
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

// handle single incoming packet
fn handle_query(socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
    // with socket ready, we can read a packet, block until one is received
    let mut req_buffer = BytePacketBuffer::new();

    // `recv_from` writes data into provided buffer, 
    // returns length of the data read as well as the source address
    // not interested in length, but need to keep track of source in order
    // to send reply later on
    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;
    // from buffer is used to parse raw bytes into dns packet
    let mut request = DNSPacket::read(&mut req_buffer)?;

    // create and initialize response packet
    let mut packet = DNSPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true; 
    packet.header.recursion_available = true; 
    packet.header.response = true; 

    // in normal case, exactly one question is present 
    if let Some(question) = request.questions.pop() {
        println!("received query: {:?}", question);

        // since all set is setup and as expected, query can be forwarded to the target server
        // there's always possibility that query will fail
        // if everything goes as planned, question and response records as copied into our response packet
        if let Ok(result) = recursive_lookup(&question.name, question.query_type) {
            packet.questions.push(question.clone());
            packet.header.res_code = result.header.res_code;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }

            for rec in result.authorities {
                println!("Answer: {:?}", rec);
                packet.authorities.push(rec);
            }

            for rec in result.resources {
                println!("Answer: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.res_code = ResultCode::SERVFAIL
        }
    } else {
        packet.header.res_code = ResultCode::FORMERR;
    }

    // encode response and send it off
    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer);

    let len = res_buffer.pos;
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}

fn main() {
    let socket = UdpSocket::bind(("0.0.0.0", 2053)).unwrap();
    loop {
        match handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("an error occurred: {}", e)
        }
    }
}
