use std::{fs::File, io::Read};
use byte_packer_buffer::BytePackerBuffer;
use dns_packet::DnsPacket;

mod byte_packer_buffer;
mod result_code;
mod dns_header;
mod query_type;
mod dns_question;
mod dns_record;
mod dns_packet;

type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePackerBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
