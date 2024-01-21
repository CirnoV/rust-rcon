// Copyright (c) 2015 [rust-rcon developers]
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const PACKET_HEADER_SIZE: i32 = 8;
const PACKET_PADDING_SIZE: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Auth,
    AuthResponse,
    ExecCommand,
    ResponseValue,
    Unknown(i32),
}

impl PacketType {
    fn to_i32(self) -> i32 {
        match self {
            PacketType::Auth => 3,
            PacketType::AuthResponse => 2,
            PacketType::ExecCommand => 2,
            PacketType::ResponseValue => 0,
            PacketType::Unknown(n) => n,
        }
    }

    pub fn from_i32(n: i32, is_response: bool) -> PacketType {
        match n {
            3 => PacketType::Auth,
            2 if is_response => PacketType::AuthResponse,
            2 => PacketType::ExecCommand,
            0 => PacketType::ResponseValue,
            n => PacketType::Unknown(n),
        }
    }
}

#[derive(Debug)]
pub struct Packet {
    length: i32,
    id: i32,
    ptype: PacketType,
    body: String,
}

impl Packet {
    pub fn new(id: i32, ptype: PacketType, body: String) -> Packet {
        Packet {
            length: 10 + body.len() as i32,
            id,
            ptype,
            body,
        }
    }

    pub fn is_error(&self) -> bool {
        self.id < 0
    }

    pub async fn serialize<T: Unpin + AsyncWrite>(&self, w: &mut T) -> io::Result<()> {
        // Write bytes to a buffer first so only one tcp packet is sent
        // This is done in order to not overwhelm a Minecraft server
        let mut buf = Vec::with_capacity(self.length as usize);

        buf.extend_from_slice(&self.length.to_le_bytes());
        buf.extend_from_slice(&self.id.to_le_bytes());
        buf.extend_from_slice(&self.ptype.to_i32().to_le_bytes());
        buf.extend_from_slice(self.body.as_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);

        w.write_all(&buf).await?;

        Ok(())
    }

    pub async fn deserialize<T: Unpin + AsyncRead>(r: &mut T) -> io::Result<Packet> {
        let mut buf = [0u8; 4];

        r.read_exact(&mut buf).await?;
        let length = i32::from_le_bytes(buf);
        r.read_exact(&mut buf).await?;
        let id = i32::from_le_bytes(buf);
        r.read_exact(&mut buf).await?;
        let ptype = i32::from_le_bytes(buf);
        let body_length = length - PACKET_HEADER_SIZE;
        let mut body_buffer = vec![0; body_length as usize];

        // Read packet body based on the calculated length, ensuring correct handling of variable sized packets
        let body_length = r.read(&mut body_buffer).await?;
        let length = body_length as i32 + PACKET_HEADER_SIZE + PACKET_PADDING_SIZE;

        // terminating nulls
        body_buffer.truncate(body_length - PACKET_PADDING_SIZE as usize);

        let body = String::from_utf8(body_buffer)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;

        let packet = Packet {
            length,
            id,
            ptype: PacketType::from_i32(ptype, true),
            body,
        };

        Ok(packet)
    }

    pub fn get_body(&self) -> &str {
        &self.body
    }

    pub fn get_type(&self) -> PacketType {
        self.ptype
    }

    pub fn get_id(&self) -> i32 {
        self.id
    }
}
