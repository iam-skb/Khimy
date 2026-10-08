//! Client TCP vers le relay.

use std::io;
use std::net::TcpStream;

use crate::network::{
    decode_envelope, encode_envelope, recv_frame, send_frame, KIND_BUNDLE,
    KIND_BUNDLE_REQUEST, KIND_CIPHERTEXT, KIND_FETCH_PENDING,
};

pub struct Client {
    pub stream: TcpStream,
    pub name: String,
}

impl Client {
    pub fn connect(addr: &str, name: &str) -> io::Result<Self> {
        let mut stream = TcpStream::connect(addr)?;
        send_frame(&mut stream, name.as_bytes())?;
        Ok(Client { stream, name: name.to_string() })
    }

    pub fn publish_bundle(&mut self, bundle_bytes: &[u8]) -> io::Result<()> {
        let env = encode_envelope(KIND_BUNDLE, &self.name, bundle_bytes);
        send_frame(&mut self.stream, &env)
    }

    pub fn request_bundle(&mut self, dest: &str) -> io::Result<()> {
        let env = encode_envelope(KIND_BUNDLE_REQUEST, dest, &[]);
        send_frame(&mut self.stream, &env)
    }

    pub fn send_ciphertext(&mut self, dest: &str, ciphertext: &[u8]) -> io::Result<()> {
        let env = encode_envelope(KIND_CIPHERTEXT, dest, ciphertext);
        send_frame(&mut self.stream, &env)
    }

    pub fn fetch_pending(&mut self) -> io::Result<()> {
        let env = encode_envelope(KIND_FETCH_PENDING, &self.name, &[]);
        send_frame(&mut self.stream, &env)
    }

    pub fn recv(&mut self) -> io::Result<(u8, String, Vec<u8>)> {
        let frame = recv_frame(&mut self.stream)?;
        decode_envelope(&frame)
    }
}
