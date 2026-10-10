//! Client TCP vers le relay.

use std::io;
use std::net::TcpStream;
use std::time::Duration;

use crate::network::{
    decode_envelope, encode_envelope, recv_frame, send_frame, KIND_BUNDLE,
    KIND_BUNDLE_REQUEST, KIND_CIPHERTEXT, KIND_ERROR, KIND_FETCH_PENDING, KIND_OK,
};

pub struct Client {
    pub stream: TcpStream,
    pub name: String,
}

impl Client {
    pub fn connect(addr: &str, name: &str) -> io::Result<Self> {
        let mut stream = TcpStream::connect(addr).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("relay injoignable ({})", e),
            )
        })?;
        send_frame(&mut stream, name.as_bytes())?;

        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let frame_result = recv_frame(&mut stream);
        stream.set_read_timeout(None)?;
        let frame = frame_result?;

        let (kind, _from, payload) = decode_envelope(&frame)?;
        match kind {
            KIND_OK => {}
            KIND_ERROR => {
                let msg = String::from_utf8_lossy(&payload).to_string();
                return Err(io::Error::new(io::ErrorKind::Other, msg));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("reponse inattendue du relay: 0x{:02x}", other),
                ));
            }
        }

        Ok(Client {
            stream,
            name: name.to_string(),
        })
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

    pub fn recv_timeout(
        &mut self,
        dur: Duration,
    ) -> io::Result<Option<(u8, String, Vec<u8>)>> {
        self.stream.set_read_timeout(Some(dur))?;
        let result = recv_frame(&mut self.stream);
        self.stream.set_read_timeout(None)?;
        match result {
            Ok(frame) => Ok(Some(decode_envelope(&frame)?)),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}
