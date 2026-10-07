//! Transport TCP + serialisation custom du PreKeyBundle.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use libsignal_protocol::*;

pub const MAX_FRAME: usize = 1 << 20;

pub fn send_frame(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame trop grande"));
    }
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

pub fn recv_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame trop grande"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

pub const KIND_BUNDLE_REQUEST: u8 = 0x01;
pub const KIND_BUNDLE: u8 = 0x02;
pub const KIND_CIPHERTEXT: u8 = 0x03;
pub const KIND_ERROR: u8 = 0x04;

pub fn encode_envelope(kind: u8, dest: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + dest.len() + 4 + payload.len());
    out.push(kind);
    out.extend_from_slice(&(dest.len() as u32).to_be_bytes());
    out.extend_from_slice(dest.as_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn decode_envelope(buf: &[u8]) -> io::Result<(u8, String, Vec<u8>)> {
    if buf.len() < 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "envelope trop court"));
    }
    let kind = buf[0];
    let mut pos = 1;

    let dlen = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if pos + dlen + 4 > buf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "dest tronque"));
    }
    let dest = String::from_utf8(buf[pos..pos + dlen].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "dest non-utf8"))?;
    pos += dlen;

    let plen = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if pos + plen > buf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "payload tronque"));
    }
    let payload = buf[pos..pos + plen].to_vec();

    Ok((kind, dest, payload))
}

pub fn serialize_bundle(b: &PreKeyBundle) -> Result<Vec<u8>, SignalProtocolError> {
    let mut out = Vec::new();

    out.extend_from_slice(&b.registration_id()?.to_be_bytes());
    out.extend_from_slice(&u32::from(b.device_id()?).to_be_bytes());

    match b.pre_key_id()? {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&u32::from(id).to_be_bytes());
            let pk = b.pre_key_public()?
                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
            out.extend_from_slice(&pk.serialize());
        }
        None => out.push(0),
    }

    out.extend_from_slice(&u32::from(b.signed_pre_key_id()?).to_be_bytes());
    out.extend_from_slice(&b.signed_pre_key_public()?.serialize());
    let sig = b.signed_pre_key_signature()?;
    out.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    out.extend_from_slice(sig);

    out.extend_from_slice(&u32::from(b.kyber_pre_key_id()?).to_be_bytes());
    out.extend_from_slice(&b.kyber_pre_key_public()?.serialize());
    let ksig = b.kyber_pre_key_signature()?;
    out.extend_from_slice(&(ksig.len() as u32).to_be_bytes());
    out.extend_from_slice(ksig);

    out.extend_from_slice(&b.identity_key()?.serialize());

    Ok(out)
}

pub fn deserialize_bundle(buf: &[u8]) -> Result<PreKeyBundle, SignalProtocolError> {
    let mut p = 0usize;

    fn take<'a>(buf: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8], SignalProtocolError> {
        if *p + n > buf.len() {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }
        let s = &buf[*p..*p + n];
        *p += n;
        Ok(s)
    }

    let reg_id = u32::from_be_bytes(take(buf, &mut p, 4)?.try_into().unwrap());
    let dev_id_u32 = u32::from_be_bytes(take(buf, &mut p, 4)?.try_into().unwrap());
    let dev_id_u8 = u8::try_from(dev_id_u32)
        .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
    let dev_id = DeviceId::new(dev_id_u8)
        .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

    let has_pre = take(buf, &mut p, 1)?[0] == 1;
    let pre_key = if has_pre {
        let id = PreKeyId::from(u32::from_be_bytes(take(buf, &mut p, 4)?.try_into().unwrap()));
        let pk = PublicKey::deserialize(take(buf, &mut p, 33)?)?;
        Some((id, pk))
    } else {
        None
    };

    let spk_id = SignedPreKeyId::from(u32::from_be_bytes(take(buf, &mut p, 4)?.try_into().unwrap()));
    let spk_pub = PublicKey::deserialize(take(buf, &mut p, 33)?)?;
    let spk_sig_len = u32::from_be_bytes(take(buf, &mut p, 4)?.try_into().unwrap()) as usize;
    let spk_sig = take(buf, &mut p, spk_sig_len)?.to_vec();

    let kpk_id = KyberPreKeyId::from(u32::from_be_bytes(take(buf, &mut p, 4)?.try_into().unwrap()));
    let kpk_pub = kem::PublicKey::deserialize(take(buf, &mut p, 1 + 1568)?)
        .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
    let kpk_sig_len = u32::from_be_bytes(take(buf, &mut p, 4)?.try_into().unwrap()) as usize;
    let kpk_sig = take(buf, &mut p, kpk_sig_len)?.to_vec();

    let id_key = IdentityKey::decode(take(buf, &mut p, 33)?)?;

    PreKeyBundle::new(
        reg_id,
        dev_id,
        pre_key,
        spk_id,
        spk_pub,
        spk_sig,
        kpk_id,
        kpk_pub,
        kpk_sig,
        id_key,
    )
}
