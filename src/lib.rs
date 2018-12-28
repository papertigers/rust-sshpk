use std::io;
use std::io::{Error, ErrorKind};
use std::io::prelude::*;
use std::path::Path;
use std::os::unix::net::UnixStream;
use byteorder::{ByteOrder, BigEndian};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;

pub mod keys;
use crate::keys::SSHKey;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Provides an interface to a user's ssh-agent
#[derive(Debug)]
pub struct SSHAgent {
    sock: UnixStream,
}

impl SSHAgent {
    /// SSH protocol:
    ///     uint32                  message length
    ///     byte[message length]    message contents

    /// Constructs a new SSHAgent from a given ssh-agent socket
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let sock = UnixStream::connect(path)?;
        Ok(SSHAgent {
            sock
        })
    }

    /// List the keys that are currently loaded into the Agent
    pub fn list_keys(&mut self) -> io::Result<(Vec<SSHKey>)> {
        let mut keys: Vec<SSHKey> = Vec::new();
        // request the keys (uint32 + 1 byte content)
        let req = [0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES];
        self.sock.write_all(&req)?;

        // read the response
        let mut res = [0; 4];
        self.sock.read_exact(&mut res)?;
        let len = BigEndian::read_u32(&res);

        let mut buf = vec![0; len as usize];
        self.sock.read_exact(&mut buf)?;
        match *buf.first().unwrap() {
            SSH_AGENT_IDENTITIES_ANSWER => Ok(()),
            SSH_AGENT_FAILURE =>
                Err(Error::new(ErrorKind::Other, "failed to list keys from the agent")),
            _ => Err(Error::new(ErrorKind::Other, "unexpected response from the agent")),
        }?;

        let mut idx = 1; // keep track of where we are in the data buffer
        let nkeys = BigEndian::read_u32(&buf[idx..]);
        idx += 4; // jump past nkeys

        // Create SSHKey's for each of the keys in the agent
        for _ in 0..nkeys {
            let bytes = read_frame(&buf, &mut idx);
            let comment = read_frame(&buf, &mut idx);
            keys.push(SSHKey::new(bytes, comment));
        }

        Ok(keys)
    }

    /// Use the ssh-agent to sign some data with one of its keys
    pub fn sign_data<R: Read>(&mut self, key: &SSHKey, mut data: R) -> io::Result<(String)> {
        // construct the request type + key blob
        let mut req = vec![0, 0, 0, 1, SSH_AGENTC_SIGN_REQUEST];
        let mut key_len = [0; 4];
        BigEndian::write_u32(&mut key_len, key.pub_key.len()as u32);

        // attach the data being signed
        let mut data_len = [0; 4];
        let mut raw_data = vec![];
        let len = io::copy(&mut data, &mut raw_data)? as usize;
        BigEndian::write_u32(&mut data_len, len as u32);
        // XXX handle flags for key.key_type == rsa
        let mut flags = [0; 4];
        BigEndian::write_u32(&mut flags, 0x02 as u32);

        // uint32 + op + uint32 + key length + uint32 + data length
        let total = 4 + 1 + 4 + key.pub_key.len() + 4 + len;
        BigEndian::write_u32(&mut req[..4], total as u32);
        req.extend(&key_len);
        req.extend(&key.pub_key);
        req.extend(&data_len);
        req.append(&mut raw_data); // consume the vector instead and leave it empty
        req.extend(&flags);

        // write the data to the ssh-agent
        self.sock.write_all(&req)?;

        // read the response
        let mut sign_res = [0; 4];
        self.sock.read_exact(&mut sign_res)?;
        let sig_len = BigEndian::read_u32(&sign_res) as usize;
        let mut buf = vec![0; sig_len];
        self.sock.read_exact(&mut buf)?;
        match *buf.first().unwrap() {
            SSH_AGENT_SIGN_RESPONSE => Ok(()),
            SSH_AGENT_FAILURE =>
                Err(Error::new(ErrorKind::Other, "failed to sign data with the agent")),
            _ => Err(Error::new(ErrorKind::Other, "unexpected response from the agent")),
        }?;

        let mut idx = 5; // skip uint32 + op
        let algo = read_frame(&buf, &mut idx);
        println!("{}", std::str::from_utf8(algo).unwrap());
        idx += 4; // jump past the uint32 that contains the total length
        // ecdsa specific... for now
        let der =  ecdsa_signature(&buf[idx..])?;
        let encoded = base64::encode(&der);
        Ok(encoded)
    }
}

/// Read a ecdsa signature from the buffer returned back from the ssh-agent
fn ecdsa_signature(buf: &[u8]) -> io::Result<Vec<u8>> {
    let mut idx = 0;
    let r = read_frame(&buf, &mut idx);
    let s = read_frame(&buf, &mut idx);
    let r_big = BigNum::from_slice(r)?;
    let s_big = BigNum::from_slice(s)?;
    Ok(EcdsaSig::from_private_components(r_big, s_big)?.to_der()?)
}

/// Read a frame of data from the ssh-agent and return a refernce to the data.
/// Where a frame is uin32 (len) + data
fn read_frame<'a>(buf: &'a [u8], index: &mut usize) -> &'a [u8] {
    let len = BigEndian::read_u32(&buf[*index..]) as usize;
    *index += 4;
    let bytes = &buf[*index..(*index + len)];
    *index += len;
    bytes
}
