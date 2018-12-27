use std::io;
use std::io::{Error, ErrorKind};
use std::io::prelude::*;
use std::path::Path;
use std::os::unix::net::UnixStream;
use byteorder::{ByteOrder, BigEndian};

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
        self.sock.write(&req)?;

        // read the response
        let mut res = [0; 4];
        self.sock.read(&mut res)?;
        let len = BigEndian::read_u32(&res);

        let mut buf = vec![0; len as usize];
        self.sock.read_exact(&mut buf)?;
        let _ = match *buf.first().unwrap() {
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
            // Get the raw key data
            let len = BigEndian::read_u32(&buf[idx..]) as usize;
            idx += 4; // jump past key len
            let bytes = &buf[idx..(idx + len)];
            idx += len; // jump past the key itself

            // Get the key comment
            let len = BigEndian::read_u32(&buf[idx..]) as usize;
            idx += 4; // jump past the comment len
            let comment = &buf[idx..(idx + len)];
            idx += len; // jump past the comment itself

            keys.push(SSHKey::new(bytes, comment));
        }

        Ok(keys)
    }

    /// Use the ssh-agent to sign some data with one of its keys
    pub fn sign_data<D: AsRef<[u8]>>(&mut self, key: SSHKey, data: D) -> io::Result<()> {
        let mut idx = 0; // offset into data buffer
        let data = data.as_ref();
        // uint32 + op + uint32 + key + uint32 + data + optional flags
        let mut buf = vec![0; 4 + 1 + 4 + key.key.len() + 4 + data.len() + 4];
        let len = buf.len() - 4; // total buffer size minus flags

        Ok(())
    }
}
