use base64;
use byteorder::{ByteOrder, BigEndian};
use ring::digest;

#[derive(Debug)]
pub enum SSHKeyType {
    DSS,
    RSA,
    ED25519,
    NISTP256,
    NISTP384,
    NISTP521,
    UNKNOWN, // generic catch all for now
}

#[derive(Debug)]
pub struct SSHKey {
    pub key_type: SSHKeyType,
    pub key: Vec<u8>,
    pub comment: String,
}

impl SSHKey {
    pub (crate) fn new(bytes: &[u8], comment: &[u8]) -> Self {
        // The key itself has all the type info
        let len = BigEndian::read_u32(&bytes) as usize;
        let kb = &bytes[4..(4 + len)];
        let key_type = get_key_type(kb);

        let key = Vec::from(bytes);

        let comment = String::from_utf8(comment.to_owned()).expect("invalid utf8");

        SSHKey {
            key_type,
            key,
            comment
        }
    }

    pub fn sha256_fingerprint(&self) -> String {
        let hash = digest::digest(&digest::SHA256, &self.key);
        format!("{}:{}", "SHA256", base64::encode(hash.as_ref()))
    }
}


fn get_key_type(bytes: &[u8]) -> SSHKeyType {
    match std::str::from_utf8(bytes).expect("invalid utf8") {
        "ssh-dss" => SSHKeyType::DSS,
        "ssh-rsa" => SSHKeyType::RSA,
        "ssh-ed25519" => SSHKeyType::ED25519,
        "ecdsa-sha2-nistp256" => SSHKeyType::NISTP256,
        "ecdsa-sha2-nistp384" => SSHKeyType::NISTP384,
        "ecdsa-sha2-nistp521" => SSHKeyType::NISTP521,
        _ => SSHKeyType::UNKNOWN,
    }
}
