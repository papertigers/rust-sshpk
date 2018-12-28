use base64;
use byteorder::{ByteOrder, BigEndian};
use openssl::hash::{hash, MessageDigest};

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
pub enum FingerprintType {
    MD5,
    SHA256,
}

#[derive(Debug)]
pub struct SSHKey {
    pub key_type: SSHKeyType,
    pub pub_key: Vec<u8>,
    pub comment: String,
}

impl SSHKey {
    pub (crate) fn new(bytes: &[u8], comment: &[u8]) -> Self {
        // The key itself has all the type info
        let len = BigEndian::read_u32(&bytes) as usize;
        let kb = &bytes[4..(4 + len)];
        let key_type = get_key_type(kb);

        let pub_key = Vec::from(bytes);

        let comment = String::from_utf8(comment.to_owned()).expect("invalid utf8");

        SSHKey {
            key_type,
            pub_key,
            comment
        }
    }

    pub fn fingerprint(&self, format: FingerprintType) -> String {
        match format {
            FingerprintType::MD5 => {
                let md5 = hash(MessageDigest::md5(), &self.pub_key).unwrap();
                let hex: Vec<String> = md5.as_ref().iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                format!("MD5:{}", hex.join(":"))
            }
            FingerprintType::SHA256 => {
                let sha256 = hash(MessageDigest::sha256(), &self.pub_key).unwrap();
                format!("{}:{}", "SHA256", base64::encode_config(sha256.as_ref(),
                    base64::STANDARD_NO_PAD))
            }
        }
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
