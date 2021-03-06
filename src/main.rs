use sshpk::SSHAgent;
use sshpk::keys::{SSHPubKey, FingerprintType};

fn main() {
    //let my_key = include_str!("../test.key");
    let path = "/run/user/1000/ssh-agent.socket";
    let agent = SSHAgent::new(path).expect("failed to create SSHAgent");
    let keys = agent.list_keys().expect("write to agent failed");
    for key in &keys {
        println!("{} -- {}", key.comment(), key.fingerprint(FingerprintType::MD5));
    }
    let key = &keys[1];
    let sig = agent.sign_data(key, "hello world".as_bytes()).unwrap();
    println!("Signature base64: {}", sig);
}
