use sshpk::SSHAgent;

fn main() {
    //let my_key = include_str!("../test.key");
    let path = "/run/user/1000/ssh-agent.socket";
    let mut agent = SSHAgent::new(path).expect("failed to create SSHAgent");
    let keys = agent.list_keys().expect("write to agent failed");
    for key in &keys {
        println!("{} -- {}", key.comment, key.sha256_fingerprint());
    }
}
