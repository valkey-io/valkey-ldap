use std::env;
use std::fs;
use std::process::Command;

fn copy_file_to_build_dir(from: &str) -> () {
    let arr = from.split("/");
    let file_name_opt = arr.last();
    match file_name_opt {
        None => println!("cargo::error=Error copying file: invalid file path"),
        Some(file_name) => {
            let res = fs::copy(
                from,
                env::var("OUT_DIR").unwrap().to_string() + "/../../../" + file_name,
            );
            if let Err(err) = res {
                println!("cargo::error=Error copying {} file: {}", file_name, err);
            }
        }
    }
    println!("cargo::rerun-if-changed={}", from);
}

fn main() {
    Command::new("bash")
        .arg("scripts/generate_test_certificates.sh")
        .status()
        .unwrap();

    copy_file_to_build_dir("test/valkey.conf");
    copy_file_to_build_dir("test/valkey-ldap-client.crt");
    copy_file_to_build_dir("test/valkey-ldap-client.key");
    copy_file_to_build_dir("scripts/docker/certs/valkey-ldap-ca.crt");
}
