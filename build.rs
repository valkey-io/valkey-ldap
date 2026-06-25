use std::env;
use std::fs;
use std::process::Command;

fn copy_file_to_build_dir(from: &str) {
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
    let profile = std::env::var("PROFILE").unwrap();
    // The debug-only test fixtures (TLS certs + sample valkey.conf) exist purely
    // for this crate's own standalone integration tests. When the crate is built
    // with the `embed` feature it is linked into a host module and those fixtures
    // are never used; skip them. (generate_test_certificates.sh also assumes the
    // crate lives in a directory literally named `valkey-ldap`, which is not the
    // case when embedded as a submodule, so running it here would hang.)
    let embedded = std::env::var_os("CARGO_FEATURE_EMBED").is_some();
    if &profile == "debug" && !embedded {
        Command::new("bash")
            .arg("scripts/generate_test_certificates.sh")
            .status()
            .unwrap();

        copy_file_to_build_dir("test/valkey.conf");
        copy_file_to_build_dir("test/valkey-ldap-client.crt");
        copy_file_to_build_dir("test/valkey-ldap-client.key");
        copy_file_to_build_dir("scripts/docker/certs/valkey-ldap-ca.crt");
    }
}
