use std::env;
use std::fs;

fn main() {
    println!("cargo::rerun-if-changed=test/valkey.conf");
    let res = fs::copy(
        "test/valkey.conf",
        env::var("OUT_DIR").unwrap().to_string() + "/../../../valkey.conf",
    );
    if let Err(err) = res {
        println!("cargo::error=Error copying valkey.conf file: {}", err);
    }
}
