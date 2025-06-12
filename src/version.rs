use const_str;

///////////////////////////////////////////////////////////////////////////
// Module Version
//
// The module version format follows the semantic versioning system.
//
// To encode the version string in a 32-bit integer value, we use the
// first byte to denote the development version phase, and the remaining
// 3 bytes encode the `MAJOR.MINOR.PATCH` values.
//
// 32          24          16          8           0
// |-----------|-----------|-----------|-----------|
// |   MAJOR   |   MINOR   |   PATCH   |  DEV, RC  |
//
// For development releases the value `1` denotes that the current version
// is being developed.
//
// Upon the release of the first release candidate version, the value is
// incremented by `1`, and continues to be incremented whenever a new
// release candidate is released.
//
// The GA release is denoted by the value `0xFF` in the first byte.
//
// Examples:
//   Version 0x01000001 should be represented by the string "1.0.0-dev"
//   Version 0x01000002 should be represented by the string "1.0.0-rc1"
//   Version 0x010003FF should be represented by the string "1.0.3"
//
// The current version is defined in Cargo.toml
//
const MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const fn module_version() -> i32 {
    const PARTS: [&str; 3] = const_str::split!(MODULE_VERSION, ".");
    let major: i32 = const_str::parse!(PARTS[0], i32);
    let minor: i32 = const_str::parse!(PARTS[1], i32);
    const IS_DEV: bool = const_str::contains!(PARTS[2], "-");

    let (patch, dev) = if IS_DEV {
        let patch_parts = const_str::split!(PARTS[2], "-");
        let patch = const_str::parse!(patch_parts[0], i32);
        let dev = if const_str::equal!(patch_parts[1], "dev") {
            1
        } else if const_str::starts_with!(patch_parts[1], "rc") {
            let rc_num = const_str::unwrap!(const_str::strip_prefix!(patch_parts[1], "rc"));
            const_str::parse!(rc_num, i32) + 1
        } else {
            panic!("Malformed version string");
        };
        (patch, dev)
    } else {
        (const_str::parse!(PARTS[2], i32), 0xFF)
    };

    (major << 24) | (minor << 16) | (patch << 8) | dev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(module_version(), 0x01000002);
    }
}
