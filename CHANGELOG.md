# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Fixed bug in CONFIG REWRITE that would always re-write the `ldap.search_bind_passwd`
  config with an obfuscated value

## Changed

- Fixed module unload that was causing spurious illegal memory accesses

## [1.0.0-rc1] - 2025-06-12

### Added

- Initial version of an LDAP authentication module for Valkey 7.2.X or above


[unreleased]: https://github.com/valkey-io/valkey-ldap/compare/v1.0.0-rc1...HEAD
[1.0.0_rc1]: https://github.com/valkey-io/valkey-ldap/releases/tag/v1.0.0-rc1
