# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-05-21

### Added

- We can now return the actual authentication error as the response of
  AUTH command, when the new config variable `return_auth_errors` is
  enabled.
  When `return_auth_errors` is disabled, the default behavior of 
  returning `WRONGPASS` error is kept. (PR #65)

### Changed

- Fixed bug in CONFIG REWRITE that would always re-write the `ldap.search_bind_passwd`
  config with an obfuscated value (PR #54)

- Fixed connection pool reconstruction to continue after a failed connection in pool (PR #60)

- Fixed NULL bytes in logging messages that may cause the module to crash (PR #63)

- Improve failure reason logging on LDAP connection failures (PR #60)

## [1.0.0] - 2025-06-13

### Changed

- Fixed module unload that was causing spurious illegal memory accesses

## [1.0.0-rc1] - 2025-06-12

### Added

- Initial version of an LDAP authentication module for Valkey 7.2.X or above


[unreleased]: https://github.com/valkey-io/valkey-ldap/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/valkey-io/valkey-ldap/releases/tag/v1.1.0
[1.0.0]: https://github.com/valkey-io/valkey-ldap/releases/tag/v1.0.0
[1.0.0_rc1]: https://github.com/valkey-io/valkey-ldap/releases/tag/v1.0.0-rc1
