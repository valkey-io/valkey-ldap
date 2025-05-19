# ValkeyLDAP - Valkey LDAP authentication module  ![CI](https://github.com/valkey-io/valkey-ldap/actions/workflows/ci.yml/badge.svg) [![Copr Build Status](https://copr.fedorainfracloud.org/coprs/rjd15372/valkey-ldap/package/valkey-ldap-nightly/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/rjd15372/valkey-ldap/package/valkey-ldap-nightly/)

The `valkey-ldap` module is a Rust based Valkey module that adds the support for handling user authentication against LDAP based identity providers.

The module works by registering and authentication handler that intercepts the valkey `AUTH` command, which validates the the username and password, specified in the `AUTH` command, using an LDAP server. Therefore the user must already exist in Valkey before LDAP can be used for authentication.

## LDAP Authentication Modes

This module supports two LDAP authentication modes. The `bind` mode, and the `search+bind` mode.

The `bind` mode can be used when the username mostly matches the DN of user entries in the LDAP directory, while the `search+bind` mode allows for a much more flexible LDAP directory structure.

### Bind Mode Authentication

In the `bind` mode, the module will bind to the distinguished name constructed by prepending a configurable prefix and appending a configurable suffix to the username.
Typically, the prefix parameter is used to specify `cn=`, or `DOMAIN\` in an Active Directory environment. The suffix is used to specify the remaining part of the DN in a non-Active Directory environment.

### Search+Bind Authentication

In the `search+bind` mode, the module first binds to the LDAP directory with a username and password of an account that has permissions to perform search operation in the LDAP directory.
If no username and password is configured for the binding phase, an anonymous bind will be attempted to the directory.

After the binding phase, a search operation is performed over the subtree at a configurable base DN string, and will try to do an exact match of the username specified in the `AUTH` command against the value of a configurable entry attribute.

Once the user has been found in this search, the module re-binds to the LDAP directory as this user, using the password specified in the `AUTH` command, to verify that the login is correct.

This mode allows for significantly more flexibility in where the user objects are located in the directory, but will cause two additional requests to the LDAP server to be made.

## Module Configuration

### General Options

| Config Name | Type | Default | Description |
| ------------|------|---------|-------------|
| `ldap.auth_enabled` | boolean | `yes` | Flag to control whether the module should process an authentication request or not. |
| `ldap.auth_mode` | Enum(`bind`, `search+bind`) | `bind` | The authentication method. Check the [Authentication Modes](#ldap-authentication-modes) section for more information about the differences. |
| `ldap.servers` | string | `""` | Comma separated list of LDAP URLs of the form `ldap[s]://<domain>:<port>`. |

### TLS Options

| Config Name | Type | Default | Description |
| ------------|------|---------|-------------|
| `ldap.use_starttls` | boolean | `no` | Whether upgrade to a TLS encrypted connection upon connection to a non-ssl LDAP instance. This uses the StartTLS operation per RFC 4513. |
| `ldap.tls_ca_cert_path` | string | `""` | The filesystem path of the CA certificate for validating the server certificate in a TLS connection. |
| `ldap.tls_cert_path` | string | `""` | The filesystem path of the client certificate to be used in a TLS connection to the LDAP server. |
| `ldap.tls_key_path` | string | `""` | The filesystem path of the client certificate key to be used in a TLS connection to the LDAP server. |

### Bind Mode Options

| Config Name | Type | Default | Description |
| ------------|------|---------|-------------|
| `ldap.bind_dn_prefix` | string | `"cn="` | The string to prepend to the username passed in the `AUTH` command when forming the DN that is used in LDAP bind. |
| `ldap.bind_dn_suffix` | string | `""` | The string to append to the username passed in the `AUTH` command when forming the DN that is used in LDAP bind. |

### Search+Bind Mode Options

| Config Name | Type | Default | Description |
| ------------|------|---------|-------------|
| `ldap.search_bind_dn` | string | `""` | The bind user DN for performing the search. |
| `ldap.search_bind_passwd` | string | `""` | The bind user password for performing the search. |
| `ldap.search_base` | string | `""` | The root DN where the search for the user entry begins. |
| `ldap.search_filter` | string | `"objectClass=*"` | The search filter used to filter directory entries. |
| `ldap.search_attribute` | string | `"uid"` | The entry attribute used in search for matching the username specified in the `AUTH` command. |
| `ldap.search_scope` | Enum(`base`, `one`, `sub`) | `sub` | The search scope. |
| `ldap.search_dn_attribute` | string | `"entryDN"` | The attribute that contains the DN of the user entry. |

## Installation

We currently build RPMs for several distributions in the [valkey-ldap Copr project](https://copr.fedorainfracloud.org/coprs/rjd15372/valkey-ldap/).

## Development

### Build Instructions

ValkeyLDAP uses Cargo for building the Valkey module.

```bash
cargo build
```

### Manual Module Testing

The project has a collection of scripts to start an LDAP and Valkey server using docker-compose to easily test the module.

To start a Valkey CLI shell to test the module commands, run:

```bash
./scripts/run_test_cli.sh
```

The above command will start the LDAP and Valkey servers, and opens the valkey CLI shell. When the shell closes, it also stops the LDAP and Valkey servers.

If you just want to start the LDAP and Valkey server, run:

```bash
./scripts/start_valkey_ldap.sh
```

You can connect to the LDAP server and Valkey server from the localhost address.

To stop the servers, run:

```bash
./scripts/stop_valkey_ldap.sh
```

### Automated Integration Tests

The integration tests are written in python 3, and live in the `test/integration` directory. To run the tests locally we suggest to create a virtual environment to install the necessary python dependencies.

Assuming you have python 3 installed in your system, to install the python dependencies using a virtual environment do the following:

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r test/integration/requirements.txt
```

After setting up the virtual environment, you can run the test using the following command:

```bash
./script/run_integration_tests.sh
```
