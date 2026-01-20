# ValkeyLDAP - Valkey LDAP authentication module  ![CI](https://github.com/valkey-io/valkey-ldap/actions/workflows/ci.yml/badge.svg) [![codecov](https://codecov.io/gh/valkey-io/valkey-ldap/branch/main/graph/badge.svg)](https://codecov.io/gh/valkey-io/valkey-ldap) [![Copr Build Status](https://copr.fedorainfracloud.org/coprs/rjd15372/valkey-ldap/package/valkey-ldap-nightly/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/rjd15372/valkey-ldap/package/valkey-ldap-nightly/)

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

## LDAP-Based Authorization

In addition to authentication, the module supports authorization backed by LDAP.

Two approaches are available:

- Legacy mapping to ACL users: Map LDAP groups to Valkey ACL user names via `ldap.group_acl_user_map` (comma-separated `group=acluser`). After successful bind, the client is authenticated as the mapped ACL user.
- Dynamic ACL rule sync (recommended): Read ACL rule tokens directly from LDAP group entries and apply them with `ACL SETUSER` at login. The client is authenticated as the Valkey user with the same name as the LDAP username; rules are provisioned automatically.

### Dynamic ACL Rule Sync

After a successful LDAP bind, the module searches group entries matching the user DN and reads rule tokens from a configurable attribute on each group. All tokens are merged (duplicates deduplicated) and combined with module defaults. The resulting set is applied via `ACL SETUSER <username> <rules...>` before the client is authenticated.

- `ldap.groups_rules_attribute`: LDAP attribute on group entries containing space-delimited ACL rule tokens. Default: `valkeyACL`.
- `ldap.default_acl_rules`: Module-level default tokens always applied. Default: `on resetpass`.
- Group search controls: `ldap.groups_search_base` (fallback to `ldap.search_base`), `ldap.groups_filter` (default `objectClass=groupOfNames`), `ldap.groups_member_attribute` (default `member`).

Example group entry attributes:

```
dn: cn=appdev-team,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: appdev-team
member: cn=bob,ou=users,dc=example,dc=com
valkeyACL: +@read ~proj:app:* -@dangerous
```

Resulting user rules (assuming defaults `on resetpass`):

```
ACL SETUSER bob on resetpass +@read ~proj:app:* -@dangerous
```

Notes:

- Tokens from all matched groups are merged; duplicates are removed.
- If the LDAP attribute is missing or empty, only `ldap.default_acl_rules` are applied.
- You do not need to pre-create complex ACL users or update server-side ACLs manually; rules are provisioned at login.

## Setting Up Valkey Users

As mentioned before, this module requires that user accounts must exist in Valkey in order to authenticate LDAP users. This restriction is necessary because the ACL rules for each LDAP user are stored in the Valkey user account.

For a user `bob` to be successfully authenticated by the LDAP module it must exist in the Valkey ALC database with the same username `bob`.

We can create the Valkey user `bob` without a password, to prevent someone from trying to log in using `bob` account using the password-based authentication method.

To create a user without a password we need to set the `resetpass` rule in the ACL rules list. Example:

```
ACL SET USER bob on resetpass +@hash
```

After creating the above user `bob` in Valkey, it will only be possible to authenticate user `bob` with a successful authentication from the LDAP module.

### Automatic Cleanup of Deleted LDAP Users

When a user is deleted from LDAP but still exists in the Valkey ACL, the module automatically removes that user from Valkey's ACL on the next authentication attempt. This ensures that ACL entries stay synchronized with LDAP and prevents unauthorized access from stale user accounts.

**Important Security Notes:**

1. **Exempted users are never deleted**: Users matching the `ldap.exempted_users_regex` pattern are protected from automatic deletion, even if LDAP authentication fails.

2. **Deletion only on "user not found"**: A user is deleted from ACL **only** when LDAP confirms the user does not exist. Wrong passwords or other transient failures will NOT trigger deletion, preventing denial-of-service attacks from password typos.

3. **Deletion triggers**: A user is deleted from ACL when:
   - The user attempts to authenticate
   - LDAP returns a "user not found" error (not just invalid credentials)
   - The user is not exempted from LDAP authentication

4. **Protected users**: The `default` user and other system users that cannot be deleted by `ACL DELUSER` are automatically protected by Valkey's built-in safeguards.

## Exempting Users from LDAP Authentication

In some scenarios, certain users need to bypass LDAP authentication and use local Valkey authentication instead. Common examples include:

- **Default super admin user**: Administrative access that shouldn't depend on LDAP availability
- **Inter-node communication**: Replication and cluster communication users
- **Monitoring and metrics**: Exporters and health check services that poll frequently
- **Service accounts**: Automated tools and scripts that need reliable authentication

### Why Exempt Users?

Exempting high-frequency service accounts (like Redis exporters) from LDAP reduces load on the LDAP server and prevents potential crashes from excessive authentication requests. It also ensures critical services remain operational even if LDAP becomes unavailable.

### Configuration

Use the `ldap.exempted_users_regex` configuration to specify a regex pattern matching usernames that should bypass LDAP:

```bash
# Exempt specific users
CONFIG SET ldap.exempted_users_regex "^(default|exporter|replication)$"

# Exempt users with a prefix pattern
CONFIG SET ldap.exempted_users_regex "^(admin|metrics-.*|repl-.*)$"

# Clear exemptions (all users go through LDAP)
CONFIG SET ldap.exempted_users_regex ""
```

**Important Notes:**

1. **Local passwords required**: Exempted users must have local passwords configured in Valkey using `ACL SETUSER <username> >password` since they won't authenticate via LDAP.

2. **Exemption takes precedence**: If a username matches the exemption pattern, LDAP is **never contacted** for that user, even if a user with the same name exists in LDAP. Only the local Valkey password will work.

3. **Name conflicts**: To avoid confusion, use distinctive naming conventions for exempted users (e.g., `local-exporter`, `valkey-admin`) or ensure exempted usernames don't exist in your LDAP directory.

4. **Protection from automatic deletion**: Exempted users are protected from the automatic ACL cleanup feature. When a non-exempted user fails LDAP authentication, they are automatically removed from Valkey's ACL. Exempted users will never be automatically deleted, even if authentication fails.

### Example Setup

```bash
# Create local users with passwords
ACL SETUSER default on >supersecret +@all ~*
ACL SETUSER exporter on >exporterpass +@read ~*
ACL SETUSER replication on >replpass +@all ~*

# Configure LDAP exemptions
CONFIG SET ldap.exempted_users_regex "^(default|exporter|replication)$"

# Regular LDAP users (no local password)
ACL SETUSER bob on resetpass +@hash
ACL SETUSER alice on resetpass +@read
```

## ACL Fallback for LDAP Server Unavailability

The ACL fallback feature provides high availability by allowing users to authenticate against cached credentials in the local ACL when the LDAP server is unreachable. This ensures continued service operation during LDAP outages while maintaining security.

### How It Works

When `ldap.acl_fallback_enabled` is set to `true`:

1. **On successful LDAP authentication**: The user's password is securely saved in the Valkey ACL alongside their permissions
2. **On LDAP server unavailability**: Users can authenticate using their cached password in the ACL
3. **On credential rejection**: Authentication fails immediately without falling back to ACL (prevents bypassing LDAP password changes)

### Configuration

```bash
# Enable ACL fallback
CONFIG SET ldap.acl_fallback_enabled true

# Disable ACL fallback (default)
CONFIG SET ldap.acl_fallback_enabled false
```

### Important Behavior

**Server Unavailability vs Credential Rejection:**
- ✅ **Server unavailable** (connection failure, no healthy servers): Falls back to ACL if enabled
- ❌ **Wrong credentials** (invalid password, user not found): Never falls back to ACL
- ❌ **LDAP rejects credentials**: Never falls back to ACL

This distinction is critical for security:
- If a user changes their LDAP password, they cannot use the old cached password in ACL
- If a user is disabled in LDAP, they cannot bypass this using the ACL
- Only true infrastructure failures trigger the fallback mechanism

### Security Considerations

1. **Password Caching**: Passwords are stored in Valkey's ACL system. Ensure proper access controls and encryption for your Valkey instance.

2. **Stale Credentials**: If a user changes their LDAP password while the LDAP server is reachable, the cached password is automatically updated. However, if they change it while LDAP is down, the old password remains cached until the next successful LDAP authentication.

3. **User Removal**: If a user is removed from LDAP and marked as "user not found", they are deleted from the ACL even if fallback is enabled. Only server unavailability triggers fallback.

4. **Exempted Users**: Exempted users (via `ldap.exempted_users_regex`) bypass LDAP entirely and always use local ACL authentication, regardless of the fallback setting.

### Example Usage

```bash
# Setup: Enable ACL fallback
CONFIG SET ldap.acl_fallback_enabled true

# User authenticates successfully via LDAP
# (password is now cached in ACL automatically)
AUTH alice <ldap-password>

# LDAP server becomes unavailable...
# User can still authenticate using cached credentials
AUTH alice <ldap-password>

# User changes password in LDAP (after LDAP recovers)
AUTH alice <new-ldap-password>
# New password is now cached

# User tries wrong password
AUTH alice <wrong-password>
# Fails immediately - no fallback to ACL for wrong credentials
```

### When to Use ACL Fallback

**Enable ACL fallback when:**
- High availability is critical and brief LDAP outages cannot interrupt service
- You have monitoring to detect and alert on LDAP server issues
- Your security policies allow password caching

**Keep ACL fallback disabled when:**
- Security policies require real-time LDAP validation for all authentications
- You prefer to fail closed (deny access) during LDAP outages
- Immediate enforcement of password changes is required

# Authenticate as exempted user (uses local password)
AUTH default supersecret

# Authenticate as LDAP user (uses LDAP password)
AUTH bob ldap-password
```


## Module Configuration

### General Options

| Config Name | Type | Default | Description |
| ------------|------|---------|-------------|
| `ldap.auth_mode` | Enum(`bind`, `search+bind`) | `bind` | The authentication method. Check the [Authentication Modes](#ldap-authentication-modes) section for more information about the differences. |
| `ldap.servers` | string | `""` | Comma separated list of LDAP URLs of the form `ldap[s]://<domain>:<port>`. |

### TLS Options

| Config Name | Type | Default | Description |
| ------------|------|---------|-------------|
| `ldap.use_starttls` | boolean | `no` | Whether upgrade to a TLS encrypted connection upon connection to a non-ssl LDAP instance. This uses the StartTLS operation per RFC 4513. |
| `ldap.tls_ca_cert_path` | string | `""` | The filesystem path of the CA certificate for validating the server certificate in a TLS connection. |
| `ldap.tls_cert_path` | string | `""` | The filesystem path of the client certificate to be used in a TLS connection to the LDAP server. |
| `ldap.tls_key_path` | string | `""` | The filesystem path of the client certificate key to be used in a TLS connection to the LDAP server. |
| `ldap.tls_skip_verify` | boolean | `no` | **⚠️ INSECURE**: Skip TLS certificate verification. When enabled, accepts any certificate presented by the LDAP server, including self-signed and expired certificates. This disables protection against man-in-the-middle attacks and should **only be used in development/testing environments**. Never use in production. |

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

### Advanced Options

| Config Name | Type | Default | Description |
| ------------|------|---------|-------------|
| `ldap.connection_pool_size` | number | `2` | The number of connections available in each LDAP server's connection pool. |
| `ldap.failure_detector_interval` | number | `1` | The number of seconds between each iteration of the failure detector. |
| `ldap.timeout_connection` | number | `2` | The number of seconds for to wait when connection to an LDAP server before timing out. |
| `ldap.timeout_ldap_operation` | number | `2` | The number of seconds for to wait for an LDAP operation before timing out. |
| `ldap.group_acl_user_map` | string | `""` | Comma-separated LDAP group to Valkey ACL user mapping (`group=acluser`). (Legacy approach; use dynamic ACL rule sync below for most cases.) |
| `ldap.groups_search_base` | string | `""` | DN for group search; defaults to `ldap.search_base` when unset. |
| `ldap.groups_filter` | string | `"objectClass=groupOfNames"` | LDAP filter used when searching for groups. |
| `ldap.groups_member_attribute` | string | `"member"` | LDAP attribute in the group entry that references the user DN. |
| `ldap.groups_name_attribute` | string | `"cn"` | LDAP attribute in the group entry that is used as the group name for mapping. |
| `ldap.groups_rules_attribute` | string | `"valkeyACL"` | LDAP attribute on group entries containing space-delimited ACL rule tokens applied to the user at login. |
| `ldap.default_acl_rules` | string | `"on resetpass"` | Default ACL rule tokens always applied alongside LDAP-provided tokens. |
| `ldap.exempted_users_regex` | string | `""` | Regex pattern to exempt certain users from LDAP authentication. Users matching this pattern will bypass LDAP and use local Valkey authentication. Useful for service accounts, monitoring users, and inter-node communication. Examples: `^(default|exporter|replication)$` or `^(admin\|metrics-.*)$`. |
| `ldap.acl_fallback_enabled` | bool | `no` | Enable ACL fallback when LDAP server is unavailable. When enabled and LDAP authentication succeeds, the user's password is saved in the ACL. If the LDAP server becomes unavailable later, the user can still authenticate using the cached password in the ACL. Note: This only applies to server unavailability; credential rejections will never fall back to ACL. |

### Quick Setup: Dynamic ACL Rule Sync

Minimal steps to enable LDAP-backed authorization without manual ACL management:

```bash
# Configure where to search for users and groups (examples)
CONFIG SET ldap.search_base "ou=users,dc=example,dc=com"
CONFIG SET ldap.groups_search_base "ou=groups,dc=example,dc=com"

# Set group filter and attributes (defaults shown)
CONFIG SET ldap.groups_filter "objectClass=groupOfNames"
CONFIG SET ldap.groups_member_attribute "member"
CONFIG SET ldap.groups_rules_attribute "valkeyACL"

# Ensure default rules include disabling local passwords
CONFIG SET ldap.default_acl_rules "on resetpass"

# Create the Valkey user (no local password)
ACL SETUSER bob on resetpass

# Authenticate: module binds to LDAP, reads group tokens,
# applies ACL rules dynamically, and authenticates the client
AUTH bob <ldap-password>
```

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
