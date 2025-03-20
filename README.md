# ValkeyLDAP - Valkey LDAP authentication module  ![CI](https://github.com/rjd15372/valkey-ldap/actions/workflows/ci.yml/badge.svg)

## Build Instructions

ValkeyLDAP uses CMake for building the Valkey module.

```bash
mkdir build && cd build
cmake ..
make
```

The default build configuration assumes that the Valkey module API header is present in `/usr/include`.
If that is not the case, we can specify the path to the module API header file using the build option `-DVALKEYMODULE_HEADER_PATH`.

```bash
mkdir build
cmake -DVALKEYMODULE_HEADER_PATH=<path_to_valkeymodule.h> ..
make
```

## Manual testing of the module

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
