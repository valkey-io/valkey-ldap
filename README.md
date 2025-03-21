# ValkeyLDAP - Valkey LDAP authentication module  ![CI](https://github.com/rjd15372/valkey-ldap/actions/workflows/ci.yml/badge.svg)

## Build Instructions

ValkeyLDAP uses CMake for building the Valkey module.

```bash
mkdir build
cmake -S . -B build
cmake --build build --target all
```

## Manual Module Testing

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

## Automated Unit Tests

The unit tests use the [googletest](https://github.com/google/googletest) framework and depend on the availability of the LDAP server. Therefore we need to start the LDAP server before running the unit tests.

To run the tests locally:

```bash
./scripts/start_valkey_ldap.sh
cd build
ctest
cd ..
./scripts/stop_valkey_ldap.sh
```
