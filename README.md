# ValkeyLDAP - Valkey LDAP authentication module  ![CI](https://github.com/rjd15372/valkey-ldap/actions/workflows/ci.yml/badge.svg)

## Build Instructions

ValkeyLDAP uses Cargo for building the Valkey module.

```bash
cargo build
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

## Automated Integration Tests

The integration tests are written in python 3, and live in the `test/integration` directory. To run the tests locally we suggest to create a virtual environment to install the necessary python dependencies.

Assuming you have python 3 installed in your system, to install the python dependencies using a virtual environment do the following:

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r test/integration/requirements.txt
```

After setting up the virtual environment, you can run the test using the following commands:

```bash
./script/start_valkey_ldap.sh
pytest test/integration
./script/stop_valkey_ldap.sh
```
