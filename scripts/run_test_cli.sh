#!/bin/bash

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done

cargo build || exit 1

DOCKER_COMPOSE_RUNNING=`docker compose ls --filter name=valkey-ldap -q && true`

STOP_SERVERS=""

if [ -z $DOCKER_COMPOSE_RUNNING ]; then
    ./scripts/start_valkey_ldap.sh
    STOP_SERVERS=true
fi

# Wait for valkey-server to be online
while true; do
    nc -z localhost 6379 && break
done

docker exec -ti valkey valkey-cli config set ldap.servers "ldap://ldap ldap://ldap-2"
docker exec -ti valkey valkey-cli config set ldap.tls_ca_cert_path "/valkey-ldap/valkey-ldap-ca.crt"
docker exec -ti valkey valkey-cli config set ldap.tls_cert_path "/valkey-ldap/valkey-ldap-client.crt"
docker exec -ti valkey valkey-cli config set ldap.tls_key_path "/valkey-ldap/valkey-ldap-client.key"

docker exec -ti valkey valkey-cli config set ldap.bind_dn_suffix ",OU=devops,DC=valkey,DC=io"
docker exec -ti valkey valkey-cli ACL SETUSER user1 ON \>pass allcommands
docker exec -ti valkey valkey-cli ACL SETUSER u2 ON \>pass allcommands

docker exec -ti valkey valkey-cli config set ldap.auth_mode search+bind
docker exec -ti valkey valkey-cli config set ldap.search_base "dc=valkey,dc=io"
docker exec -ti valkey valkey-cli config set ldap.search_bind_dn "cn=admin,dc=valkey,dc=io"
docker exec -ti valkey valkey-cli config set ldap.search_bind_passwd "admin123!"

docker exec -ti valkey valkey-cli

if [ ! -z $STOP_SERVERS ]; then
    ./scripts/stop_valkey_ldap.sh
fi
