#!/bin/bash

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done

VALKEY_VERSION=
if [ -z "$1" ]; then
    VALKEY_VERSION=8.1
else
    VALKEY_VERSION=$1
fi

cargo build

DOCKER_COMPOSE_RUNNING="$(docker compose ls --filter name=valkey-ldap -q && true)"
DOCKER_COMPOSE_SERVICE="valkey-${VALKEY_VERSION}"
DOCKER_COMPOSE_CONFIG_FILE="./scripts/docker/docker-compose.yaml"
DOCKER_COMPOSE_RUNNING_CONTAINERS="$(docker compose -f "${DOCKER_COMPOSE_CONFIG_FILE}" ps --status=running | grep "${DOCKER_COMPOSE_SERVICE}" | wc -l)"

if [ ! -z "${DOCKER_COMPOSE_RUNNING}" ] &&  [ "${DOCKER_COMPOSE_RUNNING_CONTAINERS}" -eq 3 ]; then
    echo "The LDAP and Valkey servers are already running"
else
    pushd scripts/docker > /dev/null

    docker compose --profile "${DOCKER_COMPOSE_SERVICE}" up -d --wait
    docker compose --profile "${DOCKER_COMPOSE_SERVICE}" logs -f > /tmp/valkey-ldap.log 2>&1 &

    popd > /dev/null
fi

# Wait for valkey-server to be online
while true; do
    echo "Waiting for Valkey server"
    sleep 1
    nc -z localhost 6379 && break
done

# Wait for ldap server to be online
while true; do
    echo "Waiting for LDAP server"
    sleep 1
    nc -z localhost 389 && break
done

./scripts/populate_ldap.sh
