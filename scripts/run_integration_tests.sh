#!/bin/bash

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done

cargo build || exit 1

VALKEY_VERSION=${1:-8.1}
shift

STOP_SERVERS=

DOCKER_COMPOSE_RUNNING="$(docker compose ls --filter name=valkey-ldap -q && true)"
DOCKER_COMPOSE_SERVICE="valkey-${VALKEY_VERSION}"
DOCKER_COMPOSE_CONFIG_FILE="./scripts/docker/docker-compose.yaml"
DOCKER_COMPOSE_RUNNING_CONTAINERS="$(docker compose -f "${DOCKER_COMPOSE_CONFIG_FILE}" ps --status=running | grep -c "${DOCKER_COMPOSE_SERVICE}")"

if [ -z "${DOCKER_COMPOSE_RUNNING}" ] ||  [ "${DOCKER_COMPOSE_RUNNING_CONTAINERS}" -lt 3 ]; then
    timeout 5m ./scripts/start_valkey_ldap.sh $VALKEY_VERSION || exit 1
    STOP_SERVERS=true
fi

pytest -v test/integration $*

if [ ! -z $STOP_SERVERS ]; then
    ./scripts/stop_valkey_ldap.sh
fi
