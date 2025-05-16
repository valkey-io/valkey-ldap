#!/bin/bash

# Wait for ldap server to be online
while true; do
    nc -z localhost 389 && break
done

ADMIN_PASSWD=admin123!
ADMIN_DN="cn=admin,dc=valkey,dc=io"

ldapadd -x -w ${ADMIN_PASSWD} -D ${ADMIN_DN} < test/ldap_users.txt
ldapadd -H ldap://localhost:390 -x -w ${ADMIN_PASSWD} -D ${ADMIN_DN} < test/ldap_users.txt
