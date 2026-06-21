#!/bin/bash
set -euo pipefail

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done

if [ -f scripts/docker/certs/valkey-ldap-ca.crt ] && \
   [ -f test/valkey-ldap-client.crt ] && \
   [ -f test/valkey-ldap-client.key ]; then
    echo "Certificates were already generated"
    exit 0
fi

rm -rf scripts/docker/certs
mkdir -p scripts/docker/certs
cd scripts/docker/certs

# CA Certificate
openssl req -x509 -new -nodes -newkey rsa:2048 -keyout valkey-ldap-ca.key -sha256 -days 1825 -out valkey-ldap-ca.crt -subj /CN='valkey-ldap-ca'

# Diffie-Hellman parameters
openssl dhparam -out dhparam.pem 2048

# LDAP server certificate
openssl req -newkey rsa:2048 -nodes -keyout valkey-ldap.key -out valkey-ldap.csr -subj /CN=ldap -addext subjectAltName=DNS:ldap
printf "subjectAltName=DNS:ldap\n" > valkey-ldap.ext
openssl x509 -req -in valkey-ldap.csr -extfile valkey-ldap.ext -CA valkey-ldap-ca.crt -CAkey valkey-ldap-ca.key -CAcreateserial -out valkey-ldap.crt -days 365 -sha256

# LDAP client certificate
openssl req -newkey rsa:2048 -nodes -keyout valkey-ldap-client.key -out valkey-ldap-client.csr -subj /CN=valkey -addext subjectAltName=DNS:valkey
printf "subjectAltName=DNS:valkey\n" > valkey-ldap-client.ext
openssl x509 -req -in valkey-ldap-client.csr -extfile valkey-ldap-client.ext -CA valkey-ldap-ca.crt -CAkey valkey-ldap-ca.key -CAcreateserial -out valkey-ldap-client.crt -days 365 -sha256

rm -f *.csr *.srl *.ext

# Move client certificates to test directory
mv valkey-ldap-client.* ../../../test/
