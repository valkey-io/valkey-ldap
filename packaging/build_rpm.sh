#!/bin/bash

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done

./packaging/build_srpm.sh

SRPM=`ls valkey-ldap-*.rpm`

TMPDIR=`mktemp -d`
mv $SRPM $TMPDIR
cd $TMPDIR

mock  --rebuild --enable-network --resultdir=$TMPDIR $* $SRPM

echo "RPM is in $TMPDIR"
