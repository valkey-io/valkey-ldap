#!/bin/bash

while [[ ! $PWD/ = */valkey-ldap/ ]]; do
    cd ..
done

VERSION=`grep "version = .*" Cargo.toml | sed 's/.* = "\(.*\)"/\1/g'`

PKG_NAME=valkey-ldap

if [[ $VERSION = *-dev ]]; then
    if [ -z "$1" ]; then
        GIT_SHA=`git rev-parse --short HEAD`
    else
        GIT_SHA=$1
    fi
    VERSION="${VERSION}+${GIT_SHA}"
    PKG_NAME="${PKG_NAME}-nightly"
fi

REPO_PATH=`pwd`

echo "Generating RPM for version $VERSION"

TMPDIR=`mktemp -d`

SOURCEDIR=$TMPDIR/valkey-ldap-${VERSION}
mkdir -p $SOURCEDIR

RPM_VERSION=`echo "$VERSION" | tr - '~'`
cat packaging/valkey-ldap.spec.in | \
    sed -e "s/#\[RPM_VERSION\]/$RPM_VERSION/g" \
        -e "s/#\[VERSION\]/$VERSION/g" \
        -e "s/#\[PKG_NAME\]/$PKG_NAME/g" \
        > $TMPDIR/${PKG_NAME}.spec

DATE=`LC_TIME=en_US.UTF-8 date "+%a %b %d %Y"`
echo "* $DATE Ricardo Dias <ricardo.dias@percona.com> - ${RPM_VERSION}" >> $TMPDIR/${PKG_NAME}.spec
echo "- Update to upstream version ${VERSION}" >> $TMPDIR/${PKG_NAME}.spec

cp -r src $SOURCEDIR
cp -r vendor $SOURCEDIR
cp Cargo.toml $SOURCEDIR
cp Cargo.lock $SOURCEDIR
cp README.md $SOURCEDIR
cp LICENSE $SOURCEDIR
cp build.rs $SOURCEDIR

cd $TMPDIR
mkdir SOURCES
tar -czf SOURCES/valkey-ldap-${VERSION}.tar.gz valkey-ldap-${VERSION}

rpmbuild --define "_topdir `pwd`" -bs ${PKG_NAME}.spec

SRPM=`ls $TMPDIR/SRPMS`

cp $TMPDIR/SRPMS/$SRPM $REPO_PATH/${PKG_NAME}-${RPM_VERSION}-1.src.rpm
