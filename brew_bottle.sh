#!/bin/sh

# Bottle a release for brew:
# Usage `./brew-bottle.sh 1.0`
# run only on macos
VERSION="$1"
echo "Bottling version $VERSION ..."

cargo build --release

mkdir -p /tmp/akr/$VERSION/bin
cp ./target/release/akr /tmp/akr/$VERSION/bin/
tar -czf akr-$VERSION.big_sur.bottle.tar.gz -C /tmp akr
cp akr-$VERSION.big_sur.bottle.tar.gz akr-$VERSION.catalina.bottle.tar.gz

ls *.bottle.tar.gz

# clean up
rm -rf /tmp/akr