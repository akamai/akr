#!/bin/sh


# Bottle a release for brew:
# Usage `./brew-bottle.sh 1.0`
# run only on macos
VERSION="$1"

if [ -z "$VERSION" ]
then
      echo "Must pass version, like '1.0' as a parameter"
      exit 1
else
      echo "Bottling version $VERSION ..."
fi

# build and release
main() {
    need_cmd cargo
    need_cmd tar
    need_cmd gh

    build_artifacts
    create_github_release

    rm *.bottle.tar.gz
}


# build the bottles
build_artifacts() {
    cargo build --release

    mkdir -p /tmp/akr/$VERSION/bin
    cp ./target/release/akr /tmp/akr/$VERSION/bin/
    tar -czf akr-$VERSION.big_sur.bottle.tar.gz -C /tmp akr
    cp akr-$VERSION.big_sur.bottle.tar.gz akr-$VERSION.catalina.bottle.tar.gz

    ls *.bottle.tar.gz

    # clean up
    rm -rf /tmp/akr
}

create_github_release() {
    export GH_REPO="github.com/akamai/homebrew-mfa"

    gh release create -t "$VERSION" -n "Release $VERSION" $VERSION *.bottle.tar.gz
    gh workflow run bottle --raw-field versionString=$VERSION
    
}

# tests that a command exists
need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1
    then err "need '$1' (command not found)"
    fi
}

main