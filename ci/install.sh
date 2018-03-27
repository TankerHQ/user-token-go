#!/bin/bash

set -e

LIBSODIUM_VERSION="1.0.16"
LIBSODIUM_GO_SHA1="692ddacd45e46b2c7512890f032b39d019a5464b"

echo "Installing libsodium"
wget -q https://github.com/jedisct1/libsodium/releases/download/$LIBSODIUM_VERSION/libsodium-$LIBSODIUM_VERSION.tar.gz
tar -xzf libsodium-$LIBSODIUM_VERSION.tar.gz
(
    cd libsodium-$LIBSODIUM_VERSION/
    ./configure
    make -j $(nproc)
    sudo make install
)

echo "Install go dependencies"
go get -v -t ./...

echo "Build libsodium-go dependency"
(
  cd $GOPATH/src/github.com/GoKillers/libsodium-go/
  git reset --hard $LIBSODIUM_GO_SHA1
  # clang can't compile this Oo
  export CC=gcc CXX=g++
  ./build.sh
  go install -v ./...
)

go test -v ./...
