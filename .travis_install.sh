#!/bin/bash

set -e

echo "Installing libsodium"
(
    wget -q https://github.com/jedisct1/libsodium/releases/download/$LIBSODIUM_VERSION/libsodium-$LIBSODIUM_VERSION.tar.gz
    tar -xzf libsodium-$LIBSODIUM_VERSION.tar.gz
    cd libsodium-$LIBSODIUM_VERSION/
    # env CC=tcc CFLAGS='-w' ./configure --prefix=/tmp --disable-dependency-tracking --disable-shared || cat config.log
    ./configure --prefix=/tmp --disable-dependency-tracking --disable-shared || cat config.log
    make
    make install
    ldconfig
    cd -
    rm -rf libsodium-$LIBSODIUM_VERSION*
)

echo "Install go dependencies"
go get -t ./...

echo "Build libsodium-go dependency"
(
  cd $GOPATH/src/github.com/GoKillers/libsodium-go/
  # clang can't compile this Oo
  export CC=gcc CXX=g++
  ./build.sh
  go install -v ./...
)