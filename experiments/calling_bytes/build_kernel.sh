#!/bin/bash

VERSION=4.4.302
#VERSION=4.14.268
TAG=v$VERSION
DIR=kernel

set -eux

# install some dependencies
sudo apt-get install -y git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison

# download the kernel source code first
echo "Downloading linux kernel source code..."
rm -rf $DIR
git clone --branch $TAG --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git $DIR
git -C kernel apply $(realpath ./kernel_patch_$VERSION)

# apply the configuration and compile the kernel
pushd $DIR
make defconfig
make -j`nproc`
popd
