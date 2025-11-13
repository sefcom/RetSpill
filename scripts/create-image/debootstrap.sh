#!/bin/bash
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

sudo rm -rf $DIR
mkdir -p $DIR

if ! \
  sudo debootstrap --include=$PREINSTALL_PKGS $RELEASE $DIR; \
then
  sudo debootstrap --no-check-gpg --include=$PREINSTALL_PKGS $RELEASE $DIR \
    http://archive.debian.org/debian
fi
