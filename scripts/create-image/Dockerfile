FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-c"]

RUN <<EOF
apt-get update
apt-get install -y \
    ssh \
    debootstrap \
    e2fsprogs \
    $NULL
apt-get clean
ln -sf /bin/env /bin/sudo
EOF

ENV DIR=chroot
ENV RELEASE=trixie
ENV PREINSTALL_PKGS=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default,wget
ENV ADD_PACKAGE="make,sysbench,git,vim,tmux,usbutils,tcpdump,net-tools"

ENV FEATURE=minimal
ENV SEEK=2047
ENV PERF=false
ENV IN_DOCKER=true

# Use COPY after agt-get to allow caching apt
WORKDIR /src
COPY --chmod=0755 debootstrap.sh /src/
RUN ./debootstrap.sh

# will copy the img file to /mnt. Need --privileged flag for docker run.
COPY --chmod=0755 configure.sh /src/
CMD ["bash", "-c", "set -ex; source /src/configure.sh"]

