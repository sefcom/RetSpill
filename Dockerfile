from ubuntu:22.04

run apt-get update && apt-get install -y build-essential

# compile QEMU 7.2.0
run apt-get install -y git python3 ninja-build zlib1g-dev pkg-config libglib2.0-dev binutils-dev libboost-all-dev autoconf libtool libssl-dev libpixman-1-dev python3-pip python3-capstone virtualenv libslirp-dev
run git clone -b v7.2.0 --depth 1 https://git.qemu.org/git/qemu.git /qemu
run mkdir /qemu/build && cd /qemu/build && ../configure --target-list=x86_64-softmmu --python=`which python3` --disable-debug-info --enable-slirp && make -j`nproc`

# install ropr
run apt-get install -y curl
run curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /tmp/a && bash /tmp/a -y
env PATH="/root/.cargo/bin/:${PATH}"
run cargo install ropr

# clone the repo and upload the disk image
run git clone --depth 1 https://github.com/sefcom/RetSpill /RetSpill
copy scripts/create-image /RetSpill/scripts/create-image

# setup the running environment
# the angrop on pypi is broken
run pip install angr monkeyhex jinja2 pwntools colorlog tqdm
run git clone https://github.com/angr/angrop /angrop
run cd /angrop && pip install -e .
run apt-get install -y gdb
run mkdir /root/.ssh/

workdir /RetSpill/igni
cmd bash
