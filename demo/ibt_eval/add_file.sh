#!/bin/bash


if [ -z $1 ];
then
	echo "use this script as '$0 <file>'"
	exit
fi

FILE=$(realpath $1)
DIR=$(dirname $(realpath -s $0))

pushd $DIR
	mkdir -p .fs
	sudo mount ./img/stretch.img ./.fs
	#sudo mount ./jammy.img ./.fs
	sudo cp $FILE ./.fs/root/
	sudo cp $FILE ./.fs/home/user/
	sudo umount .fs
	rmdir .fs
popd
