#! /bin/sh

# This container is not really built to be a daemon, more of a one-shot, but
# leaving this option in place in case it changes in the future.
if [ "$1" = "daemon" ]
then
	export INTERACTIVE="-d"
	export NAME="--name nvdsearch"
	shift
	docker rm -f nvdsearch
else
	export INTERACTIVE="-it"
	export NAME=""
fi


if [ ! -f config ]
then
	echo "Please setup config file"
	exit 0
fi

BASEDIR=$(dirname "$0")
cd $BASEDIR

CMDLINE="docker run $INTERACTIVE $NAME \
-v "$PWD":/ \
nvdsearch $@"

echo "Running: $CMDLINE"
eval $CMDLINE
