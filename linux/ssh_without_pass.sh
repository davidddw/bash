#!/bin/bash

host=$1
pass=$2
ARGS=2
E_BADARGS=65

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <IP> <PASSWORD>"
    exit $E_BADARGS
fi

if [ ! -e "/root/.ssh/id_rsa.pub" ];
then
    ssh-keygen  -t rsa -f ~/.ssh/id_rsa  -P '' > /dev/null
fi

sshpass -p $pass \
    ssh-copy-id -i ~/.ssh/id_rsa.pub $host > /dev/null 2>&1

echo Done
exit 0