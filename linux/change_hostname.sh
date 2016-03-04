#!/bin/bash

HOST=$1
ARGS=1
E_BADARGS=65

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <HOSTNAME>"
    exit $E_BADARGS
fi

sed -i 's/HOSTNAME=.*/HOSTNAME=${HOST}.yunshan.net.cn/' /etc/sysconfig/network
hostname $HOST.yunshan.net.cn

echo "127.0.0.1   $HOST $HOST.yunshan.net.cn" >> /etc/hosts

echo Done
exit 0