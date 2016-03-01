#!/bin/bash

ARGS=2
E_BADARGS=65

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <vm_name> <target_server>"
    exit $E_BADARGS
fi

PASSWD=yunshan3302
VM=$1
SERVER=$2

if virsh list | grep -q $VM; then
    sshpass -p $PASSWD virsh migrate \
    --live $VM qemu+ssh://$SERVER/system \
    --verbose \
    --persistent \
    --undefinesource
else 
    echo "Cannot find the vm: $VM".
    exit
fi 

echo Done
exit 0