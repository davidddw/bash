#!/bin/bash

ARGS=5
E_BADARGS=65
CONFIG_PATH=/etc/sysconfig/network-scripts

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <vm_name> <snap_name> <desc> <virt_disk> <disk_file>"
    exit $E_BADARGS
fi

KVM_NAME=$1
NAME=$2
DESC=$3
VIRT=$4
DISK=$5
virsh snapshot-create-as \
    --domain $KVM_NAME \
    --name $NAME \
    --description $DESC \
    --diskspec $VIRT,file=$DISK \
    --disk-only --atomic

echo Done
exit 0