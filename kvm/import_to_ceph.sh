#!/bin/bash

ARGS=3
E_BADARGS=65

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <qcow2_name> <vm_name> <pool_name>"
    exit $E_BADARGS
fi

QCOW2_NAME=$1
VM_NAME=$2
POOL_NAME=$3

qemu-img convert -O raw $QCOW2_NAME $VM_NAME -p
rbd -p $POOL_NAME --image-format 2 import --stripe-unit 65536 --stripe-count 16 $VM_NAME
virsh pool-refresh $POOL_NAME

echo Done