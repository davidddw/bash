#!/bin/bash

ARGS=4
E_BADARGS=65
CONFIG_PATH=/etc/sysconfig/network-scripts

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <vm_name> <image_path> <disk_size G> <target vdb>"
    exit $E_BADARGS
fi

KVM_NAME=$1
DISK_PATH=$2
DISK_SIZE=$3
VIRT_DISK=$4
/usr/bin/qemu-img create -f qcow2 $DISK_PATH $DISK_SIZE
virsh attach-disk \
    --domain $KVM_NAME \
    --source $DISK_PATH \
    --target $VIRT_DISK \
    --subdriver qcow2 \
    --cache none \
    --persistent

echo Done
exit 0

# eg ./attach_disk.sh centos151 /opt/salt/centos151_data_d.qcow2 100G vdd 