#!/bin/bash

ARGS=3
E_BADARGS=65
CONFIG_PATH=/etc/sysconfig/network-scripts

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <vm_name> <image_path> <target hdc>"
    exit $E_BADARGS
fi

KVM_NAME=$1
DISK_PATH=$2
VIRT_DISK=$3
virsh attach-disk \
    --domain $KVM_NAME \
    --source $DISK_PATH \
    --target $VIRT_DISK \
    --type cdrom \
    --driver qemu \
    --mode readonly \
    --persistent

# virsh change-media centos154 hda --eject --force
echo Done
exit 0